//! Рукопожатие TLS 1.3: клиент (ClientHello по профилю браузера + проверка сервера) и сервер (после проверки токена),
//! а также «проба» настоящего сайта-прикрытия тем же клиентским кодом.
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::{self, ShortId};
use crate::cert;
use crate::chello::{self, Hello};
use crate::error::{Error, Result};
use crate::kx::{self, GROUP_HYBRID, GROUP_X25519};
use crate::profile::{self, Profile};
use crate::tls13::*;
use crate::util::{self, put_u16, put_vec16};

/// Что известно о сайте-прикрытии (его ответ на браузерный ClientHello). Сервер подгоняет ответ под эти данные.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverInfo {
    /// набор шифров в ServerHello (0 - неизвестно)
    pub suite: u16,
    /// группа key_share в ServerHello (0 - неизвестно)
    pub group: u16,
    /// порядок расширений ServerHello
    pub sh_ext_order: Vec<u16>,
    /// выбранный ALPN
    pub alpn: Option<Vec<u8>>,
    /// длины тел (шифртекст с тегом) записей перелёта сервера после ServerHello и CCS
    pub flight: Vec<usize>,
    /// длины тел записей, пришедших после Finished клиента (NewSessionTicket и т.п.)
    pub tickets: Vec<usize>,
    /// сайт прислал CCS после ServerHello
    pub ccs: bool,
    /// сайт прислал сжатый сертификат (тип 25) - только для сведения
    pub compressed_cert: bool,
    /// дополнительные наблюдения (flight, tickets): у сайта размеры плавают (подпись ECDSA 70-72 Б и т.п.);
    /// сервер выбирает случайное наблюдение на каждое соединение и воспроизводит распределение. Пусто - используются flight/tickets.
    pub samples: Vec<(Vec<usize>, Vec<usize>)>,
    /// длины тел записей сервера (после «билетов») в ответ на h2-запрос `GET /` (SETTINGS, ACK, HEADERS, DATA...); пусто - не снято
    pub h2: Vec<usize>,
    /// дополнительные наблюдения `h2` (по одному на пробу)
    pub h2_samples: Vec<Vec<usize>>,
}

impl CoverInfo {
    /// Случайное наблюдение размеров (перелёт, билеты).
    pub fn pick(&self) -> (&[usize], &[usize]) {
        if self.samples.is_empty() {
            return (&self.flight, &self.tickets);
        }
        let s = &self.samples[util::below(self.samples.len() as u32) as usize];
        (&s.0, &s.1)
    }
}

impl CoverInfo {
    /// Случайное наблюдение h2-ответа сайта (пусто, если не снималось).
    pub fn pick_h2(&self) -> &[usize] {
        if self.h2_samples.is_empty() {
            return &self.h2;
        }
        &self.h2_samples[util::below(self.h2_samples.len() as u32) as usize]
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Читает одну запись TLS: (заголовок, тело).
pub async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<([u8; 5], Vec<u8>)> {
    let mut h = [0u8; 5];
    r.read_exact(&mut h).await?;
    if !(20..=23).contains(&h[0]) || h[1] != 3 {
        return Err(Error::Protocol("not a TLS record"));
    }
    let n = u16::from_be_bytes([h[3], h[4]]) as usize;
    if n > MAX_CIPHERTEXT || n == 0 {
        return Err(Error::Protocol("bad record length"));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok((h, b))
}

pub enum ClientMode {
    /// настоящий режим: токен в session_id, проверка сервера по HMAC
    Reality { server_pub: [u8; 32], short_id: ShortId, clock_offset_secs: i64 },
    /// проба сайта-прикрытия: без токена, без проверки сертификата (ничего секретного не отправляется)
    Probe,
}

pub struct Established {
    pub send: Cipher,
    pub recv: Cipher,
    pub report: CoverInfo,
}

pub async fn client_handshake<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO, profile: &Profile, sni: &str, mode: ClientMode) -> Result<Established> {
    let draft = profile::build_hello(profile, sni);
    let mut sid = util::random::<32>();
    let mut auth_key = None;
    if let ClientMode::Reality { server_pub, short_id, clock_offset_secs } = &mode {
        let shared = kx::x25519_dh(&draft.keys.x25519, server_pub).ok_or(Error::Config("bad server public key".into()))?;
        let ak = auth::derive_auth_key(&shared, &draft.random);
        sid = auth::seal_token(&ak, &draft.random, &draft.msg, *short_id, now_unix().saturating_add_signed(*clock_offset_secs));
        auth_key = Some(ak);
    }
    let ch_msg = draft.with_sid(&sid);
    io.write_all(&draft.record(&ch_msg)).await?;
    io.flush().await?;

    // ServerHello
    let (h, body) = read_record(io).await?;
    if h[0] == CT_ALERT {
        return Err(Error::Protocol("alert instead of ServerHello"));
    }
    if h[0] != CT_HANDSHAKE {
        return Err(Error::Protocol("expected ServerHello"));
    }
    let mut hb = HsBuf::default();
    hb.push(&body);
    let sh_msg = hb.next()?.ok_or(Error::Protocol("short ServerHello"))?;
    if !hb.is_empty() {
        return Err(Error::Protocol("data after ServerHello"));
    }
    let sh = parse_server_hello(&sh_msg)?;
    if sh.version != 0x0304 {
        return Err(Error::Protocol("not TLS 1.3"));
    }
    if sh.random == HRR_RANDOM {
        return Err(Error::Protocol("HelloRetryRequest unsupported"));
    }
    if sh.session_id != sid {
        return Err(Error::Protocol("session id not echoed"));
    }
    let hello = chello::parse_hello(&ch_msg).ok_or(Error::Protocol("own hello"))?;
    if !hello.ciphers.contains(&sh.suite) {
        return Err(Error::Protocol("suite not offered"));
    }
    let suite = suite_by_id(sh.suite).ok_or(Error::Protocol("unsupported suite"))?;
    let ecdhe: Vec<u8> = match sh.group {
        GROUP_X25519 => kx::x25519_dh(&draft.keys.x25519, sh.key_exchange).ok_or(Error::Protocol("bad x25519 share"))?.to_vec(),
        GROUP_HYBRID => {
            if sh.key_exchange.len() != kx::MLKEM_CT_LEN + 32 {
                return Err(Error::Protocol("bad hybrid share"));
            }
            let (ct, xs) = sh.key_exchange.split_at(kx::MLKEM_CT_LEN);
            let mut s = kx::mlkem_decapsulate(&draft.keys.mlkem, ct).ok_or(Error::Protocol("bad ML-KEM ciphertext"))?.to_vec();
            s.extend_from_slice(&kx::x25519_dh(&draft.keys.hybrid_x, xs).ok_or(Error::Protocol("bad x25519 share"))?);
            s
        }
        _ => return Err(Error::Protocol("unsupported group")),
    };
    let mut report = CoverInfo { suite: sh.suite, group: sh.group, sh_ext_order: sh.exts.clone(), ..Default::default() };

    let mut transcript = ch_msg.clone();
    transcript.extend_from_slice(&sh_msg);
    let hs = handshake_secrets(&suite, &ecdhe, &suite.hash(&transcript));
    let mut recv = Cipher::new(suite, hs.server.clone());
    let mut send = Cipher::new(suite, hs.client.clone());

    // зашифрованный перелёт сервера
    let reality = matches!(mode, ClientMode::Reality { .. });
    let mut hbuf = HsBuf::default();
    let mut st = 0u8; // 0 ждём EE, 1 Certificate, 2 CertificateVerify, 3 Finished (строгий режим)
    let mut cert_key: Option<[u8; 32]> = None;
    let mut cv_input_th: Vec<u8> = vec![];
    let mut ccs_count = 0;
    let mut done = false;
    let mut recs = 0;
    while !done {
        let (h, mut body) = read_record(io).await?;
        match h[0] {
            CT_CCS => {
                ccs_count += 1;
                if body != [1] || ccs_count > 2 {
                    return Err(Error::Protocol("bad CCS"));
                }
                report.ccs = true;
                continue;
            }
            CT_APPDATA => {}
            CT_ALERT => return Err(Error::Protocol("alert from server")),
            _ => return Err(Error::Protocol("unexpected record")),
        }
        recs += 1;
        if recs > 16 {
            return Err(Error::Protocol("too many records in server flight"));
        }
        report.flight.push(body.len());
        let (typ, pt) = recv.open(h, &mut body)?;
        if typ != CT_HANDSHAKE {
            return Err(Error::Protocol("non-handshake record in flight"));
        }
        hbuf.push(pt);
        while let Some(m) = hbuf.next()? {
            let t = m[0];
            if reality {
                match (st, t) {
                    (0, HS_ENCRYPTED_EXTENSIONS) => {
                        report.alpn = parse_ee_alpn(&m)?;
                        st = 1;
                    }
                    (1, HS_CERTIFICATE) => {
                        let der = parse_certificate(&m)?;
                        let (pubk, mac) = cert::parse(&der).ok_or(Error::Intercepted("certificate is not a reality certificate"))?;
                        let ak = auth_key.as_ref().expect("reality");
                        if !util::ct_eq(&auth::cert_mac(ak, &pubk), &mac) {
                            return Err(Error::Intercepted("certificate HMAC mismatch (real certificate: possible interception)"));
                        }
                        cert_key = Some(pubk);
                        cv_input_th = {
                            let mut t2 = transcript.clone();
                            t2.extend_from_slice(&m);
                            suite.hash(&t2)
                        };
                        st = 2;
                    }
                    (2, HS_CERTIFICATE_VERIFY) => {
                        let (alg, sig) = parse_certificate_verify(&m)?;
                        if alg != 0x0807 {
                            return Err(Error::Intercepted("unexpected CertificateVerify algorithm"));
                        }
                        let k = signature::UnparsedPublicKey::new(&signature::ED25519, cert_key.as_ref().expect("key"));
                        k.verify(&cert_verify_input(&cv_input_th), &sig).map_err(|_| Error::Intercepted("CertificateVerify signature invalid"))?;
                        st = 3;
                    }
                    (3, HS_FINISHED) => {}
                    _ => return Err(Error::Protocol("unexpected handshake message order")),
                }
            } else if t == 25 {
                report.compressed_cert = true;
            } else if t == HS_ENCRYPTED_EXTENSIONS {
                report.alpn = parse_ee_alpn(&m).unwrap_or(None);
            }
            if t == HS_FINISHED {
                if reality && st != 3 {
                    return Err(Error::Protocol("early Finished"));
                }
                let want = finished_verify_data(&suite, &hs.server, &suite.hash(&transcript));
                if m.len() != 4 + want.len() || !util::ct_eq(&m[4..], &want) {
                    return Err(Error::Protocol("bad server Finished"));
                }
                transcript.extend_from_slice(&m);
                if !hbuf.is_empty() {
                    return Err(Error::Protocol("data after server Finished"));
                }
                done = true;
                break;
            }
            transcript.extend_from_slice(&m);
        }
    }
    let th_sfin = suite.hash(&transcript);
    let (c_ap, s_ap) = app_secrets(&suite, &hs.master_input, &th_sfin);
    let cfin = hs_msg(HS_FINISHED, &finished_verify_data(&suite, &hs.client, &th_sfin));
    let mut out = vec![CT_CCS, 3, 3, 0, 1, 1];
    out.extend_from_slice(&send.seal(CT_HANDSHAKE, &cfin, 0));
    io.write_all(&out).await?;
    io.flush().await?;
    Ok(Established { send: Cipher::new(suite, c_ap), recv: Cipher::new(suite, s_ap), report })
}

/// Решение сервера: чем отвечать клиенту, прошедшему токен.
pub struct Plan {
    pub suite: Suite,
    pub group: u16,
}

pub fn plan(h: &Hello<'_>, cover: &CoverInfo) -> Option<Plan> {
    let suite = if h.ciphers.contains(&cover.suite) && suite_by_id(cover.suite).is_some() {
        suite_by_id(cover.suite)?
    } else {
        [0x1301u16, 0x1303, 0x1302].into_iter().find(|c| h.ciphers.contains(c)).and_then(suite_by_id)?
    };
    let hyb = h.hybrid_share().is_some() && h.groups.contains(&GROUP_HYBRID);
    let x = h.x25519_share().is_some();
    let group = match cover.group {
        GROUP_X25519 if x => GROUP_X25519,
        _ if hyb => GROUP_HYBRID,
        _ if x => GROUP_X25519,
        _ => return None,
    };
    Some(Plan { suite, group })
}

pub struct ServerParams<'a> {
    pub hello: &'a Hello<'a>,
    /// ClientHello целиком (с настоящим session_id): входит в транскрипт
    pub hello_msg: &'a [u8],
    pub auth_key: [u8; 32],
    pub cover: &'a CoverInfo,
    pub plan: Plan,
    pub cn: &'a str,
}

fn cert_message(entries: &[&[u8]]) -> Vec<u8> {
    let mut list = Vec::new();
    for e in entries {
        util::put_u24(&mut list, e.len());
        list.extend_from_slice(e);
        put_u16(&mut list, 0);
    }
    let mut b = vec![0u8];
    util::put_u24(&mut b, list.len());
    b.extend_from_slice(&list);
    hs_msg(HS_CERTIFICATE, &b)
}

/// Нарезает перелёт `m` на записи нужных размеров: последняя добивается набивкой.
fn pack_records(c: &mut Cipher, m: &[u8], targets: &[usize]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0;
    for (i, ct) in targets.iter().enumerate() {
        let cap = ct - 16 - 1; // ёмкость содержимого
        let take = if i + 1 == targets.len() { m.len() - off } else { cap.min(m.len() - off) };
        let pad = cap - take;
        out.push(c.seal(CT_HANDSHAKE, &m[off..off + take], pad));
        off += take;
    }
    out
}

/// Серверная часть: отвечает на ClientHello с корректным токеном, проверяет Finished клиента, возвращает ключи приложения.
pub async fn server_handshake<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO, p: ServerParams<'_>) -> Result<Established> {
    let suite = p.plan.suite;
    let h = p.hello;
    // ключевой обмен
    let eph = kx::x25519_pair();
    let (ecdhe, kex_data): (Vec<u8>, Vec<u8>) = if p.plan.group == GROUP_HYBRID {
        let share = h.hybrid_share().ok_or(Error::Protocol("no hybrid share"))?;
        let (ek, xp) = share.split_at(kx::MLKEM_EK_LEN);
        let (ct, mut ss) = kx::mlkem_encapsulate(ek).map(|(c, s)| (c, s.to_vec())).ok_or(Error::Protocol("bad ML-KEM key"))?;
        ss.extend_from_slice(&kx::x25519_dh(&eph.secret, xp).ok_or(Error::Protocol("bad x25519 share"))?);
        let mut kd = ct;
        kd.extend_from_slice(&eph.public);
        (ss, kd)
    } else {
        let xp = h.x25519_share().ok_or(Error::Protocol("no x25519 share"))?;
        (kx::x25519_dh(&eph.secret, xp).ok_or(Error::Protocol("bad x25519 share"))?.to_vec(), eph.public.to_vec())
    };
    // ServerHello
    let mut ext43 = Vec::new();
    put_u16(&mut ext43, 0x0304);
    let mut ext51 = Vec::new();
    put_u16(&mut ext51, p.plan.group);
    put_vec16(&mut ext51, &kex_data);
    let mut order: Vec<u16> = p.cover.sh_ext_order.iter().copied().filter(|e| *e == 43 || *e == 51).collect();
    for e in [43u16, 51] {
        if !order.contains(&e) {
            order.push(e);
        }
    }
    let mut exts = Vec::new();
    for e in order {
        put_u16(&mut exts, e);
        put_vec16(&mut exts, if e == 43 { &ext43 } else { &ext51 });
    }
    let mut sb = Vec::new();
    put_u16(&mut sb, 0x0303);
    sb.extend_from_slice(&util::random::<32>());
    util::put_vec8(&mut sb, h.session_id);
    put_u16(&mut sb, suite.id);
    sb.push(0);
    put_vec16(&mut sb, &exts);
    let sh_msg = hs_msg(HS_SERVER_HELLO, &sb);
    let mut transcript = p.hello_msg.to_vec();
    transcript.extend_from_slice(&sh_msg);
    let hs = handshake_secrets(&suite, &ecdhe, &suite.hash(&transcript));
    let mut send = Cipher::new(suite, hs.server.clone());
    let mut recv = Cipher::new(suite, hs.client.clone());

    // сообщения перелёта
    let alpn = p.cover.alpn.as_ref().filter(|a| h.alpn.iter().any(|x| x == *a));
    let mut ee = Vec::new();
    if let Some(a) = alpn {
        let mut l = Vec::new();
        util::put_vec8(&mut l, a);
        let mut e = Vec::new();
        put_vec16(&mut e, &l);
        put_u16(&mut ee, 16);
        put_vec16(&mut ee, &e);
    }
    let mut eeb = Vec::new();
    put_vec16(&mut eeb, &ee);
    let ee_msg = hs_msg(HS_ENCRYPTED_EXTENSIONS, &eeb);

    let seed: [u8; 32] = util::random();
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| Error::Protocol("ed25519"))?;
    let ed_pub: [u8; 32] = kp.public_key().as_ref().try_into().expect("32");
    let der = cert::build(&ed_pub, &auth::cert_mac(&p.auth_key, &ed_pub), p.cn, util::random());

    let cv_len = 4 + 2 + 2 + 64;
    let fin_len = 4 + suite.hash_len();
    let cert0 = cert_message(&[&der]);
    let m0 = ee_msg.len() + cert0.len() + cv_len + fin_len;
    let (flight, tickets) = p.cover.pick();
    let targets: Vec<usize> = flight.iter().copied().filter(|c| *c > 17).collect();
    let cap: usize = targets.iter().map(|c| c - 17).sum();
    let packed = !targets.is_empty() && m0 <= cap;
    let cert_msg = if packed && cap - m0 >= 5 {
        let filler = vec![0u8; cap - m0 - 5];
        let mut f = filler;
        util::fill(&mut f);
        cert_message(&[&der, &f])
    } else {
        cert0
    };
    transcript.extend_from_slice(&ee_msg);
    transcript.extend_from_slice(&cert_msg);
    let sig = kp.sign(&cert_verify_input(&suite.hash(&transcript)));
    let mut cvb = Vec::new();
    put_u16(&mut cvb, 0x0807);
    put_vec16(&mut cvb, sig.as_ref());
    let cv_msg = hs_msg(HS_CERTIFICATE_VERIFY, &cvb);
    transcript.extend_from_slice(&cv_msg);
    let fin_msg = hs_msg(HS_FINISHED, &finished_verify_data(&suite, &hs.server, &suite.hash(&transcript)));
    transcript.extend_from_slice(&fin_msg);
    let th_sfin = suite.hash(&transcript);

    let mut out = Vec::new();
    out.push(CT_HANDSHAKE);
    out.extend_from_slice(&[3, 3]);
    put_vec16(&mut out, &sh_msg);
    out.extend_from_slice(&[CT_CCS, 3, 3, 0, 1, 1]);
    if packed {
        let m = [ee_msg, cert_msg, cv_msg, fin_msg].concat();
        for r in pack_records(&mut send, &m, &targets) {
            out.extend_from_slice(&r);
        }
    } else {
        for m in [ee_msg, cert_msg, cv_msg, fin_msg] {
            out.extend_from_slice(&send.seal(CT_HANDSHAKE, &m, 0));
        }
    }
    io.write_all(&out).await?;
    io.flush().await?;

    // Finished клиента
    let want = finished_verify_data(&suite, &hs.client, &th_sfin);
    let mut hbuf = HsBuf::default();
    let mut ccs = 0;
    loop {
        let (h, mut body) = read_record(io).await?;
        match h[0] {
            CT_CCS => {
                ccs += 1;
                if body != [1] || ccs > 2 {
                    return Err(Error::Protocol("bad CCS"));
                }
                continue;
            }
            CT_APPDATA => {}
            _ => return Err(Error::Protocol("unexpected record from client")),
        }
        let (typ, pt) = recv.open(h, &mut body)?;
        if typ != CT_HANDSHAKE {
            return Err(Error::Protocol("expected client Finished"));
        }
        hbuf.push(pt);
        if let Some(m) = hbuf.next()? {
            if m[0] != HS_FINISHED || m.len() != 4 + want.len() || !util::ct_eq(&m[4..], &want) || !hbuf.is_empty() {
                return Err(Error::Protocol("bad client Finished"));
            }
            break;
        }
    }
    let (c_ap, s_ap) = app_secrets(&suite, &hs.master_input, &th_sfin);
    let mut send = Cipher::new(suite, s_ap);
    // «билеты» как у сайта-прикрытия: случайное содержимое, клиент их отбрасывает
    let mut tk = Vec::new();
    for ct in tickets.iter().filter(|c| **c >= 17 + 25).take(4) {
        let tl = ct - 17 - 25;
        let mut b = Vec::new();
        b.extend_from_slice(&7200u32.to_be_bytes());
        b.extend_from_slice(&util::random::<4>());
        util::put_vec8(&mut b, &util::random::<8>());
        let mut t = vec![0u8; tl];
        util::fill(&mut t);
        put_vec16(&mut b, &t);
        put_u16(&mut b, 0);
        tk.extend_from_slice(&send.seal(CT_HANDSHAKE, &hs_msg(HS_NEW_SESSION_TICKET, &b), 0));
    }
    if !tk.is_empty() {
        io.write_all(&tk).await?;
        io.flush().await?;
    }
    Ok(Established { send, recv: Cipher::new(suite, c_ap), report: CoverInfo::default() })
}
