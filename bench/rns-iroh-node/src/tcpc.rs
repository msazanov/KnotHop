//! Запасной носитель поверх TCP: те же пакеты RNS, что идут датаграммами QUIC, кадрами `u16 BE длина | пакет`.
//!
//! Нужен там, где UDP режется или душится (замер на пилоте: между nl1 и ru1 около 50% потерь UDP при чистом TCP). Подлинность и секретность
//! даёт сам RNS Link, а носитель подключается к интерфейсу пира (`mux.rs`) и не создаёт собственного. Рукопожатие `RGT3` взаимное: набирающая
//! сторона доказывает свой ключ iroh подписью по свежему nonce принимающей, принимающая - свой подписью по обоим nonce (самозванец по адресу
//! из подсказок не пройдёт и не заставит клиента бросить рабочий QUIC). Так TCP-носитель попадает к тому же интерфейсу, что и QUIC того же ключа. Права
//! рукопожатие не даёт. Поток после рукопожатия открытый (без шифрования и MAC): его защищает только Link. Цена TCP: потерянный пакет задерживает всё, что идёт после него (блокировка головы очереди), а TCP внутри туннеля поверх TCP хуже,
//! чем поверх UDP: это запасной путь, а не основной.

use super::*;
use std::sync::LazyLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAGIC: &[u8; 4] = b"RGT3";
/// домен подписи рукопожатия: подпись нельзя использовать нигде, кроме TCP-носителя KnotHop
const SIGN_DOMAIN: &[u8] = b"knothop/rgt3/v1";
/// домен подписи принимающей стороны (другой, чтобы подпись одной стороны не принималась за подпись другой)
const SIGN_DOMAIN_ACK: &[u8] = b"knothop/rgt3/ack/v1";
/// очередь кадров в каждую сторону: 2048 Б * 512 = до 1 МиБ на носитель (было 4096 кадров, до 8 МиБ)
const QUEUE_FRAMES: usize = 512;
/// не больше стольких интерфейсов пиров на узле (QUIC + TCP до допуска)
pub(crate) const MAX_MUX: usize = 320;
pub(crate) const MAX_FRAME: usize = 2048;
const MAX_CONNS: usize = 64;
/// не больше столько соединений с одного адреса (иначе один узел занимает все слоты)
const MAX_PER_IP: usize = 6;
/// молчащее дольше этого соединение закрывается (клиенты и узлы шлют пинг каждые 1-2 с)
const IDLE: Duration = Duration::from_secs(60);
/// принимающая сторона: маркер и первый полный кадр должны прийти за это время от начала соединения
const AUTH_DEADLINE: Duration = Duration::from_secs(10);
/// запись батча дольше этого: медленный читатель не держит слот бесконечно
const WRITE_STALL: Duration = Duration::from_secs(30);
/// пауза после ошибки accept (например EMFILE), чтобы цикл не крутился на 100% CPU
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Слоты соединений TCP-носителя (общие для `listen`).
static SLOTS: LazyLock<SlotsRef> = LazyLock::new(Default::default);
/// relay iroh: отдельный пул, равный лимиту клиентов `relay::MAX_CLIENTS`
static RELAY_SLOTS: LazyLock<SlotsRef> = LazyLock::new(Default::default);
const MAX_RELAY_CONNS: usize = 64;
/// сколько ждём первый байт, чтобы отличить носитель от relay (как и ожидание маркера в `hello_accept`)
const MARKER_WAIT: Duration = Duration::from_secs(5);

/// Срок чтения: до первого полного кадра принимающей стороны - общий `auth_until`, потом обычная тишина `IDLE`.
fn read_until(authed: bool, auth_until: tokio::time::Instant) -> tokio::time::Instant {
    if authed { tokio::time::Instant::now() + IDLE } else { auth_until }
}

/// Подключить TCP-поток носителем интерфейса `mux` и ждать, пока он не закроется или не сработает `stop`. `select`: сразу назначить его носителем данных
/// (набирающая сторона); принимающая следует за пакетами, которые приходят по нему. `ready` получает true, когда носитель зарегистрирован в интерфейсе
/// (после этого прежний носитель можно закрывать без потери пакетов), и false, если интерфейс его не принял.
pub async fn run(mux: Arc<mux::Mux>, mut rd: tokio::net::tcp::OwnedReadHalf, mut wr: tokio::net::tcp::OwnedWriteHalf, dialer: bool, select: bool, ready: Option<tokio::sync::oneshot::Sender<bool>>, mut stop: tokio::sync::watch::Receiver<bool>) {
    // неаутентифицированная фаза принимающей стороны ограничена общим сроком от начала соединения
    let auth_until = tokio::time::Instant::now() + AUTH_DEADLINE;
    let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(QUEUE_FRAMES);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(QUEUE_FRAMES);
    let (dead_tx, mut dead_rx) = tokio::sync::watch::channel(false);
    let d1 = dead_tx.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_FRAME];
        // дialer доверяет своему соединению сразу; принимающая сторона - после первого полного кадра
        let mut authed = dialer;
        loop {
            let mut h = [0u8; 2];
            match tokio::time::timeout_at(read_until(authed, auth_until), rd.read_exact(&mut h)).await {
                Ok(Ok(_)) => {}
                _ => break,   // ошибка или тишина дольше срока
            }
            let n = u16::from_be_bytes(h) as usize;
            if n == 0 || n > MAX_FRAME || !matches!(tokio::time::timeout_at(read_until(authed, auth_until), rd.read_exact(&mut buf[..n])).await, Ok(Ok(_))) {
                break;
            }
            authed = true;
            if in_tx.try_send(buf[..n].to_vec()).is_err() && in_tx.is_closed() {
                break;
            }
        }
        let _ = d1.send(true);
    });
    let writer = tokio::spawn(async move {
        let mut batch: Vec<u8> = Vec::with_capacity(16 * 1024);
        while let Some(first) = out_rx.recv().await {
            batch.clear();
            let mut n = 0;
            let mut cur = Some(first);
            while let Some(p) = cur.take() {
                batch.extend_from_slice(&(p.len() as u16).to_be_bytes());
                batch.extend_from_slice(&p);
                n += 1;
                if n < 64 && batch.len() < 12 * 1024 {
                    cur = out_rx.try_recv().ok();
                }
            }
            match tokio::time::timeout(WRITE_STALL, wr.write_all(&batch)).await {
                Ok(Ok(())) => {}
                _ => break, // ошибка записи или читатель стоит дольше WRITE_STALL
            }
        }
        let _ = dead_tx.send(true);
    });
    let added = mux.add_tcp(out_tx, in_rx, select);
    if let Some(r) = ready {
        let _ = r.send(added.is_some());
    }
    if let Some(id) = added {
        loop {
            tokio::select! {
                _ = dead_rx.changed() => break,
                r = stop.changed() => { if r.is_err() || *stop.borrow() { break; } }
            }
        }
        mux.remove(id);
    }
    reader.abort();
    writer.abort();
}

/// Слушать TCP на том же порту, что и QUIC (порты TCP и UDP независимы). С `relay` тот же порт обслуживает и TLS-relay iroh:
/// соединение различается по первому байту (`R` - маркер носителя, `0x16` - TLS), без relay поведение прежнее.
pub async fn listen(node: Arc<Node>, sh: Arc<Shared>, port: u16, self_sk: iroh::SecretKey, relay: Option<Arc<relay::Host>>) {
    let l = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            sh.note(format!("TCP-носитель: порт {port}/tcp не открыт: {e}"));
            return;
        }
    };
    sh.note(format!("TCP-носитель слушает {port}/tcp"));
    loop {
        let (s, peer) = match l.accept().await {
            Ok(v) => v,
            Err(_) => {
                // например EMFILE: не крутиться на месте
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        // лишнее подключение (общий или поадресный лимит) закрывается сразу: `s` уходит из области видимости
        let Some(slot) = Slot::take(&SLOTS, Some(peer.ip()), MAX_CONNS, MAX_PER_IP) else { continue };
        let (node, sh) = (node.clone(), sh.clone());
        let (relay, self_sk) = (relay.clone(), self_sk.clone());
        tokio::spawn(async move {
            let kind = match &relay {
                Some(_) => relay::classify(&s, MARKER_WAIT).await,
                None => relay::Kind::Carrier,
            };
            match (kind, relay) {
                (relay::Kind::Carrier, _) => {
                    let _slot = slot;
                    let _ = s.set_nodelay(true);
                    let (mut rd, mut wr) = s.into_split();
                    let Some(key) = hello_accept(&mut rd, &mut wr, &self_sk).await else { return };
                    let Some(mux) = sh.muxes.get_or_create(&node, &sh, key, MAX_MUX) else { return };
                    let (_keep, rx) = tokio::sync::watch::channel(false);
                    run(mux, rd, wr, false, false, None, rx).await;
                }
                (relay::Kind::Relay, Some(host)) => {
                    // слот носителя нужен был только до опознания; relay считается отдельно, чтобы не вытеснять носитель
                    drop(slot);
                    let Some(_relay_slot) = Slot::take(&RELAY_SLOTS, Some(peer.ip()), MAX_RELAY_CONNS, MAX_PER_IP) else { return };
                    host.serve(s).await;
                }
                _ => {}
            }
        });
    }
}

/// Что подписывает набирающая сторона: домен, nonce принимающей, ключи обеих сторон (подпись нельзя перенести на другое соединение или пару).
fn signed_message(nonce: &[u8; 16], acceptor: &[u8; 32], dialer: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGN_DOMAIN.len() + 16 + 64);
    m.extend_from_slice(SIGN_DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(acceptor);
    m.extend_from_slice(dialer);
    m
}

/// Что подписывает принимающая сторона: свой домен, оба nonce и ключи обеих сторон. Nonce набирающей делает подпись свежей для этого соединения.
fn ack_message(nonce_d: &[u8; 16], nonce_a: &[u8; 16], acceptor: &[u8; 32], dialer: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGN_DOMAIN_ACK.len() + 32 + 64);
    m.extend_from_slice(SIGN_DOMAIN_ACK);
    m.extend_from_slice(nonce_d);
    m.extend_from_slice(nonce_a);
    m.extend_from_slice(acceptor);
    m.extend_from_slice(dialer);
    m
}

/// Рукопожатие принимающей стороны: `RGT3 | ключ iroh набирающей (32) | nonce_d (16)` -> `RGT3 | nonce_a (16)` -> подпись набирающей (64) ->
/// `RGT3 | подпись принимающей (64)`. Возвращает проверенный ключ iroh набирающей стороны; он выбирает интерфейс пира (`mux::Registry`) и больше
/// ничего не даёт. Неверный маркер, ключ или подпись - None.
async fn hello_accept<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(rd: &mut R, wr: &mut W, self_sk: &iroh::SecretKey) -> Option<[u8; 32]> {
    use rand_core::RngCore;
    let wait = Duration::from_secs(5);
    let self_id = self_sk.public();
    let self_id = self_id.as_bytes();
    let mut m = [0u8; 52];
    matches!(tokio::time::timeout(wait, rd.read_exact(&mut m)).await, Ok(Ok(_))).then_some(())?;
    (&m[..4] == MAGIC).then_some(())?;
    let dialer: [u8; 32] = m[4..36].try_into().ok()?;
    let nonce_d: [u8; 16] = m[36..].try_into().ok()?;
    let pk = iroh::PublicKey::from_bytes(&dialer).ok()?;
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let mut out = [0u8; 20];
    out[..4].copy_from_slice(MAGIC);
    out[4..].copy_from_slice(&nonce);
    matches!(tokio::time::timeout(wait, wr.write_all(&out)).await, Ok(Ok(()))).then_some(())?;
    let mut sig = [0u8; 64];
    matches!(tokio::time::timeout(wait, rd.read_exact(&mut sig)).await, Ok(Ok(_))).then_some(())?;
    pk.verify(&signed_message(&nonce, self_id, &dialer), &iroh::Signature::from_bytes(&sig)).ok()?;
    let mut ack = [0u8; 68];
    ack[..4].copy_from_slice(MAGIC);
    ack[4..].copy_from_slice(&self_sk.sign(&ack_message(&nonce_d, &nonce, self_id, &dialer)).to_bytes());
    matches!(tokio::time::timeout(wait, wr.write_all(&ack)).await, Ok(Ok(()))).then_some(())?;
    Some(dialer)
}

/// Итог исходящего подключения.
pub enum Dial {
    /// соединено, ключ подтверждён обеими сторонами и ответ пира вернулся: путь работает в обе стороны
    Up(TcpStream),
    /// рукопожатие прошло, а данные до пира не доходят: типичная картина DPI/чёрной дыры на пути
    Blackhole,
    /// не соединилось ни с одним адресом (хост выключен, порт закрыт, SYN режется)
    Unreachable,
}

/// Сколько ждём ответ на каждый шаг рукопожатия: RTO TCP вдвое-втрое меньше, одна потеря сегмента успевает отыграться.
const PROBE: Duration = Duration::from_secs(4);

/// Исходящее TCP-соединение к одному из адресов с настоящей проверкой пути: полное рукопожатие `RGT3` в обе стороны.
/// Без проверки соединение, у которого проходит только рукопожатие TCP, выглядело бы живым и рвалось бы по таймаутам.
/// `sk` - наш ключ iroh, `peer` - ключ iroh пира, к которому набираем (подпись привязана к паре).
pub async fn connect(addrs: &[SocketAddr], sk: &iroh::SecretKey, peer: &EndpointId) -> Dial {
    let mut reached = false;
    for a in addrs {
        let Ok(Ok(mut s)) = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(a)).await else { continue };
        reached = true;
        let _ = s.set_nodelay(true);
        if hello(&mut s, sk, peer.as_bytes()).await {
            return Dial::Up(s);
        }
    }
    if reached { Dial::Blackhole } else { Dial::Unreachable }
}

async fn hello(s: &mut TcpStream, sk: &iroh::SecretKey, acceptor: &[u8; 32]) -> bool {
    use rand_core::RngCore;
    let me = *sk.public().as_bytes();
    let mut nonce_d = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce_d);
    let mut first = [0u8; 52];
    first[..4].copy_from_slice(MAGIC);
    first[4..36].copy_from_slice(&me);
    first[36..].copy_from_slice(&nonce_d);
    if !matches!(tokio::time::timeout(PROBE, s.write_all(&first)).await, Ok(Ok(()))) {
        return false;
    }
    let mut r = [0u8; 20];
    if !matches!(tokio::time::timeout(PROBE, s.read_exact(&mut r)).await, Ok(Ok(_))) || &r[..4] != MAGIC {
        return false;
    }
    let nonce: [u8; 16] = r[4..].try_into().unwrap();
    let sig = sk.sign(&signed_message(&nonce, acceptor, &me)).to_bytes();
    if !matches!(tokio::time::timeout(PROBE, s.write_all(&sig)).await, Ok(Ok(()))) {
        return false;
    }
    let mut ack = [0u8; 68];
    if !matches!(tokio::time::timeout(PROBE, s.read_exact(&mut ack)).await, Ok(Ok(_))) || &ack[..4] != MAGIC {
        return false;
    }
    // принимающая обязана доказать, что держит ключ, к которому мы набираем: иначе любой, кто слушает адрес из подсказок, пройдёт
    let Ok(pk) = iroh::PublicKey::from_bytes(acceptor) else { return false };
    let Ok(sig) = <[u8; 64]>::try_from(&ack[4..]) else { return false };
    pk.verify(&ack_message(&nonce_d, &nonce, acceptor, &me), &iroh::Signature::from_bytes(&sig)).is_ok()
}

/// Отвечает ли хост на TCP-рукопожатие (без отправки данных).
pub async fn reachable(addrs: &[SocketAddr]) -> bool {
    for a in addrs {
        if matches!(tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(a)).await, Ok(Ok(_))) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Принимающая сторона на loopback; возвращает её адрес и ключ.
    async fn acceptor() -> (SocketAddr, iroh::SecretKey) {
        let sk = iroh::SecretKey::generate();
        let key = sk.clone();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let key = key.clone();
                tokio::spawn(async move {
                    let (mut rd, mut wr) = s.into_split();
                    if hello_accept(&mut rd, &mut wr, &key).await.is_some() {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                });
            }
        });
        (a, sk)
    }

    #[tokio::test]
    async fn connect_confirms_delivery_on_healthy_path() {
        let (a, srv) = acceptor().await;
        let me = iroh::SecretKey::generate();
        assert!(matches!(connect(&[a], &me, &srv.public()).await, Dial::Up(_)));
    }

    /// Первая часть рукопожатия набирающей стороны: `RGT3 | ключ | nonce_d`; возвращает nonce принимающей.
    async fn dialer_first<S: AsyncReadExt + AsyncWriteExt + Unpin>(a: &mut S, me: &[u8; 32], nonce_d: &[u8; 16]) -> [u8; 16] {
        let mut first = [0u8; 52];
        first[..4].copy_from_slice(MAGIC);
        first[4..36].copy_from_slice(me);
        first[36..].copy_from_slice(nonce_d);
        a.write_all(&first).await.unwrap();
        let mut r = [0u8; 20];
        a.read_exact(&mut r).await.unwrap();
        r[4..].try_into().unwrap()
    }

    #[tokio::test]
    async fn acceptor_returns_the_proven_dialer_key_and_signs_back() {
        let (acc, dia) = (iroh::SecretKey::generate(), iroh::SecretKey::generate());
        let acc_id = *acc.public().as_bytes();
        let (mut a, mut b) = tokio::io::duplex(1024);
        let h = tokio::spawn(async move {
            let (mut br, mut bw) = tokio::io::split(&mut b);
            hello_accept(&mut br, &mut bw, &acc).await
        });
        let me = *dia.public().as_bytes();
        let nonce_d = [7u8; 16];
        let nonce = dialer_first(&mut a, &me, &nonce_d).await;
        a.write_all(&dia.sign(&signed_message(&nonce, &acc_id, &me)).to_bytes()).await.unwrap();
        let mut ack = [0u8; 68];
        a.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack[..4], MAGIC);
        let pk = iroh::PublicKey::from_bytes(&acc_id).unwrap();
        let sig = iroh::Signature::from_bytes(&<[u8; 64]>::try_from(&ack[4..]).unwrap());
        assert!(pk.verify(&ack_message(&nonce_d, &nonce, &acc_id, &me), &sig).is_ok());
        assert_eq!(h.await.unwrap(), Some(me));
    }

    /// Чужая подпись, подпись для другого принимающего и подпись по чужому nonce не принимаются; ответа (ack) нет.
    #[tokio::test]
    async fn acceptor_rejects_forged_signatures() {
        let (acc, dia, other) = (iroh::SecretKey::generate(), iroh::SecretKey::generate(), iroh::SecretKey::generate());
        let acc_id = *acc.public().as_bytes();
        let me = *dia.public().as_bytes();
        for case in 0..3 {
            let (mut a, mut b) = tokio::io::duplex(1024);
            let acc = acc.clone();
            let h = tokio::spawn(async move {
                let (mut br, mut bw) = tokio::io::split(&mut b);
                hello_accept(&mut br, &mut bw, &acc).await
            });
            let nonce = dialer_first(&mut a, &me, &[1u8; 16]).await;
            let sig = match case {
                0 => other.sign(&signed_message(&nonce, &acc_id, &me)),
                1 => dia.sign(&signed_message(&nonce, other.public().as_bytes(), &me)),
                _ => dia.sign(&signed_message(&[9u8; 16], &acc_id, &me)),
            };
            a.write_all(&sig.to_bytes()).await.unwrap();
            assert_eq!(h.await.unwrap(), None, "случай {case}");
            let mut ack = [0u8; 4];
            assert!(a.read_exact(&mut ack).await.is_err(), "ack на неверную подпись (случай {case})");
        }
    }

    /// Самозванец без ключа принимающей: отвечает маркером и любой подписью. Набирающая сторона его не принимает.
    #[tokio::test]
    async fn dialer_rejects_impostor_acceptor() {
        for mode in 0..2 {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            let real = iroh::SecretKey::generate();
            let fake = iroh::SecretKey::generate();
            tokio::spawn(async move {
                let Ok((mut s, _)) = l.accept().await else { return };
                let mut m = [0u8; 52];
                s.read_exact(&mut m).await.unwrap();
                let (nonce_d, dialer): ([u8; 16], [u8; 32]) = (m[36..].try_into().unwrap(), m[4..36].try_into().unwrap());
                let nonce = [3u8; 16];
                let mut out = [0u8; 20];
                out[..4].copy_from_slice(MAGIC);
                out[4..].copy_from_slice(&nonce);
                s.write_all(&out).await.unwrap();
                let mut sig = [0u8; 64];
                s.read_exact(&mut sig).await.unwrap();
                let mut ack = [0u8; 68];
                ack[..4].copy_from_slice(MAGIC);
                // mode 0: нулевая подпись; mode 1: подпись чужим ключом по верному сообщению
                if mode == 1 {
                    ack[4..].copy_from_slice(&fake.sign(&ack_message(&nonce_d, &nonce, &[0u8; 32], &dialer)).to_bytes());
                }
                let _ = s.write_all(&ack).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
            let me = iroh::SecretKey::generate();
            assert!(!matches!(connect(&[a], &me, &real.public()).await, Dial::Up(_)), "самозванец принят (режим {mode})");
        }
    }

    #[tokio::test]
    async fn acceptor_rejects_bad_marker() {
        let (mut a, mut b) = tokio::io::duplex(128);
        let (mut br, mut bw) = tokio::io::split(&mut b);
        a.write_all(&[b'X'; 52]).await.unwrap();
        assert_eq!(hello_accept(&mut br, &mut bw, &iroh::SecretKey::generate()).await, None);
    }

    #[tokio::test]
    async fn connect_unreachable_when_port_closed() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        let (me, peer) = (iroh::SecretKey::generate(), iroh::SecretKey::generate());
        assert!(matches!(connect(&[a], &me, &peer.public()).await, Dial::Unreachable));
        assert!(!reachable(&[a]).await);
    }

    /// Нужна сеть, где проходит рукопожатие, а сегменты с данными режутся (`bench/android/blackhole_test.sh`).
    #[tokio::test]
    #[ignore]
    async fn connect_reports_blackhole_when_payload_is_dropped() {
        let (a, srv) = acceptor().await;
        let me = iroh::SecretKey::generate();
        assert!(matches!(connect(&[a], &me, &srv.public()).await, Dial::Blackhole));
    }

    #[test]
    fn per_ip_slots_are_released_and_zero_entries_removed() {
        let t: SlotsRef = Default::default();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let held: Vec<Slot> = (0..MAX_PER_IP).map(|_| Slot::take(&t, Some(a), MAX_CONNS, MAX_PER_IP).unwrap()).collect();
        assert!(Slot::take(&t, Some(a), MAX_CONNS, MAX_PER_IP).is_none(), "лимит на адрес не сработал");
        drop(held);
        let s = t.lock().unwrap();
        assert_eq!(s.live, 0);
        assert!(s.per_ip.is_empty(), "нулевая запись осталась в карте адресов");
    }

    #[test]
    fn total_slots_limit_across_addresses() {
        let t: SlotsRef = Default::default();
        let held: Vec<Slot> = (0..MAX_CONNS)
            .map(|i| Slot::take(&t, Some(IpAddr::from([10, 0, (i / 256) as u8, (i % 256) as u8])), MAX_CONNS, MAX_PER_IP).unwrap())
            .collect();
        assert!(Slot::take(&t, Some(IpAddr::from([10, 1, 0, 1])), MAX_CONNS, MAX_PER_IP).is_none(), "общий лимит не сработал");
        drop(held);
        assert_eq!(t.lock().unwrap().live, 0);
    }
}
