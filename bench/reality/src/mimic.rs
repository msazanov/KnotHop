//! Начальный обмен «как h2 браузера» внутри записей application_data сразу после рукопожатия, до начала туннельных данных,
//! и форма первых записей туннеля. Содержимое записей - случайные байты (шифртекст); совпадают длины, порядок и RTT-зависимость.
//!
//! Обмен (по эталону Chromium 155 -> nginx, `hello-profiles/chrome155-h2.txt`):
//! ```text
//! клиент: Finished | [B1 = preface+SETTINGS+WU: 87] [B2 = HEADERS: 465..]       (сразу, как браузер)
//! сервер: (билеты) | [S0 = SETTINGS+WU: 57] ... после B1,B2: [ответы: 26, 118 / 104, 40 ...]    (из наблюдений сайта)
//! клиент: [ACK: 26]  -> туннель
//! ```
//! Служебные байты внутри шифрования: первый байт B1 = число записей пачки клиента, первый байт S0 = число ответных записей сервера
//! (остальное - случайность). Записи защищены AEAD ключами рукопожатия, поэтому подделать их снаружи нельзя.
//! Цена: +1 RTT на установку туннеля (клиент ждёт S0), байты - сумма записей обмена (≈ 0,2 + 0,3 КБ вверх по умолчанию).
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::handshake::{read_record, CoverInfo, Established};
use crate::stream::Shape;
use crate::tls13::*;
use crate::util;

pub const H2_PROFILE: &str = include_str!("../hello-profiles/chrome155-h2.txt");

/// Верхний предел числа записей пачки клиента/ответа сервера, принимаемых от пира.
const MAX_RECORDS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H2Profile {
    pub c_settings: (usize, usize),
    pub c_headers: (usize, usize),
    pub c_ack: (usize, usize),
    pub s_default: Vec<usize>,
    pub reply_max_records: usize,
    pub reply_max_bytes: usize,
    pub reply_rec_cap: usize,
    pub up_chunk: (usize, usize),
    pub up_records: u64,
    pub down_records: usize,
    pub down_pad_cap: usize,
}

fn num(s: &str) -> Result<usize> {
    s.parse().map_err(|_| Error::Config(format!("h2 profile: bad number {s:?}")))
}

fn range(v: &[&str], key: &str) -> Result<(usize, usize)> {
    let [a, b] = v else { return Err(Error::Config(format!("h2 profile: {key} wants `lo hi`"))) };
    let (a, b) = (num(a)?, num(b)?);
    if a < 18 || b < a || b > MAX_CIPHERTEXT {
        return Err(Error::Config(format!("h2 profile: {key} range {a}..{b} out of 18..{MAX_CIPHERTEXT}")));
    }
    Ok((a, b))
}

impl H2Profile {
    pub fn parse(text: &str) -> Result<H2Profile> {
        let mut p = H2Profile {
            c_settings: (0, 0),
            c_headers: (0, 0),
            c_ack: (0, 0),
            s_default: vec![],
            reply_max_records: 0,
            reply_max_bytes: 0,
            reply_rec_cap: 0,
            up_chunk: (0, 0),
            up_records: 0,
            down_records: 0,
            down_pad_cap: 0,
        };
        let mut seen = 0u32;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let t: Vec<&str> = line.split_whitespace().collect();
            let (k, v) = (t[0], &t[1..]);
            let bit = match k {
                "c_settings" => {
                    p.c_settings = range(v, k)?;
                    1
                }
                "c_headers" => {
                    p.c_headers = range(v, k)?;
                    2
                }
                "c_ack" => {
                    p.c_ack = range(v, k)?;
                    4
                }
                "s_default" => {
                    p.s_default = v.iter().map(|x| num(x)).collect::<Result<_>>()?;
                    if p.s_default.is_empty() || p.s_default.iter().any(|x| *x < 18 || *x > MAX_CIPHERTEXT) {
                        return Err(Error::Config("h2 profile: s_default".into()));
                    }
                    8
                }
                "reply_max_records" => {
                    p.reply_max_records = num(v.first().unwrap_or(&""))?;
                    16
                }
                "reply_max_bytes" => {
                    p.reply_max_bytes = num(v.first().unwrap_or(&""))?;
                    32
                }
                "reply_rec_cap" => {
                    p.reply_rec_cap = num(v.first().unwrap_or(&""))?.clamp(18, MAX_CIPHERTEXT);
                    64
                }
                "up_chunk" => {
                    p.up_chunk = range(v, k)?;
                    128
                }
                "up_records" => {
                    p.up_records = num(v.first().unwrap_or(&""))? as u64;
                    256
                }
                "down_records" => {
                    p.down_records = num(v.first().unwrap_or(&""))?;
                    512
                }
                "down_pad_cap" => {
                    p.down_pad_cap = num(v.first().unwrap_or(&""))?;
                    1024
                }
                _ => return Err(Error::Config(format!("h2 profile: unknown key {k:?}"))),
            };
            seen |= bit;
        }
        if seen != 2047 {
            return Err(Error::Config("h2 profile: missing keys".into()));
        }
        if p.reply_max_records > MAX_RECORDS {
            return Err(Error::Config("h2 profile: reply_max_records too large".into()));
        }
        Ok(p)
    }
    pub fn chrome155() -> H2Profile {
        H2Profile::parse(H2_PROFILE).expect("встроенный h2-профиль корректен")
    }
}

/// Настройка «похожести на h2»: начальный обмен (+1 RTT) и форма первых записей туннеля.
/// `enabled` - часть протокола: должно совпадать у клиента и сервера (иначе рукопожатие зависнет до таймаута).
#[derive(Clone, Debug)]
pub struct Mimic {
    pub enabled: bool,
    pub profile: H2Profile,
}

impl Default for Mimic {
    fn default() -> Self {
        Mimic { enabled: true, profile: H2Profile::chrome155() }
    }
}

impl Mimic {
    pub fn disabled() -> Mimic {
        Mimic { enabled: false, ..Mimic::default() }
    }
}

fn pick(r: (usize, usize)) -> usize {
    r.0 + util::below((r.1 - r.0 + 1) as u32) as usize
}

/// Запись application_data с телом (шифртекст с тегом) ровно `body` байт; первый байт содержимого - `first`, остальное случайное.
fn fake_record(c: &mut Cipher, body: usize, first: u8) -> Vec<u8> {
    let n = body.clamp(18, MAX_CIPHERTEXT) - 17;
    let mut v = vec![0u8; n];
    util::fill(&mut v);
    v[0] = first;
    c.seal(CT_APPDATA, &v, 0)
}

async fn read_fake<IO: AsyncRead + Unpin>(io: &mut IO, c: &mut Cipher) -> Result<u8> {
    // «билеты» сервера (handshake) идут перед обменом: клиент их пропускает, как и в потоке
    for _ in 0..16 {
        let (h, mut body) = read_record(io).await?;
        if h[0] != CT_APPDATA {
            return Err(Error::Protocol("h2 preface: unexpected record type"));
        }
        let (typ, pt) = c.open(h, &mut body)?;
        match typ {
            CT_HANDSHAKE => continue,
            CT_APPDATA if !pt.is_empty() => return Ok(pt[0]),
            _ => return Err(Error::Protocol("h2 preface: bad record")),
        }
    }
    Err(Error::Protocol("h2 preface: too many handshake records"))
}

/// Размеры ответа сервера по наблюдению сайта: (S0, ответы, цели набивки первых записей туннеля).
pub fn server_plan(m: &H2Profile, cover: &CoverInfo) -> (usize, Vec<usize>, Vec<usize>) {
    let obs = cover.pick_h2();
    let obs: &[usize] = if obs.is_empty() { &m.s_default } else { obs };
    let s0 = obs[0].clamp(18, MAX_CIPHERTEXT);
    let mut replies = vec![];
    let mut total = 0;
    for &r in obs[1..].iter().take(m.reply_max_records) {
        let r = r.clamp(18, m.reply_rec_cap.max(18));
        if total + r > m.reply_max_bytes {
            break;
        }
        total += r;
        replies.push(r);
    }
    let hi = m.down_pad_cap.min(obs.iter().copied().max().unwrap_or(0));
    let pad_to = if hi >= 200 { (0..m.down_records).map(|_| hi * 3 / 4 + util::below((hi / 4 + 1) as u32) as usize).collect() } else { vec![] };
    (s0, replies, pad_to)
}

/// Серверная сторона: после билетов. Возвращает форму первых записей туннеля.
pub async fn server_preface<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO, est: &mut Established, m: &H2Profile, cover: &CoverInfo) -> Result<Shape> {
    let (s0, replies, pad_to) = server_plan(m, cover);
    // SETTINGS сервера уходят сразу (как у браузерного сервера: после билетов, не дожидаясь клиента)
    io.write_all(&fake_record(&mut est.send, s0, replies.len() as u8)).await?;
    io.flush().await?;
    let n = read_fake(io, &mut est.recv).await? as usize;
    if n == 0 || n > MAX_RECORDS {
        return Err(Error::Protocol("h2 preface: bad client burst"));
    }
    for _ in 1..n {
        read_fake(io, &mut est.recv).await?;
    }
    let mut out = Vec::new();
    for r in &replies {
        out.extend_from_slice(&fake_record(&mut est.send, *r, 0));
    }
    if !out.is_empty() {
        io.write_all(&out).await?;
        io.flush().await?;
    }
    read_fake(io, &mut est.recv).await?; // ACK клиента
    Ok(Shape { chunk: None, chunk_records: 0, pad_to })
}

/// Клиентская сторона: сразу после своего Finished.
pub async fn client_preface<IO: AsyncRead + AsyncWrite + Unpin>(io: &mut IO, est: &mut Established, m: &H2Profile) -> Result<Shape> {
    let mut out = fake_record(&mut est.send, pick(m.c_settings), 2);
    out.extend_from_slice(&fake_record(&mut est.send, pick(m.c_headers), 0));
    io.write_all(&out).await?;
    io.flush().await?;
    let k = read_fake(io, &mut est.recv).await? as usize;
    if k > MAX_RECORDS {
        return Err(Error::Protocol("h2 preface: bad server reply count"));
    }
    for _ in 0..k {
        read_fake(io, &mut est.recv).await?;
    }
    io.write_all(&fake_record(&mut est.send, pick(m.c_ack), 0)).await?;
    io.flush().await?;
    Ok(Shape { chunk: Some(m.up_chunk), chunk_records: m.up_records, pad_to: vec![] })
}

/// Настоящие h2-байты для пробы сайта-прикрытия: (preface+SETTINGS+WINDOW_UPDATE) и (HEADERS GET /). Как у Chrome, но без кук.
pub fn probe_h2_requests(authority: &str) -> (Vec<u8>, Vec<u8>) {
    let mut a = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // SETTINGS Chrome: HEADER_TABLE_SIZE 65536, ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 6291456, MAX_HEADER_LIST_SIZE 262144
    a.extend_from_slice(&[0, 0, 24, 4, 0, 0, 0, 0, 0]);
    for (id, v) in [(1u16, 65536u32), (2, 0), (4, 6291456), (6, 262144)] {
        a.extend_from_slice(&id.to_be_bytes());
        a.extend_from_slice(&v.to_be_bytes());
    }
    a.extend_from_slice(&[0, 0, 4, 8, 0, 0, 0, 0, 0]);
    a.extend_from_slice(&15663105u32.to_be_bytes());
    // HPACK без Huffman: :method GET, :scheme https, :path /, :authority, user-agent (литерал, имя из статической таблицы #58)
    let mut hp = vec![0x82, 0x87, 0x84, 0x41, authority.len().min(127) as u8];
    hp.extend_from_slice(&authority.as_bytes()[..authority.len().min(127)]);
    let ua = b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";
    hp.push(0x0f);
    hp.push(58 - 15);
    hp.push(ua.len() as u8);
    hp.extend_from_slice(ua);
    let mut b = vec![0, (hp.len() >> 8) as u8, hp.len() as u8, 1, 0x05, 0, 0, 0, 1];
    b.extend_from_slice(&hp);
    // SETTINGS ACK
    b.extend_from_slice(&[0, 0, 0, 4, 1, 0, 0, 0, 0]);
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_parses_and_is_sane() {
        let p = H2Profile::chrome155();
        assert_eq!(p.c_settings, (87, 87));
        assert_eq!(p.c_headers, (465, 525));
        assert_eq!(p.c_ack, (26, 26));
        assert_eq!(p.s_default, vec![57, 26, 118]);
        assert_eq!(p.up_chunk, (150, 470));
        assert!(H2Profile::parse("c_settings 87 87").is_err());
        assert!(H2Profile::parse(&H2_PROFILE.replace("c_ack 26 26", "c_ack 5 6")).is_err());
        assert!(H2Profile::parse(&format!("{H2_PROFILE}\nbogus 1")).is_err());
    }

    #[test]
    fn server_plan_follows_observation_and_caps() {
        let p = H2Profile::chrome155();
        let mut c = CoverInfo::default();
        let (s0, r, pad) = server_plan(&p, &c);
        assert_eq!((s0, r.as_slice()), (57, &[26, 118][..]), "по умолчанию - таблица профиля");
        assert!(pad.is_empty(), "мелкие записи сайта -> набивки нет");
        c.h2 = vec![57, 26, 16401, 16401, 173, 16401, 16401, 53];
        let (s0, r, pad) = server_plan(&p, &c);
        assert_eq!(s0, 57);
        assert_eq!(r[0], 26);
        assert!(r.iter().all(|x| *x <= p.reply_rec_cap) && r.iter().sum::<usize>() <= p.reply_max_bytes && r.len() <= p.reply_max_records);
        assert_eq!(pad.len(), p.down_records);
        assert!(pad.iter().all(|t| (p.down_pad_cap * 3 / 4..=p.down_pad_cap).contains(t)));
    }

    #[test]
    fn probe_h2_bytes_have_chrome_shape() {
        let (a, b) = probe_h2_requests("cover.lab");
        assert_eq!(a.len(), 70, "preface 24 + SETTINGS 33 + WINDOW_UPDATE 13");
        assert_eq!(&b[3..5], &[1, 0x05]);
        assert_eq!(b.len(), 9 + ((b[1] as usize) << 8 | b[2] as usize) + 9);
    }
}
