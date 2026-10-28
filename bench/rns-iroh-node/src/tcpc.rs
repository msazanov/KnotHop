//! Запасной носитель поверх TCP: те же пакеты RNS, что идут датаграммами QUIC, кадрами `u16 BE длина | пакет`.
//!
//! Нужен там, где UDP режется или душится (замер на пилоте: между nl1 и ru1 около 50% потерь UDP при чистом TCP). Подлинность и секретность
//! даёт сам RNS Link (ключи закреплены в профиле/анонсе), поэтому транспорт ничего не проверяет, кроме маркера `RGT1` в начале (отсекает случайные
//! подключения и сканеры). Цена: потерянный пакет задерживает всё, что идёт после него (блокировка головы очереди), а TCP внутри туннеля поверх TCP
//! хуже, чем поверх UDP: это запасной путь, а не основной.

use super::*;
use std::sync::LazyLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAGIC: &[u8; 4] = b"RGT1";
const MAGIC2: &[u8; 4] = b"RGT2";
const MAX_FRAME: usize = 2048;
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

struct TcpSink {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl PacketSink for TcpSink {
    fn send(&mut self, packet: &[u8]) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};
        if packet.len() > MAX_FRAME {
            return Err(Error::from(ErrorKind::InvalidInput));
        }
        match self.tx.try_send(packet.to_vec()) {
            Ok(()) => Ok(()),
            // очередь записи полна: пакет теряется, как в переполненном буфере QUIC; не фатально
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(Error::from(ErrorKind::WouldBlock)),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(Error::new(ErrorKind::BrokenPipe, "tcp carrier closed")),
        }
    }
}

struct TcpSource {
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl PacketSource for TcpSource {
    async fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        self.rx.recv().await.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "tcp carrier closed"))
    }
    fn try_recv(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        self.rx.try_recv().ok().map(Ok)
    }
}

/// Подключить TCP-поток как интерфейс RNS и ждать, пока он не закроется или не сработает `stop`.
/// `dialer`: мы набирали и шлём маркер первыми; иначе ждём его.
pub async fn attach(node: Arc<Node>, sh: Arc<Shared>, name: String, stream: TcpStream, dialer: bool, mut stop: tokio::sync::watch::Receiver<bool>) {
    let _ = stream.set_nodelay(true);
    // неаутентифицированная фаза принимающей стороны ограничена общим сроком от начала соединения
    let auth_until = tokio::time::Instant::now() + AUTH_DEADLINE;
    let (mut rd, mut wr) = stream.into_split();
    // исходящая сторона отправила маркер ещё в `connect` (там же проверена доставка)
    if !dialer && !hello_accept(&mut rd, &mut wr).await {
        return;
    }
    let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
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
    let (_, mtu) = carrier();
    let t = tuning();
    let opts = PacketChannelOptions { hw_mtu: mtu, buffer_size: if t.1 > 0 { t.1 } else { 1024 } };
    match node.spawn_packet_channel(&name, TcpSource { rx: in_rx }, TcpSink { tx: out_tx }, opts) {
        Ok(handle) => {
            sh.note(format!("packet interface attached: {name} (tcp carrier, hw_mtu {mtu})"));
            loop {
                tokio::select! {
                    _ = dead_rx.changed() => break,
                    r = stop.changed() => { if r.is_err() || *stop.borrow() { break; } }
                }
            }
            drop(handle);
            sh.note(format!("packet interface detached (tcp closed): {name}"));
            sh.detach.send_modify(|v| *v += 1);
        }
        Err(e) => sh.note(format!("spawn_packet_channel failed for {name}: {e}")),
    }
    reader.abort();
    writer.abort();
}

/// Слушать TCP на том же порту, что и QUIC (порты TCP и UDP независимы). С `relay` тот же порт обслуживает и TLS-relay iroh:
/// соединение различается по первому байту (`R` - маркер носителя, `0x16` - TLS), без relay поведение прежнее.
pub async fn listen(node: Arc<Node>, sh: Arc<Shared>, port: u16, relay: Option<Arc<relay::Host>>) {
    let l = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            sh.note(format!("TCP-носитель: порт {port}/tcp не открыт: {e}"));
            return;
        }
    };
    sh.note(format!("TCP-носитель слушает {port}/tcp"));
    let mut n = 0u32;
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
        n += 1;
        let (node, sh) = (node.clone(), sh.clone());
        let name = format!("tcp-in-{}-{n}", peer.ip());
        let relay = relay.clone();
        tokio::spawn(async move {
            let kind = match &relay {
                Some(_) => relay::classify(&s, MARKER_WAIT).await,
                None => relay::Kind::Carrier,
            };
            match (kind, relay) {
                (relay::Kind::Carrier, _) => {
                    let _slot = slot;
                    let (_keep, rx) = tokio::sync::watch::channel(false);
                    attach(node, sh, name, s, false, rx).await;
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

/// Приветствие принимающей стороны. `RGT1` - прежний клиент, без ответа. `RGT2` - клиент, проверяющий путь в обе стороны: отвечаем тем же маркером,
/// иначе (если ответ режется на пути) он не узнает, что связь односторонняя.
async fn hello_accept<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(rd: &mut R, wr: &mut W) -> bool {
    let mut m = [0u8; 4];
    match tokio::time::timeout(Duration::from_secs(5), rd.read_exact(&mut m)).await {
        Ok(Ok(_)) if &m == MAGIC => true,
        Ok(Ok(_)) if &m == MAGIC2 => matches!(tokio::time::timeout(Duration::from_secs(5), wr.write_all(MAGIC2)).await, Ok(Ok(()))),
        _ => false,
    }
}

/// Итог исходящего подключения.
pub enum Dial {
    /// соединено, маркер доставлен (подтверждён ACK пира)
    Up(TcpStream),
    /// рукопожатие прошло, а данные до пира не доходят: типичная картина DPI/чёрной дыры на пути
    Blackhole,
    /// не соединилось ни с одним адресом (хост выключен, порт закрыт, SYN режется)
    Unreachable,
}

/// Сколько ждём ACK на маркер: RTO TCP вдвое-втрое меньше, одна потеря сегмента успевает отыграться.
const PROBE: Duration = Duration::from_secs(4);

/// Байт в очереди отправки, ещё не подтверждённых пиром (`SIOCOUTQ`); None - узнать нельзя.
fn unacked(s: &TcpStream) -> Option<i32> {
    use std::os::fd::AsRawFd;
    let mut n: libc::c_int = 0;
    let r = unsafe { libc::ioctl(s.as_raw_fd(), libc::TIOCOUTQ as _, &mut n) };
    (r == 0).then_some(n)
}

/// Исходящее TCP-соединение к одному из адресов с настоящей проверкой пути: шлём маркер и ждём, пока пир его подтвердит.
/// Без проверки соединение, у которого проходит только рукопожатие, выглядело бы живым и рвалось бы по таймаутам.
pub async fn connect(addrs: &[SocketAddr]) -> Dial {
    let mut reached = false;
    for a in addrs {
        let Ok(Ok(mut s)) = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(a)).await else { continue };
        reached = true;
        match hello(&mut s).await {
            Hello::Both => return Dial::Up(s),
            Hello::Silent => continue,
            // узел старой версии закрыл соединение на `RGT2`: проверяем доставку только в нашу сторону, как раньше
            Hello::Legacy => {
                if let Some(s) = legacy_probe(a).await {
                    return Dial::Up(s);
                }
            }
        }
    }
    if reached { Dial::Blackhole } else { Dial::Unreachable }
}

enum Hello {
    /// маркер дошёл до пира и ответ вернулся: путь работает в обе стороны
    Both,
    /// пир не ответил за `PROBE`: данные в одну из сторон не проходят
    Silent,
    /// пир закрыл соединение, не распознав `RGT2`
    Legacy,
}

async fn hello(s: &mut TcpStream) -> Hello {
    if !matches!(tokio::time::timeout(PROBE, s.write_all(MAGIC2)).await, Ok(Ok(()))) {
        return Hello::Silent;
    }
    let mut m = [0u8; 4];
    match tokio::time::timeout(PROBE, s.read_exact(&mut m)).await {
        Ok(Ok(_)) if &m == MAGIC2 => Hello::Both,
        Ok(_) => Hello::Legacy,
        Err(_) => Hello::Silent,
    }
}

async fn legacy_probe(a: &SocketAddr) -> Option<TcpStream> {
    let Ok(Ok(mut s)) = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(a)).await else { return None };
    if !matches!(tokio::time::timeout(PROBE, s.write_all(MAGIC)).await, Ok(Ok(()))) {
        return None;
    }
    let until = tokio::time::Instant::now() + PROBE;
    loop {
        match unacked(&s) {
            Some(0) | None => return Some(s),
            Some(_) if tokio::time::Instant::now() >= until => return None,
            Some(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
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

    /// Принимающая сторона на loopback: текущая (`hello_accept`) или старая (принимает только `RGT1`, закрывает остальное, не отвечает).
    async fn dial_loopback_to(legacy: bool) -> Dial {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                tokio::spawn(async move {
                    let (mut rd, mut wr) = s.into_split();
                    if legacy {
                        let mut m = [0u8; 4];
                        if rd.read_exact(&mut m).await.is_ok() && &m == MAGIC {
                            tokio::time::sleep(Duration::from_secs(30)).await;
                        }
                    } else if hello_accept(&mut rd, &mut wr).await {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                });
            }
        });
        connect(&[a]).await
    }

    async fn dial_loopback() -> Dial {
        dial_loopback_to(false).await
    }

    #[tokio::test]
    async fn connect_confirms_delivery_on_healthy_path() {
        assert!(matches!(dial_loopback().await, Dial::Up(_)));
    }

    #[tokio::test]
    async fn connect_falls_back_to_legacy_acceptor() {
        assert!(matches!(dial_loopback_to(true).await, Dial::Up(_)));
    }

    #[tokio::test]
    async fn acceptor_replies_only_to_new_marker() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let (mut br, mut bw) = tokio::io::split(&mut b);
        a.write_all(MAGIC).await.unwrap();
        assert!(hello_accept(&mut br, &mut bw).await);
        drop((br, bw));
        let mut x = [0u8; 4];
        assert!(tokio::time::timeout(Duration::from_millis(100), a.read_exact(&mut x)).await.is_err(), "ответ на старый маркер сломал бы старый клиент");
        let (mut a, mut b) = tokio::io::duplex(64);
        let (mut br, mut bw) = tokio::io::split(&mut b);
        a.write_all(MAGIC2).await.unwrap();
        assert!(hello_accept(&mut br, &mut bw).await);
        a.read_exact(&mut x).await.unwrap();
        assert_eq!(&x, MAGIC2);
        let (mut a, mut b) = tokio::io::duplex(64);
        let (mut br, mut bw) = tokio::io::split(&mut b);
        a.write_all(b"XXXX").await.unwrap();
        assert!(!hello_accept(&mut br, &mut bw).await);
    }

    #[tokio::test]
    async fn connect_unreachable_when_port_closed() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        assert!(matches!(connect(&[a]).await, Dial::Unreachable));
        assert!(!reachable(&[a]).await);
    }

    /// Нужна сеть, где проходит рукопожатие, а сегменты с данными режутся (`bench/android/blackhole_test.sh`).
    #[tokio::test]
    #[ignore]
    async fn connect_reports_blackhole_when_payload_is_dropped() {
        assert!(matches!(dial_loopback().await, Dial::Blackhole));
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
