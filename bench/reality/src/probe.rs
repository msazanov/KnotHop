//! Проба сайта-прикрытия: браузерный ClientHello без токена, разбор ответа (набор шифров, группа, порядок расширений,
//! размеры записей перелёта и «билетов»). По результату сервер подгоняет свой ответ. Секретов не отправляет.
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::handshake::{client_handshake, read_record, ClientMode, CoverInfo};
use crate::profile::Profile;
use crate::tls13::*;

pub async fn probe_cover(dest: &str, sni: &str, profile: &Profile, timeout: Duration) -> Result<CoverInfo> {
    let mut tcp = tokio::time::timeout(timeout, TcpStream::connect(dest)).await.map_err(|_| Error::Timeout("probe connect"))??;
    let _ = tcp.set_nodelay(true);
    let mut est = tokio::time::timeout(timeout, client_handshake(&mut tcp, profile, sni, ClientMode::Probe)).await.map_err(|_| Error::Timeout("probe handshake"))??;
    // как браузер: если выбран h2, сразу шлём preface+SETTINGS+WINDOW_UPDATE и HEADERS GET / (ответ снимаем ради размеров)
    let h2 = est.report.alpn.as_deref() == Some(&b"h2"[..]);
    if h2 {
        // как браузер, чьё h2-приложение стартует чуть позже Finished: сайт успевает отправить SETTINGS отдельной записью
        tokio::time::sleep(Duration::from_millis(5)).await;
        let (a, b) = crate::mimic::probe_h2_requests(sni);
        let mut out = est.send.seal(CT_APPDATA, &a, 0);
        out.extend_from_slice(&est.send.seal(CT_APPDATA, &b, 0));
        let _ = tcp.write_all(&out).await;
    }
    // билеты (handshake) и h2-записи сайта (application_data), которые он шлёт после Finished клиента
    let mut end = tokio::time::Instant::now() + Duration::from_millis(600);
    while est.report.tickets.len() < 8 && est.report.h2.len() < 16 {
        let Ok(r) = tokio::time::timeout_at(end, read_record(&mut tcp)).await else { break };
        let Ok((h, mut body)) = r else { break };
        if h[0] != CT_APPDATA {
            break;
        }
        let n = body.len();
        match est.recv.open(h, &mut body) {
            Ok((CT_HANDSHAKE, _)) => est.report.tickets.push(n),
            Ok((CT_APPDATA, _)) if h2 => {
                est.report.h2.push(n);
                end = tokio::time::Instant::now() + Duration::from_millis(250);
            }
            _ => break,
        }
    }
    // вежливое закрытие
    let alert = est.send.seal(CT_ALERT, &[1, 0], 0);
    let _ = tcp.write_all(&alert).await;
    Ok(est.report)
}

/// Несколько проб подряд: первая - основная, все наблюдения размеров попадают в `samples`.
pub async fn probe_cover_samples(dest: &str, sni: &str, profile: &Profile, timeout: Duration, n: usize) -> Result<CoverInfo> {
    let mut main = probe_cover(dest, sni, profile, timeout).await?;
    main.samples.push((main.flight.clone(), main.tickets.clone()));
    main.h2_samples.push(main.h2.clone());
    for _ in 1..n.max(1) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        // отдельные неудачи игнорируем: сайт мог ограничить частоту
        if let Ok(c) = probe_cover(dest, sni, profile, timeout).await {
            if c.suite == main.suite && c.group == main.group && c.flight.len() == main.flight.len() {
                main.samples.push((c.flight, c.tickets));
                main.h2_samples.push(c.h2);
            }
        }
    }
    Ok(main)
}
