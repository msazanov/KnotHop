//! Кадрирование: порядок и целостность, отбрасывание по времени в очереди и по заполнению.
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use bytes::Bytes;
use knothop_reality::carrier::{spawn, FrameConfig};
use tokio::io::duplex;

#[tokio::test]
async fn roundtrip_in_order_all_sizes() {
    let (a, b) = duplex(1 << 16);
    let la = spawn(a, FrameConfig::default());
    let mut lb = spawn(b, FrameConfig::default());
    let mut sent = vec![];
    for i in 0..2000usize {
        let n = 1 + (i * 7919) % 1500;
        let p = Bytes::from((0..n).map(|k| (k + i) as u8).collect::<Vec<u8>>());
        sent.push(p.clone());
        // очередь ограничена: ждём, пока освободится (UDP-семантика допускает потерю, здесь нужна доставка)
        while !la.sender.try_send(p.clone()) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    for p in sent {
        let g = tokio::time::timeout(Duration::from_secs(5), lb.rx.recv()).await.unwrap().unwrap();
        assert_eq!(g, p);
    }
    // граничные размеры
    assert!(!la.sender.try_send(Bytes::new()));
    assert!(!la.sender.try_send(Bytes::from(vec![0u8; 65536])));
    assert!(la.sender.try_send(Bytes::from(vec![5u8; 65535])));
    let g = lb.rx.recv().await.unwrap();
    assert_eq!(g.len(), 65535);
    assert_eq!(la.stats.drop_size.load(Relaxed), 2);
}

#[tokio::test]
async fn stale_frames_are_dropped_not_delayed() {
    // узкая труба и читатель, который не читает: писатель блокируется, очередь стареет
    let (a, b) = duplex(256);
    let cfg = FrameConfig { max_queue_delay: Duration::from_millis(100), batch_bytes: 2048, ..FrameConfig::default() };
    let la = spawn(a, cfg);
    for _ in 0..200 {
        assert!(la.sender.try_send(Bytes::from(vec![1u8; 1000])));
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    // читатель просыпается: ждёт только свежие кадры
    let mut lb = spawn(b, FrameConfig::default());
    let mut got = 0;
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(300), lb.rx.recv()).await {
        got += 1;
    }
    assert!(la.stats.drop_stale.load(Relaxed) > 100, "устаревшие кадры должны отбрасываться: {}", la.stats.drop_stale.load(Relaxed));
    assert!(got < 100, "доставлено слишком много старых кадров: {got}");
    // новый кадр проходит с малой задержкой
    assert!(la.sender.try_send(Bytes::from_static(b"fresh")));
    let g = tokio::time::timeout(Duration::from_secs(1), lb.rx.recv()).await.unwrap().unwrap();
    assert_eq!(&g[..], b"fresh");
}

#[tokio::test]
async fn full_queue_drops_without_blocking() {
    let (a, _b) = duplex(16);
    let cfg = FrameConfig { queue_frames: 8, max_queue_delay: Duration::from_secs(60), ..FrameConfig::default() };
    let la = spawn(a, cfg);
    let t = std::time::Instant::now();
    let mut ok = 0;
    for _ in 0..1000 {
        if la.sender.try_send(Bytes::from(vec![0u8; 100])) {
            ok += 1;
        }
    }
    assert!(t.elapsed() < Duration::from_millis(200), "try_send не должен блокироваться");
    assert!(ok < 1000);
    assert!(la.stats.drop_full.load(Relaxed) > 900);
}

#[tokio::test]
async fn closed_notification() {
    let (a, b) = duplex(1024);
    let mut la = spawn(a, FrameConfig::default());
    drop(b);
    tokio::time::timeout(Duration::from_secs(2), la.closed()).await.expect("closed");
}
