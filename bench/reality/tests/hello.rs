//! ClientHello по профилю: форма совпадает со снятыми у Chromium 155, JA4 совпадает с эталоном, порядок расширений случаен.
use knothop_reality::chello::{self, parse_hello};
use knothop_reality::profile::{build_hello, Profile};
use knothop_reality::util::{self, is_grease};
use std::collections::BTreeSet;

const EXPECTED_JA4: &str = "t13d1517h2_8daaf6152771_cb7bf5808d99";

/// Форма хелло: всё, что не случайно, как есть; GREASE и случайные поля замаскированы.
fn shape(msg: &[u8]) -> (Vec<u16>, BTreeSet<(u16, Vec<u8>)>, usize) {
    let h = parse_hello(msg).expect("разбор");
    let mut ciphers: Vec<u16> = h.ciphers.iter().map(|c| if is_grease(*c) { 0xdead } else { *c }).collect();
    ciphers.dedup();
    let mut set = BTreeSet::new();
    for (id, d) in &h.exts {
        let id = if is_grease(*id) { 0xdead } else { *id };
        let d: Vec<u8> = match id {
            10 | 13 | 43 => {
                // списки u16: GREASE маскируем
                let skip = if id == 43 { 1 } else { 2 };
                let mut v = d[..skip].to_vec();
                for c in d[skip..].chunks(2) {
                    let x = u16::from_be_bytes([c[0], c[1]]);
                    v.extend_from_slice(&if is_grease(x) { 0xdeadu16 } else { x }.to_be_bytes());
                }
                v
            }
            51 => {
                // key_share: группы и длины
                let mut v = vec![];
                let mut r = util::Rd::new(&d[2..]);
                while r.left() > 0 {
                    let g = r.u16().unwrap();
                    let b = r.vec16().unwrap();
                    v.extend_from_slice(&(if is_grease(g) { 0xdead } else { g }).to_be_bytes());
                    v.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    if g == 0 || is_grease(g) {
                        v.extend_from_slice(b);
                    }
                }
                v
            }
            65037 => d[..5].to_vec(), // тип, kdf, aead; длины payload проверяются отдельно
            _ => d.to_vec(),
        };
        set.insert((id, d));
    }
    let ech_len = h.ext(65037).unwrap().len();
    (ciphers, set, ech_len)
}

fn captures() -> Vec<Vec<u8>> {
    include_str!("../hello-profiles/chrome155-captures.hex").lines().filter(|l| !l.trim().is_empty()).map(|l| util::unhex(l).unwrap()).collect()
}

#[test]
fn shape_matches_chromium_captures() {
    let caps = captures();
    assert!(caps.len() >= 8);
    let p = Profile::chrome155();
    // эталонная форма: у всех снятых хелло одинакова (с точностью до ECH payload длины)
    let ref_shape = shape(&caps[0][5..]);
    for c in &caps {
        let s = shape(&c[5..]);
        assert_eq!(s.0, ref_shape.0);
        assert_eq!(s.1, ref_shape.1);
    }
    for _ in 0..300 {
        let d = build_hello(&p, "cover.example.org");
        let msg = d.with_sid(&util::random::<32>());
        let s = shape(&msg);
        assert_eq!(s.0, ref_shape.0, "шифры");
        assert_eq!(s.1, ref_shape.1, "расширения (форма)");
        assert!([186usize, 218, 250, 282].contains(&s.2), "длина ECH {}", s.2);
        // размер записи как у Chrome: 1925/1957/1989/2021
        let rec = d.record(&msg);
        assert!([1925usize, 1957, 1989, 2021].contains(&rec.len()), "длина записи {}", rec.len());
        assert_eq!(&rec[..3], &[22, 3, 1]);
        assert_eq!(chello::check_record(&rec, 16384), chello::Record::Hello(rec.len()));
    }
}

#[test]
fn ja4_equals_chromium() {
    for c in captures() {
        let h = parse_hello(&c[5..]).unwrap();
        assert_eq!(chello::ja4(&h), EXPECTED_JA4, "эталон из снимка");
    }
    let p = Profile::chrome155();
    let mut orders = BTreeSet::new();
    for _ in 0..200 {
        let d = build_hello(&p, "cover.example.org");
        let msg = d.with_sid(&[7; 32]);
        let h = parse_hello(&msg).unwrap();
        assert_eq!(chello::ja4(&h), EXPECTED_JA4);
        let ids: Vec<u16> = h.exts.iter().map(|e| e.0).collect();
        assert!(is_grease(ids[0]) && is_grease(*ids.last().unwrap()) && ids[0] != *ids.last().unwrap());
        assert_eq!(h.ext(ids[0]).unwrap(), &[] as &[u8]);
        assert_eq!(h.ext(*ids.last().unwrap()).unwrap(), &[0u8]);
        orders.insert(ids.iter().map(|i| if is_grease(*i) { 0 } else { *i }).collect::<Vec<_>>());
        assert_eq!(h.session_id.len(), 32);
        // key_share GREASE = GREASE в supported_groups
        assert_eq!(h.groups[0], h.shares[0].0);
        assert_eq!(h.shares[1].1.len(), 1216);
        assert_eq!(h.shares[2].1.len(), 32);
    }
    assert!(orders.len() > 150, "перестановка расширений должна быть случайной: {}", orders.len());
}

#[test]
fn profile_parser_rejects_garbage() {
    assert!(Profile::parse("").is_err());
    assert!(Profile::parse("ciphers zz\next 1 any raw").is_err());
    assert!(Profile::parse("bogus line").is_err());
}
