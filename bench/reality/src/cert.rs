//! Временный X.509-сертификат ed25519 (DER) в стиле REALITY: «подпись» - HMAC(auth_key, ключ), а не подпись CA.
//! Клиент не строит цепочку: разбирает DER, берёт ключ и «подпись», сверяет HMAC. Содержимое видно только после шифрования TLS.
use crate::util::Rd;

fn tlv(tag: u8, c: &[u8]) -> Vec<u8> {
    let mut o = vec![tag];
    match c.len() {
        n if n < 128 => o.push(n as u8),
        n if n < 256 => o.extend_from_slice(&[0x81, n as u8]),
        n => {
            o.push(0x82);
            o.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    o.extend_from_slice(c);
    o
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

fn name(cn: &str) -> Vec<u8> {
    let atv = seq(&[&[0x06, 0x03, 0x55, 0x04, 0x03], &tlv(0x0c, cn.as_bytes())]);
    seq(&[&tlv(0x31, &atv)])
}

pub fn build(ed_pub: &[u8; 32], mac: &[u8; 64], cn: &str, serial: [u8; 8]) -> Vec<u8> {
    let mut ser = serial;
    ser[0] &= 0x7f; // положительное целое
    ser[0] |= 0x01;
    let sigalg = seq(&[OID_ED25519]);
    let validity = seq(&[&tlv(0x17, b"260101000000Z"), &tlv(0x17, b"360101000000Z")]);
    let mut bs = vec![0u8];
    bs.extend_from_slice(ed_pub);
    let spki = seq(&[&sigalg, &tlv(0x03, &bs)]);
    let tbs = seq(&[&tlv(0xa0, &tlv(0x02, &[2])), &tlv(0x02, &ser), &sigalg, &name(cn), &validity, &name(cn), &spki]);
    let mut sig = vec![0u8];
    sig.extend_from_slice(mac);
    seq(&[&tbs, &sigalg, &tlv(0x03, &sig)])
}

fn read_tlv<'a>(r: &mut Rd<'a>) -> Option<(u8, &'a [u8])> {
    let tag = r.u8()?;
    let l = r.u8()? as usize;
    let n = match l {
        0..=127 => l,
        0x81 => r.u8()? as usize,
        0x82 => r.u16()? as usize,
        _ => return None,
    };
    Some((tag, r.bytes(n)?))
}

/// Возвращает (открытый ключ ed25519, «подпись» 64 Б) строго по шаблону build(); иное - None.
pub fn parse(der: &[u8]) -> Option<([u8; 32], [u8; 64])> {
    let mut r = Rd::new(der);
    let (t, cert) = read_tlv(&mut r)?;
    if t != 0x30 || r.left() != 0 {
        return None;
    }
    let mut c = Rd::new(cert);
    let (t, tbs) = read_tlv(&mut c)?;
    if t != 0x30 {
        return None;
    }
    let (t, alg) = read_tlv(&mut c)?;
    if t != 0x30 || alg != OID_ED25519 {
        return None;
    }
    let (t, sig) = read_tlv(&mut c)?;
    if t != 0x03 || sig.len() != 65 || sig[0] != 0 || c.left() != 0 {
        return None;
    }
    let mut b = Rd::new(tbs);
    for _ in 0..6 {
        read_tlv(&mut b)?; // version, serial, sigalg, issuer, validity, subject
    }
    let (t, spki) = read_tlv(&mut b)?;
    if t != 0x30 || b.left() != 0 {
        return None;
    }
    let mut s = Rd::new(spki);
    let (t, a) = read_tlv(&mut s)?;
    if t != 0x30 || a != OID_ED25519 {
        return None;
    }
    let (t, key) = read_tlv(&mut s)?;
    if t != 0x03 || key.len() != 33 || key[0] != 0 || s.left() != 0 {
        return None;
    }
    Some((key[1..].try_into().ok()?, sig[1..].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let der = build(&[7; 32], &[9; 64], "example.org", [1; 8]);
        assert_eq!(parse(&der), Some(([7; 32], [9; 64])));
        assert!(parse(&der[..der.len() - 1]).is_none());
        assert!(parse(&[]).is_none());
    }
}
