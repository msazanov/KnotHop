//! Заголовок PROXY protocol v2 (HAProxy), только разбор. Читает ровно заголовок, не захватывая байты TLS.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};

pub const SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
const MAX_LEN: usize = 536;

/// Ok(Some(адрес источника)) для PROXY TCP4/TCP6; Ok(None) для LOCAL/неизвестного семейства; Err при неверном заголовке.
pub async fn read_v2<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<SocketAddr>> {
    let mut h = [0u8; 16];
    r.read_exact(&mut h).await?;
    parse_v2(&h, r).await
}

async fn parse_v2<R: AsyncRead + Unpin>(h: &[u8; 16], r: &mut R) -> Result<Option<SocketAddr>> {
    if h[..12] != SIG {
        return Err(Error::Protocol("no PROXY v2 signature"));
    }
    let (ver, cmd) = (h[12] >> 4, h[12] & 0x0f);
    if ver != 2 || cmd > 1 {
        return Err(Error::Protocol("bad PROXY v2 version/command"));
    }
    let len = u16::from_be_bytes([h[14], h[15]]) as usize;
    if len > MAX_LEN {
        return Err(Error::Protocol("PROXY v2 header too long"));
    }
    let mut b = vec![0u8; len];
    r.read_exact(&mut b).await?;
    if cmd == 0 {
        return Ok(None);
    }
    Ok(match h[13] {
        0x11 if len >= 12 => Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])), u16::from_be_bytes([b[8], b[9]]))),
        0x21 if len >= 36 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), u16::from_be_bytes([b[32], b[33]])))
        }
        0x11 | 0x21 => return Err(Error::Protocol("PROXY v2 address block too short")),
        _ => None,
    })
}

/// Для тестов и стенда: собирает заголовок PROXY v2 для TCP4.
pub fn build_v2_tcp4(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let (SocketAddr::V4(s), SocketAddr::V4(d)) = (src, dst) else { panic!("только IPv4") };
    let mut o = SIG.to_vec();
    o.extend_from_slice(&[0x21, 0x11, 0, 12]);
    o.extend_from_slice(&s.ip().octets());
    o.extend_from_slice(&d.ip().octets());
    o.extend_from_slice(&s.port().to_be_bytes());
    o.extend_from_slice(&d.port().to_be_bytes());
    o
}
