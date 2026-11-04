//! Клиент: ClientHello по профилю браузера, токен в session_id, проверка сервера, поток поверх записей TLS.
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::auth::ShortId;
use crate::error::{Error, Result};
use crate::handshake::{client_handshake, ClientMode};
use crate::profile::Profile;
use crate::mimic::{self, Mimic};
use crate::stream::{Padding, RealityStream};

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// статический открытый ключ сервера x25519 (из конфигурации/приглашения)
    pub server_pubkey: [u8; 32],
    pub short_id: ShortId,
    /// SNI сайта-прикрытия
    pub sni: String,
    pub profile: Profile,
    pub padding: Padding,
    /// начальный обмен «как h2 браузера» (+1 RTT) и форма первых записей; должно совпадать с настройкой сервера
    pub mimic: Mimic,
    pub handshake_timeout: Duration,
    /// поправка к часам устройства в секундах (токен несёт время; сервер принимает окно ±skew)
    pub clock_offset_secs: i64,
}

impl ClientConfig {
    pub fn new(server_pubkey: [u8; 32], short_id: ShortId, sni: impl Into<String>) -> Self {
        ClientConfig { server_pubkey, short_id, sni: sni.into(), profile: Profile::chrome155(), padding: Padding::default(), mimic: Mimic::default(), handshake_timeout: Duration::from_secs(10), clock_offset_secs: 0 }
    }
}

/// Рукопожатие поверх готового соединения (TCP до Traefik/сервера). При подмене сервера - `Error::Intercepted`, данные не отправляются.
pub async fn connect<IO: AsyncRead + AsyncWrite + Unpin>(mut io: IO, cfg: &ClientConfig) -> Result<RealityStream<IO>> {
    let mode = ClientMode::Reality { server_pub: cfg.server_pubkey, short_id: cfg.short_id, clock_offset_secs: cfg.clock_offset_secs };
    let mut est = tokio::time::timeout(cfg.handshake_timeout, client_handshake(&mut io, &cfg.profile, &cfg.sni, mode)).await.map_err(|_| Error::Timeout("client handshake"))??;
    if cfg.mimic.enabled {
        let shape = tokio::time::timeout(cfg.handshake_timeout, mimic::client_preface(&mut io, &mut est, &cfg.mimic.profile)).await.map_err(|_| Error::Timeout("h2 preface"))??;
        return Ok(RealityStream::new(io, est, cfg.padding).with_shape(shape));
    }
    Ok(RealityStream::new(io, est, cfg.padding))
}
