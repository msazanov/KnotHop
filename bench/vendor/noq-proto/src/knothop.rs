//! KnotHop patch: потолок UDP-пакета для путей по адресам, помеченным приложением (custom-транспорт mesh).
//!
//! Custom-транспорт не сообщает QUIC свой MTU: кадр mesh едет датаграммой соседского QUIC (заголовок + пакет), и пакет больше
//! `max_datagram_size соседа - заголовок` отбрасывается молча. Без потолка тёплый запасной путь стартует с `initial_mtu` (1452),
//! крупные пакеты теряются сериями, детектор «чёрной дыры» сбрасывает MTU пути в 1200 и датаграмма VPN 1328 Б перестаёт влезать.

use std::net::SocketAddr;
use std::sync::OnceLock;

/// Функция потолка: по удалённому адресу пути вернуть наибольший UDP-пакет или `None` (без ограничения).
pub type PathMtuCap = fn(&SocketAddr) -> Option<u16>;

static CAP: OnceLock<PathMtuCap> = OnceLock::new();

/// Установить функцию потолка (один раз за процесс).
pub fn set_path_mtu_cap(f: PathMtuCap) {
    let _ = CAP.set(f);
}

pub(crate) fn path_mtu_cap(remote: &SocketAddr) -> Option<u16> {
    CAP.get().and_then(|f| f(remote))
}
