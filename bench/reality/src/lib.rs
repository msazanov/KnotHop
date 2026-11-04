//! knothop-reality: маскировка уровня REALITY (собственная реализация). См. DESIGN.md.
pub mod auth;
pub mod carrier;
pub mod cert;
pub mod chello;
pub mod client;
pub mod error;
pub mod handshake;
pub mod kx;
pub mod mimic;
pub mod probe;
pub mod profile;
pub mod proxy;
pub mod server;
pub mod stream;
pub mod tls13;
pub mod util;

pub use client::{connect, ClientConfig};
pub use error::{Error, Result};
pub use server::{Accepted, Listener, Server, ServerConfig};
