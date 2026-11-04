use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// нарушение протокола TLS/кадрирования
    Protocol(&'static str),
    /// сервер не прошёл проверку (перехват, чужой сертификат, неверный HMAC)
    Intercepted(&'static str),
    Timeout(&'static str),
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Protocol(s) => write!(f, "protocol: {s}"),
            Error::Intercepted(s) => write!(f, "server verification failed: {s}"),
            Error::Timeout(s) => write!(f, "timeout: {s}"),
            Error::Config(s) => write!(f, "config: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            Error::Timeout(s) => io::Error::new(io::ErrorKind::TimedOut, s),
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}
