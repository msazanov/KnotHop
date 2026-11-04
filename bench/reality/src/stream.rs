//! Поток данных поверх записей TLS 1.3 после рукопожатия: AsyncRead + AsyncWrite, набивка первых записей,
//! KeyUpdate (ротация ключей по числу записей и по запросу пира), close_notify.
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::Error;
use crate::handshake::Established;
use crate::tls13::*;
use crate::util;

/// Ротация ключей отправки после стольких записей (предел AES-GCM ~2^24,5 записей; берём с большим запасом).
pub const REKEY_AFTER_RECORDS: u64 = 1 << 22;
/// Если пир не сменил ключи за столько записей - разрыв.
pub const RECV_MAX_RECORDS: u64 = 1 << 24;

/// Набивка записей против «TLS in TLS»: у первых `first_records` записей каждого направления к содержимому добавляются
/// случайные `0..=max_pad` нулевых байт (внутренняя набивка TLS 1.3, снаружи неотличима от данных).
#[derive(Clone, Copy, Debug)]
pub struct Padding {
    pub first_records: u64,
    pub max_pad: usize,
}

impl Default for Padding {
    fn default() -> Self {
        Padding { first_records: 16, max_pad: 255 }
    }
}

impl Padding {
    pub const NONE: Padding = Padding { first_records: 0, max_pad: 0 };
}

/// Форма первых записей (после начального обмена `mimic`): у записей с номером `< chunk_records` тело режется на куски случайного
/// размера из `chunk` (длина тела с тегом); `pad_to[i]` - минимальный размер тела i-й записи (добивается набивкой).
/// Если задана форма, случайная набивка `Padding` не применяется.
#[derive(Clone, Debug, Default)]
pub struct Shape {
    pub chunk: Option<(usize, usize)>,
    pub chunk_records: u64,
    pub pad_to: Vec<usize>,
}

pub struct RealityStream<IO> {
    io: IO,
    send: Cipher,
    recv: Cipher,
    rbuf: Vec<u8>,
    plain: Vec<u8>,
    plain_pos: usize,
    hs: HsBuf,
    eof: bool,
    wbuf: Vec<u8>,
    wpos: usize,
    sent: u64,
    pad: Padding,
    shape: Option<Shape>,
    need_ku: bool,
    rekey_after: u64,
    shutdown_queued: bool,
    tmp: Box<[u8; 18 * 1024]>,
}

impl<IO> RealityStream<IO> {
    pub fn new(io: IO, est: Established, pad: Padding) -> Self {
        RealityStream {
            io,
            send: est.send,
            recv: est.recv,
            rbuf: Vec::with_capacity(20 * 1024),
            plain: Vec::new(),
            plain_pos: 0,
            hs: HsBuf::default(),
            eof: false,
            wbuf: Vec::new(),
            wpos: 0,
            sent: 0,
            pad,
            shape: None,
            need_ku: false,
            rekey_after: REKEY_AFTER_RECORDS,
            shutdown_queued: false,
            tmp: Box::new([0u8; 18 * 1024]),
        }
    }
    /// Форма первых записей (см. `Shape`); вместо случайной набивки.
    pub fn with_shape(mut self, s: Shape) -> Self {
        self.shape = Some(s);
        self
    }
    /// Порог ротации ключей отправки (по умолчанию REKEY_AFTER_RECORDS); для тестов.
    pub fn set_rekey_after(&mut self, records: u64) {
        self.rekey_after = records.max(1);
    }
    pub fn get_ref(&self) -> &IO {
        &self.io
    }
    pub fn into_inner(self) -> IO {
        self.io
    }
}

fn proto(e: Error) -> io::Error {
    e.into()
}

impl<IO: AsyncRead + Unpin> RealityStream<IO> {
    /// Забирает из rbuf одну целую запись и разбирает; Ok(true) - состояние изменилось (появились данные/EOF).
    fn take_record(&mut self) -> io::Result<bool> {
        if self.rbuf.len() < 5 {
            return Ok(false);
        }
        let n = u16::from_be_bytes([self.rbuf[3], self.rbuf[4]]) as usize;
        if self.rbuf[1] != 3 || n > MAX_CIPHERTEXT {
            return Err(proto(Error::Protocol("bad record header")));
        }
        if self.rbuf.len() < 5 + n {
            return Ok(false);
        }
        let hdr: [u8; 5] = self.rbuf[..5].try_into().unwrap();
        let mut body: Vec<u8> = self.rbuf[5..5 + n].to_vec();
        self.rbuf.drain(..5 + n);
        if hdr[0] != CT_APPDATA {
            return Err(proto(Error::Protocol("unexpected plaintext record")));
        }
        if self.recv.seq >= RECV_MAX_RECORDS {
            return Err(proto(Error::Protocol("peer did not rekey")));
        }
        let (typ, pt) = self.recv.open(hdr, &mut body).map_err(proto)?;
        match typ {
            CT_APPDATA => {
                self.plain.clear();
                self.plain.extend_from_slice(pt);
                self.plain_pos = 0;
                Ok(true)
            }
            CT_ALERT => {
                if pt.len() == 2 && pt[1] == 0 {
                    self.eof = true;
                    Ok(true)
                } else {
                    Err(proto(Error::Protocol("alert from peer")))
                }
            }
            CT_HANDSHAKE => {
                self.hs.push(pt);
                while let Some(m) = self.hs.next().map_err(proto)? {
                    match m[0] {
                        HS_KEY_UPDATE => {
                            if m.len() != 5 || m[4] > 1 {
                                return Err(proto(Error::Protocol("bad KeyUpdate")));
                            }
                            self.recv.rekey();
                            if m[4] == 1 {
                                self.need_ku = true;
                            }
                        }
                        HS_NEW_SESSION_TICKET => {}
                        _ => return Err(proto(Error::Protocol("unexpected post-handshake message"))),
                    }
                }
                Ok(true)
            }
            _ => Err(proto(Error::Protocol("unexpected inner record type"))),
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for RealityStream<IO> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.plain_pos < this.plain.len() {
                let n = (this.plain.len() - this.plain_pos).min(out.remaining());
                out.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.take_record()? {
                continue;
            }
            let mut rb = ReadBuf::new(&mut this.tmp[..]);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                if this.rbuf.is_empty() {
                    // обрыв без close_notify: для туннеля это конец потока, но не «чистый»
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed without close_notify")));
                }
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated record")));
            }
            let filled = rb.filled().to_vec();
            this.rbuf.extend_from_slice(&filled);
        }
    }
}

impl<IO: AsyncWrite + Unpin> RealityStream<IO> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }

    fn queue_key_update(&mut self) {
        let m = hs_msg(HS_KEY_UPDATE, &[0]);
        let r = self.send.seal(CT_HANDSHAKE, &m, 0);
        self.wbuf.extend_from_slice(&r);
        self.send.rekey();
        self.need_ku = false;
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for RealityStream<IO> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.shutdown_queued {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.send.seq >= this.rekey_after || this.need_ku {
            this.queue_key_update();
        }
        let (n, pad) = if let Some(sh) = &this.shape {
            let mut cap = MAX_INNER - 1;
            if let (Some((lo, hi)), true) = (sh.chunk, this.sent < sh.chunk_records) {
                cap = cap.min((lo + util::below((hi - lo + 1) as u32) as usize).saturating_sub(17).max(1));
            }
            let n = buf.len().min(cap);
            let pad = sh.pad_to.get(this.sent as usize).map_or(0, |t| t.saturating_sub(n + 17).min(MAX_INNER - 1 - n));
            (n, pad)
        } else {
            let pad = if this.sent < this.pad.first_records && this.pad.max_pad > 0 { util::below(this.pad.max_pad as u32 + 1) as usize } else { 0 };
            (buf.len().min(MAX_INNER - 1 - pad), pad)
        };
        let rec = this.send.seal(CT_APPDATA, &buf[..n], pad);
        this.wbuf.extend_from_slice(&rec);
        this.sent += 1;
        // попытка сразу отправить; если сокет занят - запись остаётся в wbuf и уйдёт при следующем вызове
        match this.poll_drain(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            _ => {}
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if !this.shutdown_queued {
            let r = this.send.seal(CT_ALERT, &[1, 0], 0);
            this.wbuf.extend_from_slice(&r);
            this.shutdown_queued = true;
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
