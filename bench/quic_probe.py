#!/usr/bin/env python3
"""QUIC through the tunnel: does real QUIC (RFC 9000, UDP, >=1200-byte datagrams) work, and how fast.

Runs inside the test containers (aioquic, BSD-3-Clause; test tool only, never part of the product).
  server:  quic_probe.py server <port>
  client:  quic_probe.py client <host> <port> <seconds>
The client prints one JSON object: handshake time, short request/response RTTs (each on its own stream),
and goodput of a timed bulk upload on one stream.
A self-signed throw-away certificate is generated in memory on every server start; nothing is stored.
"""
import asyncio
import datetime
import json
import ssl
import sys
import time

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived

ALPN = ["knothop-probe"]


def self_signed():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "knothop-probe")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1)).sign(key, hashes.SHA256()))
    return cert, key


class ServerProto(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.received = {}  # per connection: stream ids repeat across connections

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if event.data.startswith(b"PING") and event.end_stream:
                self._quic.send_stream_data(sid, event.data, end_stream=True)
            else:
                self.received[sid] = self.received.get(sid, 0) + len(event.data)
                if event.end_stream:
                    self._quic.send_stream_data(sid, str(self.received[sid]).encode(), end_stream=True)
            self.transmit()


async def run_server(port):
    cert, key = self_signed()
    cfg = QuicConfiguration(is_client=False, alpn_protocols=ALPN, certificate=cert, private_key=key)
    await serve("0.0.0.0", port, configuration=cfg, create_protocol=ServerProto)
    await asyncio.Future()


class ClientProto(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.waiters = {}
        self.buf = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self.buf[event.stream_id] = self.buf.get(event.stream_id, b"") + event.data
            if event.end_stream and event.stream_id in self.waiters:
                self.waiters.pop(event.stream_id).set_result(self.buf.pop(event.stream_id))
        elif isinstance(event, ConnectionTerminated):
            for w in self.waiters.values():
                if not w.done():
                    w.set_exception(ConnectionError(event.reason_phrase))

    async def request(self, data, timeout=5.0):
        sid = self._quic.get_next_available_stream_id()
        fut = asyncio.get_running_loop().create_future()
        self.waiters[sid] = fut
        self._quic.send_stream_data(sid, data, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(fut, timeout)


async def run_client(host, port, seconds):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=ALPN, verify_mode=ssl.CERT_NONE)
    out = {"ok": False}
    t0 = time.perf_counter()
    try:
        async with connect(host, port, configuration=cfg, create_protocol=ClientProto, wait_connected=True) as c:
            out["handshake_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            rtts = []
            for i in range(30):
                s = time.perf_counter()
                reply = await c.request(b"PING%04d" % i)
                if reply.startswith(b"PING"):
                    rtts.append((time.perf_counter() - s) * 1000)
                await asyncio.sleep(0.05)
            rtts.sort()
            out["rtt_ms"] = {"n": len(rtts), "p50": round(rtts[len(rtts) // 2], 2), "p95": round(rtts[int(len(rtts) * 0.95) - 1], 2),
                             "max": round(rtts[-1], 2)} if rtts else None
            # Timed bulk upload on one stream.
            sid = c._quic.get_next_available_stream_id()
            fut = asyncio.get_running_loop().create_future()
            c.waiters[sid] = fut
            chunk = b"\x5a" * 60000
            sent, start = 0, time.perf_counter()
            while time.perf_counter() - start < seconds:
                c._quic.send_stream_data(sid, chunk, end_stream=False)
                c.transmit()
                sent += len(chunk)
                # Do not queue unboundedly in user space: wait while the unacknowledged backlog is large.
                # (`_buffer` is aioquic's private send buffer; absent -> no backpressure, still a valid test.)
                while len(getattr(c._quic._streams[sid].sender, "_buffer", b"")) > 3_000_000:
                    await asyncio.sleep(0.001)
                await asyncio.sleep(0)
            c._quic.send_stream_data(sid, b"", end_stream=True)
            c.transmit()
            total = int((await asyncio.wait_for(fut, 30)).decode())
            took = time.perf_counter() - start
            out.update(ok=total == sent, bytes_sent=sent, bytes_acked_by_server=total, seconds=round(took, 2),
                       goodput_mbit_s=round(total * 8 / took / 1e6, 2))
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
    print(json.dumps(out))


if __name__ == "__main__":
    if sys.argv[1] == "server":
        asyncio.run(run_server(int(sys.argv[2])))
    else:
        asyncio.run(run_client(sys.argv[2], int(sys.argv[3]), float(sys.argv[4])))
