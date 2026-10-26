"""Host-side protocol regression tests; no public network and no VPN required.
Compile the same tiny client locally and test complete, chunked and bad responses.
"""
import http.server
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
import json


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/forbidden":
            self.send_response(403)
            self.end_headers()
            return
        if self.path == "/eof":
            # HTTP/1.0 без Content-Length: тело читается до закрытия соединения
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"0123456789")
            self.close_connection = True
            return
        self.send_response(200)
        if self.path == "/chunked":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"3\r\nabc\r\n7\r\ndefghij\r\n0\r\n\r\n")
        else:
            self.send_header("Content-Length", "10")
            self.end_headers()
            self.wfile.write(b"abc" if self.path == "/short" else b"abcdefghij")

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        data = self.rfile.read(n)
        self.send_response(200 if len(data) == n else 400)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class NetprobeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="knothop-netprobe-")
        cls.binary = str(Path(cls.tmp.name) / "netprobe")
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(Path(__file__).with_name("netprobe.c")), "-o", cls.binary], check=True)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.tmp.cleanup()

    def probe(self, mode, path, n):
        return subprocess.run([self.binary, mode, "127.0.0.1", str(self.server.server_port), path, str(n)],
                              capture_output=True, text=True, timeout=10)

    def test_complete_download_and_chunked_count_body_not_headers(self):
        for path in ["/plain", "/chunked", "/eof"]:
            r = self.probe("down", path, 10)
            self.assertEqual(r.returncode, 0, r.stderr)
            v = json.loads(r.stdout)
            self.assertEqual(v["body_received"], 10)
            # скорость приёма считается от connect до последнего байта, как и отдача - без DNS/connect
            base = v["seconds"] - v["connect_seconds"]
            self.assertGreater(base, 0)
            self.assertAlmostEqual(v["mbit_s"], 10 * 8 / base / 1e6, delta=0.01 + v["mbit_s"] * 0.05)

    def test_get_mode_prints_body_to_stderr_and_json_to_stdout(self):
        r = self.probe("get", "/plain", 0)
        self.assertEqual(r.returncode, 0, r.stderr)
        v = json.loads(r.stdout)
        self.assertEqual(v["body_received"], 10)
        self.assertEqual(v["mbit_s"], 0)
        self.assertIn("abcdefghij", r.stderr)

    def test_incomplete_or_http_error_never_claims_speed(self):
        for path in ["/short", "/forbidden"]:
            r = self.probe("down", path, 10)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stdout, "")

    def test_upload_requires_server_reply(self):
        r = self.probe("up", "/upload", 100000)
        self.assertEqual(r.returncode, 0, r.stderr)
        v = json.loads(r.stdout)
        self.assertEqual((v["status"], v["bytes_sent"], v["body_received"]), (200, 100000, 2))
        # время отдачи считается от connect до ответа сервера: без DNS/connect, но с подтверждением приёма
        self.assertGreater(v["send_seconds"], 0)
        self.assertGreaterEqual(v["seconds"] - v["connect_seconds"] + 1e-6, v["send_seconds"])
        self.assertAlmostEqual(v["mbit_s"] / (100000 * 8 / v["send_seconds"] / 1e6), 1, delta=0.01)

    def test_wrong_expected_length_is_failure(self):
        r = self.probe("down", "/plain", 11)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
