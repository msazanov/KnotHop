#!/usr/bin/env python3
"""Узкие mock-тесты deploy/phones.sh и deploy/live-check.sh без живых adb/ssh/сети.

Моки adb/ssh кладутся первыми в PATH и отвечают по переменным MOCK_*. Проверяется
реальное поведение скриптов: успех vpn-on только при режиме «VPN включён» и tun>0,
свежий UI dump, ошибки узла/телефона как не-pass, отсутствие сырого stderr и адресов
в JSON, сохранение нулей/false счётчиков, netprobe missing/failed.
"""
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PHONES = ROOT / "deploy" / "phones.sh"
LIVE = ROOT / "deploy" / "live-check.sh"

MOCK_ADB = r'''#!/usr/bin/env python3
import os, sys, pathlib
state = pathlib.Path(os.environ["KH_MOCK_DIR"])
ui = state / "ui.xml"
mode_file = state / "mode"

def render():
    # Диалог показывается до первого тапа «Разрешить» (тап пишет notif_done).
    pkg = "" if (state / "notif_done").exists() else os.environ.get("MOCK_DIALOG", "")
    mode = mode_file.read_text(encoding="utf-8").strip() if mode_file.exists() else os.environ.get("MOCK_MODE", "off")
    if pkg:
        return ('<?xml version="1.0"?><hierarchy rotation="0">'
                '<node package="%s" text="" bounds="[0,0][1080,2400]">'
                '<node text="Разрешить" bounds="[500,1200][900,1300]"/></node></hierarchy>' % pkg)
    title = {"vpn": "VPN включён", "network": "В сети нод, без VPN", "off": "Отключено",
             "blocked": "VPN не работает, трафик заблокирован: сдвиньте влево до конца"}.get(mode, "Отключено")
    conn = '<node text="выход: mock" bounds="[20,100][400,140]"/>' if mode in ("vpn", "network") else ""
    return ('<?xml version="1.0"?><hierarchy rotation="0">'
            '<node package="com.knothop.vpn" text="" bounds="[0,0][1080,2400]">'
            '<node text="%s" bounds="[20,2200][1060,2260]"/>%s'
            '<node class="android.widget.SeekBar" bounds="[40,2300][1040,2360]"/>'
            '</node></hierarchy>' % (title, conn))

args = sys.argv[1:]
if args == ["devices"]:
    if os.environ.get("MOCK_ADB_DAEMON") == "1":
        print("* daemon not running; starting now at tcp:5037")
        print("* daemon started successfully", file=sys.stderr)
    print("List of devices attached")
    for item in filter(None, os.environ.get("MOCK_DEVICES", "S1=device").split(",")):
        print(item.replace("=", "\t"))
    sys.exit(0)
if len(args) >= 3 and args[0] == "-s":
    serial, rest = args[1], args[2:]
    if rest and rest[0] == "install":
        print("Success"); sys.exit(0)
    if rest and rest[0] == "shell":
        cmd = " ".join(rest[1:])
        if cmd.startswith("rm -f "):
            p = cmd[len("rm -f "):].strip()
            if p == "/sdcard/knothop_ui.xml" and ui.exists():
                ui.unlink()
            sys.exit(0)
        if cmd.startswith("uiautomator dump"):
            if os.environ.get("MOCK_DUMP_FAIL") == "1":
                sys.exit(1)
            ui.write_text(render(), encoding="utf-8")
            sys.exit(0)
        if cmd.startswith("cat "):
            if ui.exists():
                sys.stdout.write(ui.read_text(encoding="utf-8")); sys.exit(0)
            sys.exit(1)
        if "ip -o link" in cmd:
            n = int(os.environ.get("MOCK_TUN", "0"))
            for i in range(n):
                print("%d: tun%d: <POINTOPOINT,UP> mtu 1280 qdisc none" % (i + 2, i))
            sys.exit(0)
        if "dumpsys package" in cmd:
            vc = os.environ.get("MOCK_PKG_VC", "")
            if vc:
                print("Packages:")
                print("  versionCode=%s minSdk=26 targetSdk=34" % vc)
                print("    versionName=%s" % os.environ.get("MOCK_PKG_VN", "0.0.0"))
            sys.exit(0)
        if cmd.startswith("getprop"):
            print(os.environ.get("MOCK_MODEL", "mock-model")); sys.exit(0)
        if cmd == "toybox" or cmd.startswith("toybox "):
            print("acpi base64 cat chmod cp cut date echo grep nc sleep tr"); sys.exit(0)
        if cmd.startswith("ping "):
            if os.environ.get("MOCK_PING_ALL_LOSS") == "1":
                # rc 0 при 100% потерь — путь для проверки защиты от ложного успеха
                print("PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data")
                print("20 packets transmitted, 0 received, 100% packet loss, time 3800ms")
                sys.exit(0)
            print("PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data")
            print("20 packets transmitted, 20 received, 0% packet loss, time 3000ms")
            print("rtt min/avg/max/mdev = 13.4/14.0/15.1/0.5 ms")
            sys.exit(0)
        if "for p in knothop-netprobe" in cmd:
            names = [x for x in os.environ.get("MOCK_NP", "").split(",") if x]
            if names:
                print(names[0])
            sys.exit(0)
        if "/data/local/tmp/" in cmd and (" down " in cmd or " up " in cmd):
            key = "DOWN" if " down " in cmd else "UP"
            sys.stdout.write(os.environ.get("MOCK_NP_%s_OUT" % key, ""))
            rc = int(os.environ.get("MOCK_NP_%s_RC" % key, "0"))
            if rc != 0:
                print("mock-netprobe: ошибка (errno=101)", file=sys.stderr)
            sys.exit(rc)
        if cmd.startswith("input "):
            if cmd.startswith("input tap"):
                (state / "notif_done").touch()
            elif cmd.startswith("input swipe") and os.environ.get("MOCK_SWIPE_OK") == "1":
                mode_file.write_text("vpn", encoding="utf-8")
            sys.exit(0)
        if cmd.startswith("am start"):
            sys.exit(0)
        sys.exit(0)
sys.exit(0)
'''

MOCK_SSH = r'''#!/usr/bin/env python3
import builtins, contextlib, io, os, pathlib, sys
state = pathlib.Path(os.environ["KH_MOCK_DIR"])
stdin = sys.stdin.read()
mode = os.environ.get("MOCK_SSH_MODE", "run")
if mode == "error":
    print("ssh: connect to host 10.1.2.3 port 22: Connection refused", file=sys.stderr)
    sys.exit(255)
if mode == "nojson":
    print("WARNING: no status", file=sys.stderr)
    sys.exit(0)
fixture = state / "status.json"
real_open = builtins.open
def fake_open(file, *a, **k):
    if str(file) == "/opt/knothop/state/status.json":
        return real_open(fixture, *a, **k)
    return real_open(file, *a, **k)
builtins.open = fake_open
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    try:
        exec(compile(stdin, "<node>", "exec"), {"__name__": "__main__"})
    except SystemExit:
        pass
builtins.open = real_open
sys.stdout.write(buf.getvalue())
sys.stdout.flush()
if os.environ.get("MOCK_SSH_EXTRA") == "1":
    print("sudo: unable to resolve host node-1")
sys.exit(0)
'''


def write_exec(path: pathlib.Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="kh-live-tools-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.state = self.tmp / "state"
        self.state.mkdir()
        write_exec(self.bin / "adb", MOCK_ADB)
        write_exec(self.bin / "ssh", MOCK_SSH)
        self.env = dict(os.environ)
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env.get("PATH", "")
        self.env["KH_MOCK_DIR"] = str(self.state)
        self.env["PHONES_UI_SETTLE"] = "0"
        self.env["PHONES_UI_POLL_TRIES"] = "2"
        for key in ("MOCK_DEVICES", "MOCK_TUN", "MOCK_MODE", "MOCK_SWIPE_OK", "MOCK_DUMP_FAIL",
                    "MOCK_NP", "MOCK_NP_DOWN_OUT", "MOCK_NP_DOWN_RC", "MOCK_NP_UP_OUT",
                    "MOCK_NP_UP_RC", "MOCK_PKG_VC", "MOCK_PKG_VN", "MOCK_MODEL", "MOCK_DIALOG",
                    "MOCK_SSH_MODE", "MOCK_SSH_EXTRA", "MOCK_ADB_DAEMON", "MOCK_PING_ALL_LOSS"):
            self.env.pop(key, None)
        self.env["MOCK_DEVICES"] = "S1=device"
        self.env["MOCK_TUN"] = "1"
        self.env["MOCK_PKG_VC"] = "32"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, script, *args, env=None):
        e = dict(self.env)
        if env:
            e.update(env)
        return subprocess.run(["bash", str(script), *args], capture_output=True, text=True,
                              env=e, timeout=120)

    def hosts(self, body="es\tmock@host\tknothopd\t\n"):
        p = self.tmp / "hosts.tsv"
        p.write_text(body, encoding="utf-8")
        return str(p)


class PhonesVpnOn(Base):
    def test_network_mode_with_exit_text_but_no_tun_is_not_success(self):
        self.env["MOCK_MODE"] = "network"
        self.env["MOCK_TUN"] = "0"
        r = self.run_script(PHONES, "vpn-on", "S1")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("VPN уже включён", r.stdout)
        self.assertNotIn("VPN подтверждён", r.stdout)
        self.assertIn("НЕ подтверждён", r.stdout)

    def test_success_requires_vpn_mode_and_tun(self):
        self.env["MOCK_MODE"] = "off"
        self.env["MOCK_TUN"] = "1"
        self.env["MOCK_SWIPE_OK"] = "1"
        r = self.run_script(PHONES, "vpn-on", "S1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VPN подтверждён", r.stdout)

    def test_stale_dump_is_not_used(self):
        # На «телефоне» лежит старый дамп с включённым VPN, свежий dump не работает.
        (self.state / "ui.xml").write_text(
            '<?xml version="1.0"?><hierarchy><node package="com.knothop.vpn" text="VPN включён" '
            'bounds="[0,0][10,10]"/></hierarchy>', encoding="utf-8")
        self.env["MOCK_MODE"] = "off"
        self.env["MOCK_TUN"] = "0"
        self.env["MOCK_DUMP_FAIL"] = "1"
        r = self.run_script(PHONES, "vpn-on", "S1")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("VPN уже включён", r.stdout)
        self.assertNotIn("VPN подтверждён", r.stdout)
        self.assertIn("свежий UI", r.stdout)

    def test_blocked_state_is_error(self):
        self.env["MOCK_MODE"] = "blocked"
        self.env["MOCK_TUN"] = "1"
        r = self.run_script(PHONES, "vpn-on", "S1")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("трафик заблокирован", r.stdout)

    def test_blocking_dialog_is_clear_error(self):
        self.env["MOCK_MODE"] = "vpn"
        self.env["MOCK_DIALOG"] = "com.android.vpndialogs"
        r = self.run_script(PHONES, "vpn-on", "S1")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("блокирующее окно", r.stdout)

    def test_notification_permission_dialog_is_dismissed(self):
        #permissioncontroller — единственный диалог, который закрывается тапом «Разрешить»
        self.env["MOCK_MODE"] = "vpn"
        self.env["MOCK_TUN"] = "1"
        self.env["MOCK_DIALOG"] = "com.google.android.permissioncontroller"
        r = self.run_script(PHONES, "vpn-on", "S1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("закрыт системный диалог", r.stdout)
        self.assertNotIn("блокирующее окно", r.stdout)
        self.assertTrue((self.state / "notif_done").exists())

    def test_explicit_serial_not_failed_by_unrelated_skipped_phone(self):
        # vpn-on с явным списком отвечает кодом за выбранные телефоны, а не за посторонние
        self.env["MOCK_DEVICES"] = "S1=device,S2=offline"
        self.env["MOCK_MODE"] = "off"
        self.env["MOCK_TUN"] = "1"
        self.env["MOCK_SWIPE_OK"] = "1"
        r = self.run_script(PHONES, "vpn-on", "S1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VPN подтверждён", r.stdout)
        self.assertIn("пропущен S2", r.stderr)

    def test_all_devices_run_fails_when_any_phone_skipped(self):
        # по умолчанию (без явного списка) пропущенный телефон — это ошибка прохода
        self.env["MOCK_DEVICES"] = "S1=device,S2=offline"
        self.env["MOCK_MODE"] = "vpn"
        self.env["MOCK_TUN"] = "1"
        r = self.run_script(PHONES, "vpn-on")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_offline_device_fails(self):
        self.env["MOCK_DEVICES"] = "S1=offline"
        r = self.run_script(PHONES, "vpn-on", "S1")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("offline/unauthorized", r.stderr + r.stdout)


class LiveCheckPhone(Base):
    def phone_json(self, r):
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        self.assertEqual(len(lines), 1, r.stdout)
        return json.loads(lines[0])

    def test_netprobe_missing_is_not_pass(self):
        self.env["MOCK_MODE"] = "vpn"
        self.env["MOCK_NP"] = ""
        r = self.run_script(LIVE, "--phones-only")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        j = self.phone_json(r)
        self.assertFalse(j["ok"])
        self.assertIn("netprobe-missing", j["problems"])
        self.assertEqual(j["netprobe"]["status"], "missing")
        self.assertNotIn("1.1.1.1", r.stdout)
        self.assertNotIn("сloudflare", r.stdout)

    def test_netprobe_failure_is_not_pass_and_no_raw_output(self):
        self.env["MOCK_MODE"] = "vpn"
        self.env["MOCK_NP"] = "knothop-netprobe"
        self.env["MOCK_NP_DOWN_RC"] = "1"
        self.env["MOCK_NP_DOWN_OUT"] = ""
        r = self.run_script(LIVE, "--phones-only")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        j = self.phone_json(r)
        self.assertFalse(j["ok"])
        self.assertEqual(j["download_50MB"]["status"], "failed")
        self.assertIn("download-failed", j["problems"])
        self.assertNotIn("mock-netprobe", r.stdout)

    def test_netprobe_ok_marks_upload_as_short_test(self):
        self.env["MOCK_MODE"] = "vpn"
        self.env["MOCK_NP"] = "rawg-netprobe"
        self.env["MOCK_NP_DOWN_OUT"] = json.dumps({
            "mode": "down", "status": 200, "body_received": 50000000, "seconds": 7.0,
            "connect_seconds": 0.1, "body_seconds": 6.9, "send_seconds": 0.01,
            "mbit_s": 57.1, "tcp_rtt_us": 13000, "tcp_total_retrans": 0}) + "\n"
        self.env["MOCK_NP_UP_OUT"] = json.dumps({
            "mode": "up", "status": 200, "bytes_sent": 10000000, "seconds": 0.5,
            "connect_seconds": 0.1, "body_seconds": 0.4, "send_seconds": 0.4,
            "mbit_s": 160.0, "tcp_rtt_us": 14000, "tcp_total_retrans": 434}) + "\n"
        r = self.run_script(LIVE, "--phones-only")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        j = self.phone_json(r)
        self.assertTrue(j["ok"])
        self.assertEqual(j["netprobe"]["name"], "rawg-netprobe")
        self.assertEqual(j["upload_10MB"]["kind"], "short-transfer-test")
        self.assertIs(j["upload_10MB"]["capacity"], False)
        self.assertNotIn("1.1.1.1", r.stdout)

    def test_no_tun_skips_measurements_and_is_not_pass(self):
        self.env["MOCK_MODE"] = "network"
        self.env["MOCK_TUN"] = "0"
        r = self.run_script(LIVE, "--phones-only")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        j = self.phone_json(r)
        self.assertFalse(j["ok"])
        self.assertIn("no-tun", j["problems"])
        self.assertEqual(j["netprobe"]["status"], "skipped")

    def test_ping_full_loss_with_rc0_is_not_ok(self):
        # некоторые toybox-сборки ping возвращают 0 даже при 100% потерь — это не успех
        self.env["MOCK_MODE"] = "vpn"
        self.env["MOCK_NP"] = "knothop-netprobe"
        self.env["MOCK_PING_ALL_LOSS"] = "1"
        self.env["MOCK_NP_DOWN_OUT"] = json.dumps({
            "status": 200, "body_received": 50000000, "seconds": 7.0}) + "\n"
        self.env["MOCK_NP_UP_OUT"] = json.dumps({
            "status": 200, "bytes_sent": 10000000, "seconds": 0.5}) + "\n"
        r = self.run_script(LIVE, "--phones-only")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        j = self.phone_json(r)
        self.assertFalse(j["ok"])
        self.assertEqual(j["problems"], ["ping-failed"])
        self.assertEqual(j["ping"]["status"], "failed")
        self.assertEqual(j["ping"]["recv"], 0)

    def test_stray_adb_daemon_lines_do_not_skip_devices(self):
        self.env["MOCK_ADB_DAEMON"] = "1"
        self.env["MOCK_MODE"] = "vpn"
        self.env["MOCK_NP"] = "knothop-netprobe"
        self.env["MOCK_NP_DOWN_OUT"] = json.dumps({
            "mode": "down", "status": 200, "body_received": 50000000, "seconds": 7.0}) + "\n"
        self.env["MOCK_NP_UP_OUT"] = json.dumps({
            "mode": "up", "status": 200, "bytes_sent": 10000000, "seconds": 0.5}) + "\n"
        r = self.run_script(LIVE, "--phones-only")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("пропущен", r.stderr)
        self.assertTrue(self.phone_json(r)["ok"])

    def test_offline_device_fails_without_json_claim(self):
        self.env["MOCK_DEVICES"] = "S1=offline"
        r = self.run_script(LIVE, "--phones-only")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual(r.stdout.strip(), "")


class LiveCheckNode(Base):
    def run_nodes(self, env=None):
        return self.run_script(LIVE, "--nodes-only", env={"HOSTS_FILE": self.hosts(), **(env or {})})

    def node_json(self, r):
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        self.assertEqual(len(lines), 1, r.stdout)
        return json.loads(lines[0])

    def status(self, body):
        (self.state / "status.json").write_text(json.dumps(body), encoding="utf-8")

    def test_status_json_error_is_not_ok(self):
        r = self.run_nodes()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        j = self.node_json(r)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"], "status-json-missing")

    def test_status_error_state_is_not_ok(self):
        self.status({"state": "error", "tun": {"dataplane": {"tx": 1}}})
        r = self.run_nodes()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        j = self.node_json(r)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"], "status-error")

    def test_zero_counters_and_false_are_kept(self):
        self.status({"tun": {"dataplane": {"tx": 0, "rx": 0, "bindings": 0, "tx_enabled": False},
                             "mesh": {"enabled": False, "tx": 0, "fwd": 0}}})
        r = self.run_nodes()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        j = self.node_json(r)
        self.assertTrue(j["ok"])
        self.assertEqual(j["dataplane"]["tx"], 0)
        self.assertIs(j["dataplane"]["tx_enabled"], False)
        self.assertIs(j["mesh"]["enabled"], False)

    def test_stderr_after_valid_json_is_ignored_and_not_published(self):
        self.status({"tun": {"dataplane": {"tx": 5, "bindings": 1}, "mesh": {"fwd": 2}}})
        r = self.run_nodes({"MOCK_SSH_EXTRA": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        j = self.node_json(r)
        self.assertTrue(j["ok"])
        self.assertNotIn("sudo", r.stdout)
        self.assertNotIn("node-1", r.stdout)

    def test_ssh_error_publishes_no_address(self):
        r = self.run_nodes({"MOCK_SSH_MODE": "error"})
        self.assertNotEqual(r.returncode, 0, r.stdout)
        j = self.node_json(r)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"], "ssh-failed")
        self.assertNotIn("10.1.2.3", r.stdout)
        self.assertNotIn("Connection", r.stdout)

    def test_unparsable_node_output_is_not_ok(self):
        r = self.run_nodes({"MOCK_SSH_MODE": "nojson"})
        self.assertNotEqual(r.returncode, 0, r.stdout)
        j = self.node_json(r)
        self.assertFalse(j["ok"])
        self.assertEqual(j["error"], "no-json")


class LiveCheckUsage(Base):
    def test_nodes_without_value_is_usage_error(self):
        r = self.run_script(LIVE, "--nodes")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_both_only_flags_is_usage_error(self):
        r = self.run_script(LIVE, "--phones-only", "--nodes-only")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
