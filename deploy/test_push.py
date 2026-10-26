import importlib.util
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("push", Path(__file__).with_name("push.py"))
push = importlib.util.module_from_spec(spec)
spec.loader.exec_module(push)

HERE = Path(__file__).resolve().parent
DIGEST = "a" * 64


def make_dist(root: Path, helper_listed: bool = True) -> Path:
    """Временный dist/ с файлами и SHA256SUMS, в формате build.sh."""
    dist = root / "dist"
    dist.mkdir()
    files = {"knothopd": b"knothopd-binary", "knothopd-u2204": b"knothopd-u2204-binary", "push-remote.sh": b"#!/bin/bash\n"}
    lines = []
    for name, data in files.items():
        (dist / name).write_bytes(data)
        if name != "push-remote.sh" or helper_listed:
            lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    (dist / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return dist


def pass_payload(digest, **overrides):
    payload = {"status": "pass", "rollback": "available", "installed_sha256": digest,
               "executable_sha256": digest, "previous_sha256": "b" * 64,
               "pid": 42, "restarts": 0, "mesh": 2, "ts": 1_800_000_000_000}
    payload.update(overrides)
    return payload


def completed(payload_line: str, rc: int = 0):
    return subprocess.CompletedProcess(["ssh"], rc, payload_line.encode(), b"")


class PushTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.dist = make_dist(self.root)
        self._patch = patch.object(push, "DIST", self.dist)
        self._patch.start()
        self.expected = push.load_expected()
        self.payloads = push.load_payloads(self.expected)

    def tearDown(self):
        self._patch.stop()
        self._td.cleanup()

    def test_allowlist_exact_and_variants(self):
        self.assertEqual(set(push.ALLOWLIST), {"es", "uae", "by", "ru1", "nl1", "de", "fin1", "us"})
        self.assertEqual(push.ALLOWLIST["de"][1], "knothopd-u2204")
        self.assertEqual(push.ALLOWLIST["nl1"][3], "de")
        self.assertEqual(push.ALLOWLIST["fin1"][3], "de")
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                push.main(["--nodes", "not-a-host"])

    def test_binary_selection_for_all_allowlisted_nodes(self):
        self.assertTrue(all(push.ALLOWLIST[n][1] == "knothopd" for n in push.ALLOWLIST if n != "de"))
        self.assertEqual([n for n, r in push.ALLOWLIST.items() if r[1] == "knothopd-u2204"], ["de"])

    def test_host_key_policy_and_pinned_inventory_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); inv = root / "inventory"; inv.mkdir(); ssh = root / ".ssh"; ssh.mkdir()
            identity = ssh / "id"; identity.touch()
            kh = ssh / "known_hosts"; kh.touch()
            (inv / "es.known_hosts").touch(); (inv / "us.known_hosts").touch(); (inv / "fin1.known_hosts").touch()
            targets = {f"KNOTHOP_SSH_TARGET_{node.upper()}": f"deploy@{node}.example.invalid" for node in push.ALLOWLIST}
            with patch.object(push, "IDENTITY", identity), patch.object(push, "KH", kh), patch.object(push, "INV", inv), \
                 patch.dict(push.os.environ, targets):
                for node in push.ALLOWLIST:
                    args = push.ssh_args(node)
                    self.assertIn("BatchMode=yes", args)
                    self.assertIn("StrictHostKeyChecking=yes", args)
                self.assertIn(f"UserKnownHostsFile={inv / 'us.known_hosts'}", push.ssh_args("us"))
                self.assertIn(f"UserKnownHostsFile={inv / 'es.known_hosts'}", push.ssh_args("es"))
                self.assertIn(f"UserKnownHostsFile={inv / 'fin1.known_hosts'}", push.ssh_args("fin1"))
                self.assertIn(f"UserKnownHostsFile={kh}", push.ssh_args("uae"))
                self.assertEqual(push.ssh_args("ru1")[-1], targets["KNOTHOP_SSH_TARGET_RU1"])
                self.assertIn("ProxyCommand=", " ".join(push.ssh_args("nl1")))

    def test_rollout_refuses_placeholder_targets_by_default(self):
        for node in push.ALLOWLIST:
            with self.subTest(node=node), patch.dict(push.os.environ, {}, clear=True):
                with self.assertRaisesRegex(push.RolloutError, "outside the repository"):
                    push.ssh_args(node)

    def test_dry_run_does_not_ssh(self):
        report = self.root / "report.json"
        with patch.object(push, "ssh_args", side_effect=AssertionError("SSH validation must not connect")):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(push.main(["--nodes", "es", "de", "--report", str(report)]), 0)
        data = json.loads(report.read_text())
        self.assertEqual(data["status"], "dry-run")
        self.assertEqual([r["variant"] for r in data["results"]], ["knothopd", "knothopd-u2204"])
        self.assertEqual(data["results"][0]["expected_sha256"], self.expected["knothopd"])

    def test_sums_are_read_once_and_changed_file_is_not_sent(self):
        # Файл, изменённый после проверки, не уходит: эталон из SUMS не пересчитывается из файла.
        (self.dist / "knothopd").write_bytes(b"tampered")
        calls = []
        with patch.object(push, "ssh_args", return_value=["ssh"]):
            with self.assertRaises(push.RolloutError) as caught:
                push.invoke("es", "knothopd", True, self.payloads, self.expected, runner=lambda *a, **k: calls.append(a))
        self.assertEqual(calls, [])
        self.assertEqual(caught.exception.row["status"], "failed")
        self.assertEqual(caught.exception.row["rollback"], "not-needed")

    def test_payload_mismatch_at_load_is_rejected(self):
        (self.dist / "knothopd-u2204").write_bytes(b"other")
        with self.assertRaises(push.RolloutError):
            push.load_payloads(self.expected)

    def test_push_remote_helper_must_be_in_sums(self):
        (self.root / "second").mkdir()
        make_dist(self.root / "second", helper_listed=False)
        with patch.object(push, "DIST", self.root / "second" / "dist"):
            with self.assertRaisesRegex(push.RolloutError, "lacks: push-remote.sh"):
                push.load_expected()

    def test_build_sh_ships_and_sums_helper(self):
        src = (HERE / "build.sh").read_text()
        self.assertRegex(src, r'cp .*"\$HERE/push-remote\.sh".* "\$DIST/"')
        match = re.search(r"sha256sum (.*?) > SHA256SUMS", src)
        self.assertIsNotNone(match)
        self.assertIn("push-remote.sh", match.group(1).split())

    def test_build_sh_ships_and_sums_hostpolicy_helper(self):
        src = (HERE / "build.sh").read_text()
        self.assertRegex(src, r'cp .*"\$HERE/node-hostpolicy\.sh".* "\$DIST/"')
        match = re.search(r"sha256sum (.*?) > SHA256SUMS", src)
        self.assertIn("node-hostpolicy.sh", match.group(1).split())

    def test_push_remote_ensures_host_acl_before_backup_and_replacement(self):
        src = (HERE / "push-remote.sh").read_text()
        call = src.index('ensure_host_acl "$acl_state" "$acl_owner"')
        self.assertLess(call, src.index('cp -p "$BIN" "$PREV"'))
        self.assertLess(call, src.index("REPLACEMENT_STARTED=1\n"))
        self.assertIn('"host_acl": None if sys.argv[15] == "null" else sys.argv[15]', src)
        # откат бинарника не должен трогать host-acl.json
        rollback = src[src.index("rollback_previous() {"):src.index("on_exit() {")]
        self.assertNotIn("host-acl", rollback)

    def test_failed_remote_result_reports_rollback_and_raises(self):
        def failed(*args, **kwargs):
            return completed('PUSH_RESULT {"status":"failed","rollback":"verified","detail":"health gate"}\n', 1)
        with patch.object(push, "ssh_args", return_value=["ssh", "target"]):
            with self.assertRaises(push.RolloutError) as caught:
                push.invoke("es", "knothopd", True, self.payloads, self.expected, runner=failed)
            self.assertEqual(caught.exception.row["rollback"], "verified")

    def test_strict_pass_accepts_valid_structured_result(self):
        seen = {}
        def success(cmd, **kwargs):
            seen.update(kwargs)
            return completed("PUSH_RESULT " + json.dumps(pass_payload(self.expected["knothopd"])) + "\n")
        with patch.object(push, "ssh_args", return_value=["ssh", "target"]):
            result = push.invoke("es", "knothopd", True, self.payloads, self.expected, runner=success)
        self.assertEqual(seen["timeout"], 300)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["pid"], 42)
        self.assertEqual(result["expected_sha256"], self.expected["knothopd"])

    def test_pass_with_bad_fields_is_unknown(self):
        good = self.expected["knothopd"]
        bad_cases = {
            "installed mismatch": pass_payload(good, installed_sha256="c" * 64),
            "executable mismatch": pass_payload(good, executable_sha256="c" * 64),
            "executable missing": pass_payload(good, executable_sha256=None),
            "restarts nonzero": pass_payload(good, restarts=1),
            "restarts string": pass_payload(good, restarts="0"),
            "restarts bool": pass_payload(good, restarts=False),
            "mesh zero": pass_payload(good, mesh=0),
            "mesh bool": pass_payload(good, mesh=True),
            "mesh missing": pass_payload(good, mesh=None),
            "pid string": pass_payload(good, pid="42"),
            "pid zero": pass_payload(good, pid=0),
            "pid missing": pass_payload(good, pid=None),
        }
        for label, payload in bad_cases.items():
            with self.subTest(label):
                def success(cmd, **kwargs):
                    return completed("PUSH_RESULT " + json.dumps(payload) + "\n")
                with patch.object(push, "ssh_args", return_value=["ssh", "target"]):
                    with self.assertRaises(push.RolloutError) as caught:
                        push.invoke("es", "knothopd", True, self.payloads, self.expected, runner=success)
                self.assertEqual(caught.exception.row["status"], "unknown")
                self.assertEqual(caught.exception.row["rollback"], "unknown")

    def test_malformed_and_non_pass_results_are_unknown(self):
        cases = {
            "malformed json": 'PUSH_RESULT {"status":"pass"',
            "non-object": "PUSH_RESULT [1,2]",
            "failed with rc0": 'PUSH_RESULT ' + json.dumps(pass_payload(self.expected["knothopd"], status="failed")),
            "no result line": "some output only",
        }
        for label, line in cases.items():
            with self.subTest(label):
                with patch.object(push, "ssh_args", return_value=["ssh", "target"]):
                    with self.assertRaises(push.RolloutError) as caught:
                        push.invoke("es", "knothopd", True, self.payloads, self.expected,
                                    runner=lambda cmd, **k: completed(line + "\n"))
                self.assertEqual(caught.exception.row["status"], "unknown")

    def test_timeout_is_unknown_and_uses_300s(self):
        seen = {}
        def timed_out(cmd, **kwargs):
            seen.update(kwargs)
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
        with patch.object(push, "ssh_args", return_value=["ssh", "target"]):
            with self.assertRaises(push.RolloutError) as caught:
                push.invoke("es", "knothopd", True, self.payloads, self.expected, runner=timed_out)
        self.assertEqual(seen["timeout"], 300)
        self.assertEqual(caught.exception.row["status"], "unknown")
        self.assertEqual(caught.exception.row["rollback"], "unknown")
        self.assertIn("not guaranteed", caught.exception.row["detail"])

    def test_remote_helper_gates_and_lock_order(self):
        source = (HERE / "push-remote.sh").read_text()
        self.assertLess(source.index("flock -n 9"), source.index("trap on_exit EXIT"))
        self.assertIn("trap 'DETAIL=received-SIGHUP", source)
        self.assertIn("0 <= age <= 10000", source)
        self.assertIn("n.get('c') in ('quic', 'tcp')", source)
        self.assertIn("BASE_TS BASE_MESH baseline_fresh", source)
        self.assertIn("baseline_fresh != 1", source)
        self.assertIn("$TS -ge $START_MS", source)
        self.assertIn("POSTSTART_RESTARTS=$(systemctl show", source)
        self.assertIn("POSTSTART_RESTARTS == 0", source)
        self.assertIn("$RESTARTS == \"$POSTSTART_RESTARTS\"", source)
        self.assertIn("streak >= 3", source)
        self.assertIn("$PID == \"$previous_pid\"", source)
        self.assertIn("healthy_streak=$streak", source)

    def test_node_install_shares_rollout_lock(self):
        self.assertIn('LOCK="$DIR/.knothop-push.lock"', (HERE / "push-remote.sh").read_text())
        install = (HERE / "node-install.sh").read_text()
        self.assertIn('exec 8>>"$DIR/.knothop-push.lock"', install)
        self.assertIn("flock -n 8", install)

    def test_canary_failure_prevents_other_hosts(self):
        calls = []
        def fake_invoke(node, *args, **kwargs):
            calls.append(node)
            raise push.RolloutError("canary failed")
        with patch.object(push, "ssh_args", return_value=["ssh"]), patch.object(push, "invoke", side_effect=fake_invoke):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(push.main(["--apply", "--nodes", "es", "uae", "--report", str(self.root / "r.json")]), 1)
        self.assertEqual(calls, ["es"])


class RolloutShellTests(unittest.TestCase):
    """rollout.sh проверяется на копии в отдельном каталоге: до ssh скрипт должен отклонить вход."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = Path(self._td.name)
        shutil.copy(HERE / "rollout.sh", self.dir / "rollout.sh")
        (self.dir / "dist").mkdir()
        (self.dir / "dist" / "SHA256SUMS").write_text(f"{DIGEST}  knothopd\n")
        self.hosts = self.dir / "hosts.tsv"

    def tearDown(self):
        self._td.cleanup()

    def run_rollout(self, *args, hosts_line=None):
        if hosts_line is not None:
            self.hosts.write_text(hosts_line + "\n")
        env = {"HOSTS_FILE": str(self.hosts), "PATH": "/usr/bin:/bin"}
        return subprocess.run(["bash", str(self.dir / "rollout.sh"), *args], env=env, capture_output=True,
                              text=True, timeout=30)

    def test_unknown_hostfix_action_is_rejected(self):
        r = self.run_rollout("hostfix", "wipe", "es", hosts_line="es\troot@127.0.0.1\tknothopd")
        self.assertEqual(r.returncode, 64, r.stdout + r.stderr)

    def test_unknown_variant_is_rejected(self):
        r = self.run_rollout("status", hosts_line="es\troot@127.0.0.1\tevil-binary")
        self.assertEqual(r.returncode, 1)
        self.assertIn("неизвестный вариант", r.stdout + r.stderr)

    def test_hostpolicy_arguments_are_validated_before_ssh(self):
        row = "es\troot@127.0.0.1\tknothopd"
        root = "ab" * 16
        for args in (("hostpolicy", "wipe", "es"), ("hostpolicy", "add-root", "zz", "8", "es"),
                     ("hostpolicy", "add-root", root, "0", "es"), ("hostpolicy", "add-root", root, "513", "es"),
                     ("hostpolicy", "add-root", root, "8"), ("hostpolicy", "add-root", root, "8;id", "es")):
            with self.subTest(args=args):
                r = self.run_rollout(*args, hosts_line=row)
                self.assertEqual(r.returncode, 64, r.stdout + r.stderr)

    def test_hostpolicy_script_must_match_sums_before_ssh(self):
        row = "es\troot@127.0.0.1\tknothopd"
        r = self.run_rollout("hostpolicy", "show", "es", hosts_line=row)  # в SUMS нет node-hostpolicy.sh
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("node-hostpolicy.sh", r.stdout + r.stderr)
        data = (HERE / "node-hostpolicy.sh").read_bytes()
        (self.dir / "dist" / "node-hostpolicy.sh").write_bytes(data + b"# tampered\n")
        (self.dir / "dist" / "SHA256SUMS").write_text(
            f"{DIGEST}  knothopd\n{hashlib.sha256(data).hexdigest()}  node-hostpolicy.sh\n")
        r = self.run_rollout("hostpolicy", "show", "es", hosts_line=row)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("не совпадает", r.stdout + r.stderr)

    def test_host_key_override_in_options_is_rejected(self):
        for opts in ("-o UserKnownHostsFile=/dev/null", "-o StrictHostKeyChecking=no", "-oUserKnownHostsFile=/dev/null", "-o GlobalKnownHostsFile=/tmp/x"):
            with self.subTest(opts):
                r = self.run_rollout("status", hosts_line=f"es\troot@127.0.0.1\tknothopd\t{opts}")
                self.assertEqual(r.returncode, 1)
                self.assertIn("нельзя переопределять", r.stdout + r.stderr)


FAKE_TOOLS = {
    "stat": 'echo "0:600"\n',
    "mktemp": 'exec /usr/bin/mktemp "$TMPDIR/hostfix.XXXXXX"\n',
    "iptables": 'echo "iptables $*" >> "$LOG"\ncase "$1" in\n  -S) [ -n "$2" ] && echo "-P $2 DROP" ;;\n  -C) exit 1 ;;\nesac\nexit 0\n',
    "nft": 'echo "nft $*" >> "$LOG"\ncase "$*" in\n  "list table"*) [ "$NFT_OK" = 1 ] || exit 1; echo "client->node client->internal client-ipv6 client->own-endpoint carrier-loop-guard knothop-user-no-tunnel masquerade" ;;\n  "list set"*) [ "$NFT_OK" = 1 ] ;;\n  "-c -f "*|"-f "*) [ "$NFT_OK" = 1 ] ;;\n  *) exit 1 ;;\nesac\nexit 0\n',
    "sysctl": "echo 1\n",
    "ss": "exit 0\n",
}


class HostfixFakeToolsTests(unittest.TestCase):
    """node-hostfix.sh apply с подменёнными nft/iptables: iptables не трогается, пока nft не проверен."""

    def run_apply(self, nft_ok: bool, endpoint_content="8.8.8.8\n"):
        with tempfile.TemporaryDirectory() as td:
            bindir = Path(td) / "bin"
            bindir.mkdir()
            endpoints = Path(td) / "own-endpoints.conf"
            if endpoint_content is not None:
                endpoints.write_text(endpoint_content)
                endpoints.chmod(0o600)
            for name, body in FAKE_TOOLS.items():
                tool = bindir / name
                tool.write_text("#!/bin/sh\n" + body)
                tool.chmod(0o755)
            log = Path(td) / "calls.log"
            env = {"PATH": f"{bindir}:/usr/bin:/bin", "LOG": str(log), "NFT_OK": "1" if nft_ok else "0",
                   "KNOTHOP_OWN_ENDPOINTS": str(endpoints), "TMPDIR": td}
            r = subprocess.run(["bash", str(HERE / "node-hostfix.sh"), "apply"], env=env, capture_output=True,
                               text=True, timeout=60)
            calls = log.read_text() if log.exists() else ""
        return r, calls

    def test_nft_failure_opens_nothing(self):
        r, calls = self.run_apply(nft_ok=False)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAIL", r.stdout)
        self.assertNotIn("iptables -I", calls)

    def test_invalid_own_endpoint_inventory_fails_before_firewall_changes(self):
        for value in (None, "10.0.0.1\n", "https://invalid.example/\n"):
            with self.subTest(value=value):
                r, calls = self.run_apply(nft_ok=True, endpoint_content=value)
                self.assertEqual(r.returncode, 1)
                self.assertIn("inventory", r.stdout)
                self.assertNotIn("nft -f", calls)
                self.assertNotIn("iptables -I", calls)

    def test_verified_nft_then_iptables_accept(self):
        r, calls = self.run_apply(nft_ok=True)
        self.assertIn("iptables -I INPUT", calls)
        self.assertIn("iptables -I FORWARD", calls)
        self.assertLess(calls.index("nft list table"), calls.index("iptables -I"))
        self.assertIn("nft -c -f", calls)
        self.assertIn("nft -f", calls)
        self.assertLess(calls.index("nft -f"), calls.index("iptables -I"))


class StaticDeployChecks(unittest.TestCase):
    def test_hostfix_applies_nft_before_iptables_and_disables_persist(self):
        src = (HERE / "node-hostfix.sh").read_text()
        apply_body = src[src.index("do_apply() {"):src.index("do_revert() {")]
        self.assertLess(apply_body.index("nft_verified ||"), apply_body.index("if need_input; then"))
        self.assertLess(apply_body.index("nft_verified ||"), apply_body.index("if need_forward; then"))
        revert_body = src[src.index("do_revert() {"):src.index("do_persist() {")]
        self.assertIn("systemctl disable knothop-hostfix.service", revert_body)
        self.assertLess(revert_body.index("systemctl disable"), revert_body.index("iptables -D"))

    def test_nft_has_loop_guard_for_knothopd_user_and_ipv6_drop(self):
        nft = (HERE.parent / "deploy-0013" / "knothop.nft").read_text()
        self.assertIn('meta skuid "knothopd" ip daddr 198.18.0.0/15', nft)
        self.assertIn('udp sport 47001 counter drop comment "carrier-loop-guard"', nft)
        self.assertIn('meta nfproto ipv6 iifname "khd0" counter drop', nft)

    def test_own_endpoint_rules_are_tun_scoped_and_precede_existing_forward_drops(self):
        nft = (HERE.parent / "deploy-0013" / "knothop.nft").read_text()
        forward = nft[nft.index("chain forward {"):nft.index("chain output {")]
        rules = [line.strip() for line in forward.splitlines() if "client->own-endpoint" in line]
        self.assertEqual(len(rules), 3)
        self.assertTrue(all('iifname "khd0"' in line and "counter drop" in line for line in rules))
        self.assertIn("fib daddr type local", rules[0])
        self.assertIn("ip daddr @own_public_v4", rules[1])
        self.assertIn("ip6 daddr @own_public_v6", rules[2])
        self.assertLess(forward.index("client->own-endpoint"), forward.index("client->internal"))
        self.assertIn("set own_public_v4", nft)
        self.assertIn("set own_public_v6", nft)

    def test_trusted_endpoint_inventory_is_literal_global_ip_only(self):
        src = (HERE / "node-hostfix.sh").read_text()
        match = re.search(r"python3 - \"\$OWN_ENDPOINTS\" <<'PY'\n(.*?)\nPY", src, re.S)
        self.assertIsNotNone(match)
        validator = match.group(1)

        def run_inventory(contents):
            with tempfile.NamedTemporaryFile(mode="w", encoding="ascii") as f:
                f.write(contents)
                f.flush()
                return subprocess.run(["python3", "-", f.name], input=validator, text=True,
                                      capture_output=True, timeout=10)

        valid = run_inventory("# trusted test values\n8.8.8.8\n2001:4860:4860::8888\n")
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn("add element inet knothop own_public_v4", valid.stdout)
        self.assertIn("add element inet knothop own_public_v6", valid.stdout)
        for bad in ("", "localhost\n", "https://example.invalid/\n", "10.0.0.1\n",
                    "fe80::1\n", "8.8.8.8/32\n"):
            with self.subTest(bad=bad):
                result = run_inventory(bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_scripts_parse(self):
        for name in ("node-hostfix.sh", "node-hostpolicy.sh", "node-install.sh", "push-remote.sh", "rollout.sh", "build.sh"):
            with self.subTest(name):
                r = subprocess.run(["bash", "-n", str(HERE / name)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
