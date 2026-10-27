"""host-acl.json в push-remote.sh и node-hostpolicy.sh: локально, без root и без узлов (systemctl подменён)."""
import getpass
import grp
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ACL = {"version": 1, "aliases": [], "allow": []}
ME = f"{getpass.getuser()}:{grp.getgrgid(os.getgid()).gr_name}"


def acl_block() -> str:
    src = (HERE / "push-remote.sh").read_text()
    return src[src.index("# --- host-acl-begin"):src.index("# --- host-acl-end")]


def fake_systemctl(bindir: Path, exec_start: str = "", user: str = "", group: str = "") -> None:
    bindir.mkdir(exist_ok=True)
    tool = bindir / "systemctl"
    tool.write_text("#!/bin/sh\necho \"$*\" >> \"$SYSTEMCTL_LOG\"\ncase \"$*\" in\n"
                    f"  *ExecStart*) printf '%s\\n' '{exec_start}' ;;\n"
                    f"  *' User'*) printf '%s\\n' '{user}' ;;\n"
                    f"  *' Group'*) printf '%s\\n' '{group}' ;;\nesac\n")
    tool.chmod(0o755)


class HostAclTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.acl = self.state / "host-acl.json"
        self.bin = self.root / "bin"
        self.log = self.root / "systemctl.log"

    def tearDown(self):
        self._td.cleanup()

    def bash(self, body: str, **systemctl):
        fake_systemctl(self.bin, **systemctl)
        script = f"UNIT=knothopd HOST_ACL=null HOST_ACL_ERR=\n{acl_block()}\n{body}"
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "SYSTEMCTL_LOG": str(self.log)}
        return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30)

    def ensure(self, state=None):
        r = self.bash(f'ensure_host_acl "{state or self.state}" "{ME}"; rc=$?; echo "rc=$rc ACL=$HOST_ACL ERR=$HOST_ACL_ERR"')
        return r.stdout.strip(), r

    def test_created_atomically_with_default_content_and_private_mode(self):
        out, r = self.ensure()
        self.assertIn("rc=0 ACL=created", out, r.stderr)
        self.assertEqual(json.loads(self.acl.read_text()), DEFAULT_ACL)
        self.assertEqual(stat.S_IMODE(self.acl.stat().st_mode), 0o600)
        self.assertEqual(self.acl.stat().st_uid, os.getuid())
        self.assertEqual([p.name for p in self.state.iterdir()], ["host-acl.json"], "temp не остался")

    def test_second_run_is_present_and_never_rewrites(self):
        self.assertIn("ACL=created", self.ensure()[0])
        self.acl.write_text('{"version":1,"aliases":["8.8.8.8"],"allow":[]}\n')
        self.acl.chmod(0o600)
        before = (self.acl.read_bytes(), self.acl.stat().st_ino)
        out, _ = self.ensure()
        self.assertIn("rc=0 ACL=present", out)
        self.assertEqual((self.acl.read_bytes(), self.acl.stat().st_ino), before)

    def test_symlink_is_refused_and_target_untouched(self):
        target = self.root / "target"
        target.write_text("keep")
        self.acl.symlink_to(target)
        out, _ = self.ensure()
        self.assertIn("rc=1 ACL=refused", out)
        self.assertEqual(target.read_text(), "keep")
        self.assertTrue(self.acl.is_symlink())

    def test_dangling_symlink_is_refused_and_not_followed(self):
        target = self.root / "missing"
        self.acl.symlink_to(target)
        out, _ = self.ensure()
        self.assertIn("rc=1 ACL=refused", out)
        self.assertFalse(target.exists())

    def test_non_regular_file_is_refused(self):
        self.acl.mkdir()
        out, _ = self.ensure()
        self.assertIn("rc=1 ACL=refused", out)
        self.assertTrue(self.acl.is_dir())

    def test_unusable_existing_file_is_refused_without_change(self):
        self.acl.write_text("x")
        self.acl.chmod(0o644)
        out, _ = self.ensure()
        self.assertIn("rc=1 ACL=refused", out)
        self.assertEqual((self.acl.read_text(), stat.S_IMODE(self.acl.stat().st_mode)), ("x", 0o644))
        self.acl.chmod(0o600)
        self.acl.write_bytes(b"x" * 16385)
        self.assertIn("rc=1 ACL=refused", self.ensure()[0])

    def test_symlinked_or_missing_state_dir_is_refused(self):
        link = self.root / "state-link"
        link.symlink_to(self.state)
        self.assertIn("rc=1 ACL=refused", self.ensure(link)[0])
        self.assertFalse(self.acl.exists())
        self.assertIn("rc=1 ACL=refused", self.ensure(self.root / "nope")[0])

    def test_state_dir_comes_from_execstart_with_safe_default(self):
        def state_dir(exec_start):
            r = self.bash("host_acl_state_dir; echo \"rc=$?\"", exec_start=exec_start)
            return r.stdout.strip()
        unit = "{ path=/opt/knothop/knothopd ; argv[]=/opt/knothop/knothopd node --state %s --config /opt/knothop/node.json ; ignore_errors=no ; }"
        self.assertEqual(state_dir(unit % "/srv/kh/state"), "/srv/kh/staterc=0")
        self.assertEqual(state_dir("{ argv[]=/x node --state=/srv/eq ; }"), "/srv/eqrc=0")
        self.assertEqual(state_dir(""), "/opt/knothop/staterc=0")
        for bad in ("/a/../b", "rel/state", "/a;b", "$(id)"):
            with self.subTest(bad=bad):
                self.assertEqual(state_dir(unit % bad), "rc=1")

    def test_owner_is_service_user_not_hardcoded_root(self):
        def owner(user, group):
            return self.bash("host_acl_owner; echo \"rc=$?\"", user=user, group=group).stdout.strip()
        self.assertEqual(owner("knothopd", "knothopd"), "knothopd:knothopdrc=0")
        self.assertEqual(owner("", ""), "root:rootrc=0")
        self.assertEqual(owner("a;b", "x"), "rc=1")
        self.assertEqual(owner("knothopd", "$(id)"), "rc=1")

    def test_default_content_matches_loader_schema(self):
        self.assertIn("HOST_ACL_DEFAULT='{\"version\":1,\"aliases\":[],\"allow\":[]}'", acl_block())
        loader = (HERE.parent / "bench/rns-iroh-node/src/host_acl.rs").read_text()
        self.assertIn("config.version != 1", loader)


class HostNftTemplateTests(unittest.TestCase):
    def test_host_access_input_is_tcp_exact_source_and_destination_only(self):
        template = (HERE.parent / "deploy-0013/knothop.nft").read_text()
        input_chain = template.split("chain input {", 1)[1].split("chain forward {", 1)[0]
        host_rule = next(line for line in input_chain.splitlines() if 'comment "client->host-access-tcp"' in line)
        for field in ('iifname "khd0"', 'ip saddr @host_access_v4',
                      'ip daddr @host_access_dest_v4', 'meta l4proto tcp', 'counter accept'):
            self.assertIn(field, host_rule)
        self.assertLess(input_chain.index("client->host-access-tcp"), input_chain.index('comment "client->node"'))
        self.assertIn('iifname "khd0" meta l4proto icmp counter accept', input_chain)
        self.assertNotIn("ct state", input_chain, "established flows must not bypass revocation")
        for name in ("host_access_v4", "host_access_dest_v4"):
            body = template.split(f"set {name} {{", 1)[1].split("}", 1)[0]
            for text in ("type ipv4_addr", "flags timeout", "timeout 3s", "size 256"):
                self.assertIn(text, body)
            self.assertNotIn("elements", body, "no persistent grants")
        forward = template.split("chain forward {", 1)[1].split("chain output {", 1)[0]
        self.assertNotIn("host_access", forward)
        for mark in ("client->own-endpoint-local", "client->own-endpoint-v4", "client->own-endpoint-v6",
                     "client->internal", "client-ipv6", "carrier-loop-guard", "knothop-user-no-tunnel"):
            self.assertIn(f'comment "{mark}"', template)

    def test_hostfix_checks_leased_sets_and_preserves_existing_reapply_path(self):
        helper = (HERE / "node-hostfix.sh").read_text()
        verified = helper.split("nft_verified() {", 1)[1].split("nft_swap()", 1)[0]
        for name in ("host_access_v4", "host_access_dest_v4"):
            self.assertIn(f"nft list set inet knothop {name}", verified)
        self.assertIn("timeout 3s", verified)
        self.assertIn('"client->host-access-tcp"', helper)
        self.assertIn("PartOf=nftables.service", helper)
        self.assertIn("ReloadPropagatedFrom=nftables.service", helper)
        self.assertIn("ExecReload=/usr/local/sbin/knothop-hostfix apply", helper)
        self.assertNotIn("flush set inet knothop host_access", helper,
                         "hostfix apply must not race the daemon by republishing dynamic grants")


class HostPolicyTests(unittest.TestCase):
    ROOT_A = "aabbccddeeff00112233445566778899"

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.policy = self.state / "host-policy.json"
        self.log = self.root / "systemctl.log"
        fake_systemctl(self.root / "bin",
                       exec_start=f"{{ argv[]=/x node --state {self.state} --config /c ; }}",
                       user=getpass.getuser(), group=grp.getgrgid(os.getgid()).gr_name)

    def tearDown(self):
        self._td.cleanup()

    def run_helper(self, *args):
        env = {"PATH": f"{self.root / 'bin'}:/usr/bin:/bin", "SYSTEMCTL_LOG": str(self.log)}
        return subprocess.run(["bash", str(HERE / "node-hostpolicy.sh"), *args], env=env, capture_output=True,
                              text=True, timeout=30)

    def doc(self):
        return json.loads(self.policy.read_text())

    def test_show_without_file_changes_nothing(self):
        r = self.run_helper("show")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no host-policy.json", r.stdout)
        self.assertFalse(self.policy.exists())

    def test_add_root_writes_loader_format_private_atomic_and_never_restarts(self):
        r = self.run_helper("add-root", self.ROOT_A.upper(), "8")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.doc(), {"v": 1, "roots": [{"root": self.ROOT_A, "max_holders": 8}]})
        self.assertEqual(stat.S_IMODE(self.policy.stat().st_mode), 0o600)
        self.assertEqual(self.policy.stat().st_uid, os.getuid())
        self.assertEqual([p.name for p in self.state.iterdir()], ["host-policy.json"])
        self.assertIn("did NOT restart", r.stdout)
        self.assertNotIn("restart", self.log.read_text(), "служба не перезапускается")
        shown = self.run_helper("show")
        self.assertIn(self.ROOT_A, shown.stdout)
        self.assertIn("max_holders=8", shown.stdout)

    def test_add_root_is_idempotent_and_updates_max_holders(self):
        self.run_helper("add-root", self.ROOT_A, "8")
        inode = self.policy.stat().st_ino
        same = self.run_helper("add-root", self.ROOT_A, "8")
        self.assertIn("unchanged", same.stdout)
        self.assertEqual(self.policy.stat().st_ino, inode)
        self.run_helper("add-root", self.ROOT_A, "16")
        self.assertEqual(self.doc()["roots"], [{"root": self.ROOT_A, "max_holders": 16}])
        self.run_helper("add-root", "11" * 16)  # без max_holders: по умолчанию 64, как в загрузчике
        self.assertEqual(self.doc()["roots"][1], {"root": "11" * 16, "max_holders": 64})

    def test_argument_limits_follow_loader(self):
        for args in (("add-root", "zz"), ("add-root", "ab" * 15), ("add-root", self.ROOT_A, "0"),
                     ("add-root", self.ROOT_A, "513"), ("add-root", self.ROOT_A, "x"), ("add-root",), ("wipe",), ()):
            with self.subTest(args=args):
                self.assertEqual(self.run_helper(*args).returncode, 64)
        self.assertFalse(self.policy.exists())
        self.assertEqual(self.run_helper("add-root", self.ROOT_A, "512").returncode, 0)

    def test_ninth_root_is_refused(self):
        for i in range(8):
            self.assertEqual(self.run_helper("add-root", f"{i:02x}" * 16, "4").returncode, 0)
        before = self.policy.read_bytes()
        r = self.run_helper("add-root", "ff" * 16, "4")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.policy.read_bytes(), before)

    def test_symlink_and_invalid_existing_files_are_refused_unchanged(self):
        target = self.root / "target"
        target.write_text("keep")
        self.policy.symlink_to(target)
        self.assertEqual(self.run_helper("add-root", self.ROOT_A, "8").returncode, 1)
        self.assertEqual(self.run_helper("show").returncode, 1)
        self.assertEqual(target.read_text(), "keep")
        self.policy.unlink()
        for bad in ("not json", '{"v":2,"roots":[]}', '{"v":true,"roots":[]}', '{"v":1}',
                    '{"v":1,"roots":[{"root":"zz"}]}', '{"v":1,"roots":[{"root":"%s","max_holders":0}]}' % self.ROOT_A):
            with self.subTest(bad=bad):
                self.policy.write_text(bad)
                r = self.run_helper("add-root", "11" * 16, "4")
                self.assertEqual(r.returncode, 1)
                self.assertEqual(self.policy.read_text(), bad)

    def test_state_directory_symlink_is_refused(self):
        link = self.root / "state-link"
        link.symlink_to(self.state)
        fake_systemctl(self.root / "bin", exec_start=f"{{ argv[]=/x node --state {link} ; }}",
                       user=getpass.getuser(), group=grp.getgrgid(os.getgid()).gr_name)
        self.assertEqual(self.run_helper("add-root", self.ROOT_A, "8").returncode, 1)
        self.assertFalse(self.policy.exists())


if __name__ == "__main__":
    unittest.main()
