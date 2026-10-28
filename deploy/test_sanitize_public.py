"""Тесты санитайзера публикационной копии: точечная замена, исключения, закрепление форка и аудит."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("sanitize_public", Path(__file__).with_name("sanitize_public.py"))
sp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sp)

BRAND = "big" + "ping"  # собрано из частей, чтобы сам тест не попадал под сканер
NODE_IP = "198.51.100.23"  # адрес документального диапазона: должен замениться на плейсхолдер
PIN = "ab" * 20


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_source(root: Path) -> None:
    write(root, "deploy/hosts.tsv", f"es\t{NODE_IP}\toperator@{NODE_IP}:2222\n")
    write(root, "deploy/node.py", f'NODE = "{NODE_IP}"  # узел\n')
    write(root, "docs/notes.md", f"Узел {BRAND} в тестовой сети\n")
    write(root, "deploy/leviculum.ref", PIN + "\n")
    write(root, "AGENTS.md", "внутренние инструкции\n")
    write(root, "state/trust.json", "{}\n")
    write(root, "LICENSE", "AGPL-3.0-or-later\n")


def make_fork(root: Path) -> str:
    root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    write(root, "leviculum-std/lib.rs", "pub fn f() {}\n")
    git = ["git", "-C", str(root), "-c", "user.name=test", "-c", "user.email=test@example.invalid"]
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "init"], check=True)
    return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


class SanitizeTests(unittest.TestCase):
    def test_async_invite_secrets_are_excluded_even_outside_named_state_dir(self):
        self.assertTrue(sp.should_exclude(Path("bench/custom-node/enroll-outbox/0123.json")))
        self.assertTrue(sp.should_exclude(Path("bench/custom-node/enroll-join.json")))
        self.assertFalse(sp.should_exclude(Path("bench/rns-iroh-node/src/enroll_net.rs")))

    def test_sanitize_replaces_tokens_and_excludes_private_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "src", Path(tmp) / "dst"
            make_source(src)
            sp.sanitize(src, dst, None)

            node = (dst / "deploy/node.py").read_text(encoding="utf-8")
            self.assertNotIn(NODE_IP, node)
            self.assertIn("203.0.113.", node)
            self.assertIn("KnotHop", (dst / "docs/notes.md").read_text(encoding="utf-8"))
            self.assertNotIn(BRAND, (dst / "docs/notes.md").read_text(encoding="utf-8"))
            self.assertFalse((dst / "deploy/hosts.tsv").exists())
            self.assertFalse((dst / "AGENTS.md").exists())
            self.assertFalse((dst / "state").exists())
            self.assertFalse((dst / "third_party").exists())
            self.assertEqual((dst / "deploy/leviculum.ref").read_text(encoding="utf-8").strip(), PIN)
            self.assertIn(PIN, (dst / "NOTICE-KNOTHOP.md").read_text(encoding="utf-8"))
            self.assertEqual(sp.scan(dst, src, None), 0)

    def test_audit_catches_change_outside_token_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "src", Path(tmp) / "dst"
            make_source(src)
            sp.sanitize(src, dst, None)
            tokens = sp.collect_private_tokens(src)
            # правка кода, не связанная с приватными значениями, должна попасть в аудит
            write(dst, "deploy/node.py", f'NODE = "1.1.1.1"  # узел\nEXTRA = 1\n')
            _, valid = sp.audit_tree(src, dst, tokens)
            self.assertFalse(valid)

    def test_fork_pin_must_match_head_and_tree_must_be_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            make_source(src)
            fork = Path(tmp) / "fork"
            head = make_fork(fork)

            write(src, "deploy/leviculum.ref", "0" * 40 + "\n")
            with self.assertRaises(SystemExit):
                sp.check_fork_pin(src, fork)

            write(src, "deploy/leviculum.ref", head + "\n")
            self.assertEqual(sp.check_fork_pin(src, fork), head)

            write(fork, "untracked.rs", "// незакоммиченная правка\n")
            with self.assertRaises(SystemExit):
                sp.check_fork_pin(src, fork)

    def test_fork_pin_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            write(src, "deploy/leviculum.ref", "короткий-ref\n")
            with self.assertRaises(SystemExit):
                sp.check_fork_pin(src, Path(tmp))


if __name__ == "__main__":
    unittest.main()
