import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("sanitize_public.py")
SPEC = importlib.util.spec_from_file_location("sanitize_public", SCRIPT)
sanitize_public = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sanitize_public)


class SanitizerPreservationTests(unittest.TestCase):
    def test_only_explicit_inventory_tokens_change_in_code(self):
        inventory_ip = ".".join(("203", "0", "113", "77"))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "deploy").mkdir()
            (root / "docs").mkdir()
            (root / "deploy" / "hosts.tsv").write_text(
                f"synthetic\tdeploy@{inventory_ip}:2222\n", encoding="utf-8"
            )
            (root / "deploy" / "public-rns-whitelist.txt").write_text("", encoding="utf-8")
            (root / "docs" / "experiments-log.md").write_text("", encoding="utf-8")

            source = (
                'const CLOUDFLARE = "1.1.1.1";\n'
                'const GOOGLE = "8.8.8.8";\n'
                'const BENCH = "198.18.0.0/15";\n'
                'const INTERNAL = "10.99.0.1";\n'
                'const OPTION = "--es";\n'
                'let us_state = "us";\n'
                f'const INVENTORY_IP = "{inventory_ip}";\n'
            )
            tokens = sanitize_public.collect_private_tokens(root)
            output = sanitize_public.sanitize_text(source, tokens, code=True)
            expected_ip = sanitize_public.replacement_for("ip", inventory_ip)
            expected = source.replace(f'"{inventory_ip}"', f'"{expected_ip}"')

            self.assertEqual(output, expected)
            self.assertIn('"1.1.1.1"', output)
            self.assertIn('"8.8.8.8"', output)
            self.assertIn('"198.18.0.0/15"', output)
            self.assertIn('"10.99.0.1"', output)
            self.assertIn('"--es"', output)
            self.assertIn('us_state', output)
            self.assertNotIn(f'"{inventory_ip}"', output)


if __name__ == "__main__":
    unittest.main()
