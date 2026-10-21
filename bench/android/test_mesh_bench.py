"""Чистый разбор лабораторных логов: без adb и сети."""
import unittest

from mesh_bench import parse_result_logs, find_current


class ParseTests(unittest.TestCase):
    def test_name_result_after_matching_queue(self):
        dest = "a" * 32
        logs = (f"1792400000.1 I rawgui: BENCH queued to={dest} mb=100\n"
                '1792400001.2 I rawgui: BENCH_RESULT {"to":"exit-test","verdict":"partial"}')
        self.assertEqual(parse_result_logs(logs, dest, 1792400000, "exit-test")["verdict"], "partial")
        self.assertIsNone(parse_result_logs(logs, dest, 1792400000, "different-exit"))
        self.assertIsNone(parse_result_logs(logs, dest, 1792400002, "exit-test"))

    def test_no_queue_or_wrong_queue_rejected(self):
        result = '1792400001.2 I rawgui: BENCH_RESULT {"to":"exit-test","verdict":"ok"}'
        self.assertIsNone(parse_result_logs(result, "a" * 32, 1792400000, "exit-test"))
        logs = f'1792400000.1 I rawgui: BENCH queued to={"b" * 32} mb=100\n' + result
        self.assertIsNone(parse_result_logs(logs, "a" * 32, 1792400000, "exit-test"))

    def test_already_current_status(self):
        self.assertEqual(find_current("I rawgui: STATUS состояние: up | выход: exit-test (aaaaaaaa)", "aaaaaaaa"), "exit-test")
        self.assertIsNone(find_current("I rawgui: STATUS состояние: idle | выход: exit-test (aaaaaaaa)", "aaaaaaaa"))


if __name__ == "__main__":
    unittest.main()
