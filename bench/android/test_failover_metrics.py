import unittest
from failover_metrics import ping_window


class FailoverMetricsTests(unittest.TestCase):
    def test_recovery_is_time_from_unblock_not_normal_ping_interval(self):
        text = "[100.0] reply icmp_seq=1\n[105.6] reply icmp_seq=57\n[105.7] reply icmp_seq=58\n"
        result = ping_window(text, 105, 106)
        self.assertAlmostEqual(result["first_reply_after_s"], 0.6)
        self.assertAlmostEqual(result["worst_observed_gap_s"], 0.6)

    def test_no_reply_is_censored_not_zero_loss_success(self):
        result = ping_window("[99.0] reply icmp_seq=1\n", 100, 108)
        self.assertIsNone(result["first_reply_after_s"])
        self.assertIsNone(result["missing_between_window_replies"])
        self.assertEqual(result["worst_observed_gap_s"], 8)

    def test_window_does_not_reuse_whole_run_loss_counts(self):
        text = "[10.0] reply icmp_seq=1\n[12.0] reply icmp_seq=21\n[12.1] reply icmp_seq=22\n"
        result = ping_window(text, 12, 13)
        self.assertEqual(result["window_replies"], 2)
        self.assertEqual(result["missing_between_window_replies"], 0)
        self.assertEqual(result["censored_tail_s"], 0.9)


if __name__ == "__main__":
    unittest.main()
