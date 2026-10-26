import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_lxmf_snapshot_e2e import unused_subnet


class SubnetSelectionTest(unittest.TestCase):
    def run_with(self, networks, routes):
        outputs = ["network1 network2\n", json.dumps(networks), json.dumps(routes)]
        with patch("run_lxmf_snapshot_e2e.subprocess.check_output", side_effect=outputs) as command:
            result = unused_subnet()
        self.assertEqual(command.call_count, 3)
        self.assertEqual(command.call_args_list[0].args[0], ["docker", "network", "ls", "-q"])
        self.assertEqual(command.call_args_list[1].args[0][:3], ["docker", "network", "inspect"])
        self.assertEqual(command.call_args_list[2].args[0][:3], ["ip", "-j", "route"])
        return result

    def test_host_and_none_networks_have_nullable_ipam_config(self):
        self.assertEqual(self.run_with([
            {"IPAM": {"Config": None}}, {"IPAM": None},
            {"IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]}},
        ], [{"dst": "default"}, {"dst": "127.0.0.0/8"}]), "172.29.102.0/24")

    def test_skips_both_docker_subnets_and_host_routes(self):
        self.assertEqual(self.run_with([
            {"IPAM": {"Config": [{"Subnet": "172.29.102.0/24"}, {"Subnet": "fd00::/64"}]}},
        ], [{"dst": "172.29.103.0/24"}, {"dst": "default"}]), "172.29.104.0/24")

    def test_no_candidate_is_not_a_reason_to_change_network_configuration(self):
        outputs = ["network1\n", json.dumps([{"IPAM": {"Config": [{"Subnet": "172.29.0.0/16"}]}}]), "[]"]
        with patch("run_lxmf_snapshot_e2e.subprocess.check_output", side_effect=outputs) as command:
            with self.assertRaisesRegex(RuntimeError, "no unused test subnet"):
                unused_subnet()
        self.assertEqual(command.call_count, 3)


if __name__ == "__main__":
    unittest.main()
