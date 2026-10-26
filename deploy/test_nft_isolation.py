"""Packet-level nft isolation checks confined to an unshared network namespace."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy-0013" / "knothop.nft"

NS_TEST = r'''set -eu
T=${KNOTHOP_NS_TMP:?}
nft -c -f "$1"
nft -f "$1"
ip link add khd0 type veth peer name client0
ip link set khd0 address 02:00:00:00:00:01
ip link set client0 address 02:00:00:00:00:02
ip addr add 198.18.0.1/24 dev khd0
ip -6 addr add 2001:db8::1/64 dev khd0
ip link set khd0 up
ip link set client0 up
ip link add wan0 type dummy
ip link set wan0 up
ip route add default dev wan0
ip -6 route add default dev wan0
ip addr add 203.0.113.10/32 dev lo
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
ip -s -j link show wan0 > "$T/wan-before.json"
python3 - <<'PY'
import socket, struct, time

def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def tcp_header(src, dst, v6=False):
    tcp = struct.pack("!HHLLBBHHH", 40000, 22, 1, 0, 5 << 4, 2, 4096, 0, 0)
    if v6:
        pseudo = socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
        pseudo += struct.pack("!I3xB", len(tcp), 6)
    else:
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    return tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]

def send4(dst):
    src = "198.18.0.2"
    tcp = tcp_header(src, dst)
    srcb, dstb = socket.inet_aton(src), socket.inet_aton(dst)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0x1234, 0, 64, 6, 0, srcb, dstb)
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    frame = bytes.fromhex("0200000000010200000000020800") + hdr + tcp
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("client0", 0)); s.send(frame); s.close()

def send6(dst):
    src = "2001:db8::2"
    tcp = tcp_header(src, dst, True)
    hdr = struct.pack("!IHBB16s16s", 6 << 28, len(tcp), 6, 64,
                      socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst))
    frame = bytes.fromhex("02000000000102000000000286dd") + hdr + tcp
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("client0", 0)); s.send(frame); s.close()

send4("8.8.8.8")                 # configured external-NAT endpoint: drop
send4("1.1.1.1")                 # unrelated public destination: forward
send4("203.0.113.10")            # locally assigned endpoint: input drop
send6("2001:4860:4860::8888")    # configured own IPv6 endpoint: drop
send6("2001:4860:4860::8844")    # other IPv6: unsupported-client drop
time.sleep(0.15)
PY
ip -s -j link show wan0 > "$T/wan.json"
nft -a list chain inet knothop forward > "$T/forward.txt"
nft -a list chain inet knothop input > "$T/input.txt"
python3 - <<'PY'
import json, re, subprocess
import os
base = os.environ["KNOTHOP_NS_TMP"]
forward = open(base + "/forward.txt").read()
input_chain = open(base + "/input.txt").read()
def packets(comment, text):
    match = re.search(r'counter packets (\d+).*comment "' + re.escape(comment) + '"', text)
    return int(match.group(1)) if match else -1
wan = json.load(open(base + "/wan.json"))[0]["stats64"]["tx"]["packets"] - \
      json.load(open(base + "/wan-before.json"))[0]["stats64"]["tx"]["packets"]
result = {
    "own_v4_drop": packets("client->own-endpoint-v4", forward),
    "own_v6_drop": packets("client->own-endpoint-v6", forward),
    "unsupported_v6_drop": packets("client-ipv6", forward),
    "local_input_drop": packets("client->node", input_chain),
    "ordinary_wan_tx": wan,
}
print(json.dumps(result, sort_keys=True))
assert result == {"own_v4_drop": 1, "own_v6_drop": 1, "unsupported_v6_drop": 1,
                  "local_input_drop": 1, "ordinary_wan_tx": 1}, result
handles = re.findall(r'comment "client->own-endpoint-[^"]+".*# handle (\d+)', forward)
assert len(handles) == 3, handles
for handle in handles:
    subprocess.run(["nft", "delete", "rule", "inet", "knothop", "forward", "handle", handle], check=True)
subprocess.run(["nft", "delete", "set", "inet", "knothop", "own_public_v4"], check=True)
subprocess.run(["nft", "delete", "set", "inet", "knothop", "own_public_v6"], check=True)
after = subprocess.check_output(["nft", "list", "chain", "inet", "knothop", "forward"], text=True)
assert "client->own-endpoint" not in after
assert "client->internal" in after and "client-ipv6" in after
print(json.dumps({"rollback_preserved_base": True}))
PY
'''


@unittest.skipUnless(all(shutil.which(x) for x in ("unshare", "nft", "ip")), "requires nft/ip/unshare")
class NftIsolationNamespaceTests(unittest.TestCase):
    def test_local_input_external_nat_and_forward_scopes(self):
        template = TEMPLATE.read_text().replace('meta skuid "knothopd"', "meta skuid 0")
        with tempfile.TemporaryDirectory(prefix="knothop-nft-ns-") as td:
            rules = Path(td) / "rules.nft"
            rules.write_text(template + "\nadd element inet knothop own_public_v4 { 8.8.8.8 }\n"
                             "add element inet knothop own_public_v6 { 2001:4860:4860::8888 }\n")
            env = {**os.environ, "KNOTHOP_NS_TMP": td}
            try:
                result = subprocess.run(["unshare", "-Urn", "bash", "-c", NS_TEST, "nft-isolation", str(rules)],
                                        capture_output=True, text=True, timeout=30, env=env)
            except subprocess.TimeoutExpired as e:
                self.fail(f"isolated nft test timed out: {e}")
        if result.returncode and "Operation not permitted" in result.stderr:
            self.skipTest("user network namespace lacks required capabilities")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"own_v4_drop": 1', result.stdout)
        self.assertIn('"own_v6_drop": 1', result.stdout)
        self.assertIn('"unsupported_v6_drop": 1', result.stdout)
        self.assertIn('"local_input_drop": 1', result.stdout)
        self.assertIn('"ordinary_wan_tx": 1', result.stdout)
        self.assertIn('"rollback_preserved_base": true', result.stdout)


if __name__ == "__main__":
    unittest.main()
