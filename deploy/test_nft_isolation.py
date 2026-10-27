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
cat > "$T/packets.py" <<'PY'
import socket, struct, time

def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def tcp_header(src, dst, v6=False, port=22):
    tcp = struct.pack("!HHLLBBHHH", 40000, port, 1, 0, 5 << 4, 2, 4096, 0, 0)
    if v6:
        pseudo = socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
        pseudo += struct.pack("!I3xB", len(tcp), 6)
    else:
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    return tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]

def send4(dst, src="198.18.0.2", port=22, proto=6):
    tcp = tcp_header(src, dst, port=port) if proto == 6 else struct.pack("!HHHH", 40000, port, 8, 0)
    srcb, dstb = socket.inet_aton(src), socket.inet_aton(dst)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x1234, 0, 64, proto, 0, srcb, dstb)
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

if __name__ == "__main__":
    send4("8.8.8.8")                 # configured external-NAT endpoint: drop
    send4("1.1.1.1")                 # unrelated public destination: forward
    send4("203.0.113.10")            # locally assigned endpoint: input drop
    send6("2001:4860:4860::8888")    # configured own IPv6 endpoint: drop
    send6("2001:4860:4860::8844")    # other IPv6: unsupported-client drop
    time.sleep(0.15)
PY
python3 "$T/packets.py"
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
# Exercise kernel INPUT decisions with raw packets, not just string matching.
# A later chain witnesses that our accept passed a packet through; unrelated
# host policy can still impose stricter restrictions (as on a real node).
import sys, time
sys.path.insert(0, base)
from packets import send4

def nft(script):
    subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True, capture_output=True)

def count(chain, comment):
    text = subprocess.check_output(["nft", "list", "chain", "inet", "knothop", chain], text=True)
    return packets(comment, text)

nft('add chain inet knothop witness { type filter hook input priority 0; policy accept; }\n'
    'add rule inet knothop witness iifname "khd0" meta l4proto tcp counter comment "witness-tcp"\n')
clear = "flush set inet knothop host_access_v4\nflush set inet knothop host_access_dest_v4\n"
grant = clear + ("add element inet knothop host_access_v4 { 198.18.0.2 timeout 3s }\n"
                 "add element inet knothop host_access_dest_v4 { 203.0.113.10 timeout 3s }\n")

def probe(accepted, *, src="198.18.0.2", dst="203.0.113.10", proto=6, port=22):
    before = count("witness", "witness-tcp")
    allow = count("input", "client->host-access-tcp")
    deny = count("input", "client->node")
    send4(dst, src, port=port, proto=proto)
    time.sleep(0.03)
    assert count("input", "client->host-access-tcp") - allow == int(accepted)
    assert count("input", "client->node") - deny == int(not accepted)
    assert count("witness", "witness-tcp") - before == int(accepted)

probe(False)                         # no grant
nft(grant)
probe(True)                          # scoped holder, exact destination
probe(True, port=443)                # current host-acl model has no port filter
probe(False, src="198.18.0.3")      # another admitted client has no grant
probe(False, dst="198.18.0.1")      # local private/service address not allowed
probe(False, proto=17)               # UDP is not opened by this rule
nft(clear)
probe(False)                         # revoke/disconnect, including same tuple
nft(grant)
time.sleep(3.1)
probe(False)                         # stalled/dead daemon: kernel lease expiry
nft(grant)
# Atomic batch rejection must not partly publish a new policy.
bad = subprocess.run(["nft", "-f", "-"], input=clear + "add element inet knothop missing_set { 198.18.0.3 }\n",
                     text=True, capture_output=True)
assert bad.returncode != 0
probe(True)
nft(clear)                           # controller's fail-closed fallback
probe(False)
# Replacing the table (hostfix reload/restart path) starts with empty sets.
nft(grant)
print(json.dumps({"host_access_grant_revoke_expiry": True, "host_access_scope_and_protocol": True,
                  "host_access_atomic_failure": True}))
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
# Reapply the persisted template atomically, without retaining dynamic grants.
{ printf 'delete table inet knothop\ndelete table ip knothop_nat\n'; cat "$1"; } > "$T/reload.nft"
nft -c -f "$T/reload.nft"
nft -f "$T/reload.nft"
python3 - <<'PY'
import json, subprocess
for name in ("host_access_v4", "host_access_dest_v4"):
    doc = json.loads(subprocess.check_output(["nft", "-j", "list", "set", "inet", "knothop", name], text=True))
    entry = next(obj["set"] for obj in doc["nftables"] if "set" in obj)
    assert not entry.get("elem")
print(json.dumps({"host_access_reload_empty": True}))
PY
if [ "${KNOTHOP_MEASURE_NFT_OVERHEAD:-0}" = 1 ]; then
python3 - <<'PY'
import json, os, re, resource, socket, statistics, struct, subprocess, sys, time
sys.path.insert(0, os.environ["KNOTHOP_NS_TMP"])
from packets import checksum, tcp_header

def nft(script):
    subprocess.run(["nft", "-f", "-"], input=script, text=True, capture_output=True, check=True)

rule = ('iifname "khd0" ip saddr @host_access_v4 ip daddr @host_access_dest_v4 '
        'meta l4proto tcp counter accept comment "client->host-access-tcp"')
text = subprocess.check_output(["nft", "-a", "list", "chain", "inet", "knothop", "input"], text=True)
handle = re.search(r'comment "client->host-access-tcp".*# handle (\d+)', text).group(1)
nft(f"delete rule inet knothop input handle {handle}\n")
src, dst = "198.18.0.2", "203.0.113.10"
tcp = tcp_header(src, dst)
hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0x1234, 0, 64, 6, 0,
                  socket.inet_aton(src), socket.inet_aton(dst))
hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
frame = bytes.fromhex("0200000000010200000000020800") + hdr + tcp
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("client0", 0))
n = 10000
samples = {"before": [], "after": []}

def denied():
    text = subprocess.check_output(["nft", "list", "chain", "inet", "knothop", "input"], text=True)
    return int(re.search(r'counter packets (\d+).*comment "client->node"', text).group(1))

for round in range(6):
    for mode in (("before", "after") if round % 2 == 0 else ("after", "before")):
        text = subprocess.check_output(["nft", "-a", "list", "chain", "inet", "knothop", "input"], text=True)
        match = re.search(r'comment "client->host-access-tcp".*# handle (\d+)', text)
        if match:
            nft("delete rule inet knothop input handle " + match.group(1) + "\n")
        if mode == "after":
            nft("insert rule inet knothop input " + rule + "\n")
        count = denied()
        wall, cpu = time.perf_counter(), time.process_time()
        for _ in range(n):
            s.send(frame)
        cpu, wall = time.process_time() - cpu, time.perf_counter() - wall
        time.sleep(0.03)
        observed = denied() - count
        assert observed == n, "namespace packet accounting lost packets"
        samples[mode].append({"wall_s": wall, "cpu_s": cpu, "pps": n / wall, "loss": n - observed})
s.close()
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
start = time.perf_counter()
for _ in range(20):
    nft("flush set inet knothop host_access_v4\nflush set inet knothop host_access_dest_v4\n")
elapsed = time.perf_counter() - start
end = resource.getrusage(resource.RUSAGE_CHILDREN)
result = {"host_access_overhead": {"samples": samples, "frames_per_sample": n,
          "frame_bytes": len(frame), "refresh_wall_ms": elapsed * 1000 / 20,
          "refresh_child_cpu_ms": ((end.ru_utime + end.ru_stime) - (usage.ru_utime + usage.ru_stime)) * 1000 / 20,
          "median_wall_delta_percent": (statistics.median(x["wall_s"] for x in samples["after"]) /
                                        statistics.median(x["wall_s"] for x in samples["before"]) - 1) * 100}}
print(json.dumps(result, sort_keys=True))
PY
fi
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
        self.assertIn('"host_access_grant_revoke_expiry": true', result.stdout)
        self.assertIn('"host_access_scope_and_protocol": true', result.stdout)
        self.assertIn('"host_access_atomic_failure": true', result.stdout)
        self.assertIn('"host_access_reload_empty": true', result.stdout)
        if os.environ.get("KNOTHOP_MEASURE_NFT_OVERHEAD") == "1":
            for line in result.stdout.splitlines():
                if '"host_access_overhead"' in line:
                    print(line)


if __name__ == "__main__":
    unittest.main()
