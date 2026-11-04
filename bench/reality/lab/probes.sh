#!/usr/bin/env bash
# Зонды без ключа и сверка с сайтом-прикрытием. Запускать после up.sh. Результат в $L/results.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); L=${L:-$HOME/.cache/knothop-target/reality/lab}; mkdir -p $L/results; R=$L/results
EDGE=$(docker inspect -f '{{(index .NetworkSettings.Networks "rr").IPAddress}}' rr-traefik)
COVER=$(docker inspect -f '{{(index .NetworkSettings.Networks "rr").IPAddress}}' rr-cover)
dx() { docker exec rr-cli sh -c "$1"; }
fp() { dx "echo | openssl s_client -connect $1:443 -servername ${2:-cover.lab} -tls1_3 2>/dev/null | openssl x509 -noout -fingerprint -sha256" 2>&1; }
{
echo "== 1. сертификат: сайт напрямую / через Traefik (SNI cover.lab) =="
fp $COVER; fp $EDGE
echo "== 2. curl h2 через Traefik =="
dx "curl -sk --http2 --resolve cover.lab:443:$EDGE -w ' [http=%{http_version} code=%{http_code}]\n' https://cover.lab/" 2>&1
echo "== 3. curl напрямую =="
dx "curl -sk --http2 --resolve cover.lab:443:$COVER -w ' [http=%{http_version} code=%{http_code}]\n' https://cover.lab/" 2>&1
echo "== 4. другой SNI через Traefik (поведение Traefik KnotHop, не наше) =="
fp $EDGE other.lab
} | tee $R/probes-basic.txt

# запись трафика: легитимный туннель, затем зонды
dx "rm -f /tmp/a.pcap /tmp/b.pcap /tmp/c.pcap"
echo "== 5. запись: легитимный туннель =="
dx "tcpdump -i eth0 -w /tmp/a.pcap -U tcp port 443 >/dev/null 2>&1 & echo \$! > /tmp/tcpdump.pid"
sleep 1
ID=$(cat $L/server.id)
dx "/b/reality-poc cli --id $ID --via custom:127.0.0.1:9000 --cap 1400 --test rtt --secs 2 2>&1 | grep -E 'rtt:|connected'"
sleep 1; dx "kill \$(cat /tmp/tcpdump.pid); sleep 1"
docker cp rr-cli:/tmp/a.pcap $R/tunnel.pcap
echo "== 6. запись: зонды (openssl, curl) и повтор записанного ClientHello =="
dx "tcpdump -i eth0 -w /tmp/b.pcap -U tcp port 443 >/dev/null 2>&1 & echo \$! > /tmp/tcpdump.pid"
sleep 1
fp $EDGE >/dev/null
dx "curl -sk --http2 --resolve cover.lab:443:$EDGE https://cover.lab/ >/dev/null"
python3 $HERE/wire.py $R/tunnel.pcap 443 ch-hex 0 > $R/ch.hex
docker cp $R/ch.hex rr-cli:/tmp/ch.hex
dx "python3 - <<'PY'
import socket
ch = bytes.fromhex(open('/tmp/ch.hex').read().strip())
s = socket.create_connection(('$EDGE', 443)); s.sendall(ch); s.settimeout(3)
d = b''
try:
    while len(d) < 3000:
        x = s.recv(4096)
        if not x: break
        d += x
except Exception: pass
print('replay: received', len(d), 'bytes, first record type', d[0] if d else None)
PY"
sleep 1; dx "kill \$(cat /tmp/tcpdump.pid); sleep 1"
docker cp rr-cli:/tmp/b.pcap $R/probes.pcap
{
echo "== JA4 легитимного клиента (наш) =="; python3 $HERE/ja.py $R/tunnel.pcap 443 "reality-bridge (наш)" 2>&1 | head -4
echo "== TLS-записи: туннель =="; python3 $HERE/wire.py $R/tunnel.pcap 443
echo "== TLS-записи: зонды (openssl; curl; повтор ClientHello) =="; python3 $HERE/wire.py $R/probes.pcap 443
} | tee $R/wire.txt
echo "== лог сервера =="; docker exec rr-srv cat /tmp/bridge.log | tail -8
