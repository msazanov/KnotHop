#!/usr/bin/env bash
# Стенд knothop-reality в Docker (сеть rr): cover (nginx TLS1.3+h2, X25519MLKEM768), edge (Traefik v3.7.11: HostSNI passthrough + PROXY v2),
# srv (reality-bridge server за PROXY v2 + reality-poc srv), cli (reality-bridge client + reality-poc cli).
# Нужны: $B/reality-bridge (cargo build --release --features bin), $P/reality-poc (PoC iroh), образ rpoc-tools.
# Ключ сервера создаётся заново при каждом запуске, лежит в $L/key (0600), не печатается.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
B=${B:-$HOME/.cache/knothop-target/reality/release}
P=${P:-$HOME/.cache/knothop-target/reality-poc/bin}
L=${L:-$HOME/.cache/knothop-target/reality/lab}
mkdir -p $L/cover $L/tr $L/bin; cd $HERE
./down.sh >/dev/null 2>&1 || true
cp $B/reality-bridge $P/reality-poc $L/bin/
rm -f $L/key; PUB=$($L/bin/reality-bridge keygen --out $L/key)
[ -f $L/cover/c.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=cover.lab" -addext "subjectAltName=DNS:cover.lab" -keyout $L/cover/k.pem -out $L/cover/c.pem 2>/dev/null
cp nginx.conf $L/cover/nginx.conf; cp dyn.yml $L/tr/dyn.yml
SID=0123456789abcdef
docker network inspect rr >/dev/null 2>&1 || docker network create rr >/dev/null
docker run -d --name rr-cover --network rr --network-alias cover -v $L/cover:/c:ro nginx:1.31.4-alpine nginx -c /c/nginx.conf -g 'daemon off;' >/dev/null
docker run -d --name rr-traefik --network rr --network-alias edge -v $L/tr:/tr:ro traefik:v3.7.11 --log.level=INFO --providers.file.filename=/tr/dyn.yml --entrypoints.websecure.address=:443/tcp >/dev/null
sleep 2
EDGE_NET=$(docker network inspect rr -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
docker run -d --name rr-srv --network rr --network-alias srv --cap-add NET_ADMIN -v $L/bin:/b:ro -v $L/key:/k/key:ro rpoc-tools \
  sh -c "/b/reality-poc srv --carrier-listen 127.0.0.1:5201 --udp 4433 --cap \${CAP:-1400} --id-file /tmp/id 2>/tmp/srv.log & exec /b/reality-bridge server --listen 0.0.0.0:8444 --key-file /k/key --short-ids $SID --dest cover:443 --sni cover.lab --proxy-protocol --allow-proxy-on-public --proxy-trusted $EDGE_NET --target 127.0.0.1:5201 2>/tmp/bridge.log" >/dev/null
docker run -d --name rr-cli --network rr --cap-add NET_ADMIN -v $L/bin:/b:ro rpoc-tools \
  sh -c "exec /b/reality-bridge client --listen 127.0.0.1:9000 --connect edge:443 --pubkey $PUB --short-id $SID --sni cover.lab 2>/tmp/bridge.log" >/dev/null
sleep 3
docker exec rr-srv cat /tmp/id > $L/server.id
echo "stand up; server id $(cut -c1-8 $L/server.id)...; bridge log: docker exec rr-srv cat /tmp/bridge.log"
