#!/usr/bin/env bash
# Поднимает стенд REALITY-PoC в Docker (сеть rp): cover (nginx TLS1.3), edge (Traefik v3.7.11 passthrough + PROXY v2),
# srv (shoes REALITY-сервер + reality-poc srv), cli (shoes REALITY-клиент + reality-poc cli).
# Ключи REALITY генерируются заново при каждом запуске (лабораторные, не коммитятся).
set -euo pipefail
W=${W:-$HOME/.cache/knothop-target/reality-poc}
HERE=$(cd "$(dirname "$0")" && pwd)
L=$W/lab; mkdir -p $L/cfg $L/cover $L/tr
./down.sh >/dev/null 2>&1 || true
KP=$($W/bin/shoes generate-reality-keypair)
PRIV=$(echo "$KP" | sed -n 's/.*private key: //p'); PUB=$(echo "$KP" | sed -n 's/.*public key: //p')
[ -f $L/cover/c.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj "/CN=cover.lab" -addext "subjectAltName=DNS:cover.lab" -keyout $L/cover/k.pem -out $L/cover/c.pem 2>/dev/null
cp $HERE/nginx.conf $L/cover/nginx.conf
cat > $L/cfg/server.yaml <<EOF
- address: "0.0.0.0:8444"
  protocol:
    type: tls
    reality_targets:
      "cover.lab":
        private_key: "$PRIV"
        short_ids: ["0123456789abcdef"]
        dest: "cover:443"
        protocol:
          type: portforward
          targets: "127.0.0.1:5201"
EOF
cat > $L/cfg/client.yaml <<EOF
- address: "127.0.0.1:9000"
  protocol:
    type: portforward
    targets: "127.0.0.1:1"
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "edge:443"
        protocol:
          type: reality
          public_key: "$PUB"
          short_id: "0123456789abcdef"
          sni_hostname: "cover.lab"
          protocol:
            type: portforward
EOF
sed 's/short_id: "0123456789abcdef"/short_id: "ffffffffffffffff"/' $L/cfg/client.yaml > $L/cfg/client-badid.yaml
sed 's/edge:443/srv:8444/' $L/cfg/client.yaml > $L/cfg/client-noedge.yaml
cp $HERE/dyn.yml $L/tr/dyn.yml
docker network inspect rp >/dev/null 2>&1 || docker network create rp >/dev/null
docker run -d --name rp-cover --network rp --network-alias cover -v $L/cover:/c:ro nginx:1.31.4-alpine nginx -c /c/nginx.conf -g 'daemon off;' >/dev/null
docker run -d --name rp-traefik --network rp --network-alias edge --cap-add NET_ADMIN -v $L/tr:/tr:ro traefik:v3.7.11 --log.level=INFO --providers.file.filename=/tr/dyn.yml --entrypoints.websecure.address=:443/tcp >/dev/null
docker run -d --name rp-srv --network rp --network-alias srv --cap-add NET_ADMIN -e SHOES_PROXY_V2=1 -v $W/bin:/b:ro -v $L/cfg:/cfg:ro rpoc-tools \
  sh -c '/b/reality-poc srv --carrier-listen 127.0.0.1:5201 --udp 4433 --cap ${CAP:-1400} --id-file /tmp/id 2>/tmp/srv.log & exec /b/shoes-pv2 -l /tmp/shoes.log /cfg/server.yaml' >/dev/null
docker run -d --name rp-cli --network rp --cap-add NET_ADMIN -v $W/bin:/b:ro -v $L/cfg:/cfg:ro rpoc-tools \
  sh -c 'exec /b/shoes -l /tmp/shoes.log /cfg/client.yaml' >/dev/null
sleep 3
docker exec rp-srv cat /tmp/id > $L/server.id
echo "stand up; server id $(cat $L/server.id | cut -c1-8)..."
