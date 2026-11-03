#!/usr/bin/env bash
docker rm -f rp-cli rp-srv rp-traefik rp-cover >/dev/null 2>&1; docker network rm rp >/dev/null 2>&1; true
