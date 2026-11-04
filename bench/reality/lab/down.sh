#!/usr/bin/env bash
docker rm -f rr-cli rr-srv rr-traefik rr-cover >/dev/null 2>&1; docker network rm rr >/dev/null 2>&1; true
