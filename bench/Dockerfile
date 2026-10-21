# Измерительный образ: Python RNS (версия зафиксирована) + утилиты для netem/снимков.
FROM python:3.12-slim

ARG RNS_VERSION=1.5.7
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 procps tcpdump \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "rns==${RNS_VERSION}" cryptography

COPY vendor/lnsd /usr/local/bin/lnsd
COPY rnsbench.py /usr/local/bin/rnsbench.py
ENTRYPOINT ["python3", "/usr/local/bin/rnsbench.py"]
