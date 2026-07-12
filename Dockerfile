# PolyGP — minimal Ubuntu + gpclient (yuezk GlobalProtect-openconnect).
# Ships a HIP report script reverse-engineered from a real Windows client, so a
# Linux gpclient passes PolyU's HIP check without the official Windows client.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
# Installs the current version from the yuezk PPA (verified on 2.5.4; 2.6.x is
# API-compatible). To pin: docker compose build --build-arg GP_PIN=2.5.4-ppa2~ubuntu24.04
ARG GP_PIN=

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        software-properties-common ca-certificates \
 && add-apt-repository -y ppa:yuezk/globalprotect-openconnect \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        globalprotect-openconnect${GP_PIN:+=$GP_PIN} \
        openconnect iproute2 iputils-ping dnsutils curl \
 && apt-get purge -y software-properties-common \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY hip/polyu-hipreport.sh /opt/polygp/hip/polyu-hipreport.sh
COPY scripts/entrypoint.sh  /opt/polygp/entrypoint.sh
RUN chmod +x /opt/polygp/hip/polyu-hipreport.sh /opt/polygp/entrypoint.sh

# gpclient needs NET_ADMIN + /dev/net/tun to build the tunnel (see compose.yml)
ENTRYPOINT ["/opt/polygp/entrypoint.sh"]
