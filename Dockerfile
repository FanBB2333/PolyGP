# PolyGP — minimal Ubuntu + gpclient (yuezk GlobalProtect-openconnect).
# Ships a HIP report script reverse-engineered from a real Windows client, so a
# Linux gpclient passes PolyU's HIP check without the official Windows client.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
# Installs the current version from the yuezk PPA (verified on 2.5.4; 2.6.x works
# too, see the non-root note below). To pin:
#   docker compose build --build-arg GP_PIN=2.5.4-ppa2~ubuntu24.04
ARG GP_PIN=

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        software-properties-common ca-certificates \
 && add-apt-repository -y ppa:yuezk/globalprotect-openconnect \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        globalprotect-openconnect${GP_PIN:+=$GP_PIN} \
        openconnect iproute2 iputils-ping dnsutils curl sudo \
 && apt-get purge -y software-properties-common \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 # gpclient >= 2.6 refuses to run gpauth (webkit browser) as root, so we run the
 # container as the non-root 'ubuntu' user (uid 1000, present in the base image)
 # and let it sudo for the tun/route bits.
 && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ubuntu \
 && chmod 440 /etc/sudoers.d/ubuntu

# Whole dir: the script needs hipreport.xml.tmpl and a hipreport.conf alongside it
# (falling back to hipreport.conf.example when no conf is present in the context).
COPY hip/                   /opt/polygp/hip/
COPY scripts/entrypoint.sh  /opt/polygp/entrypoint.sh
RUN chmod +x /opt/polygp/hip/polyu-hipreport.sh /opt/polygp/entrypoint.sh

# Needs NET_ADMIN + /dev/net/tun (see compose.yml). Runs as non-root; sudo inside.
USER ubuntu
ENTRYPOINT ["/opt/polygp/entrypoint.sh"]
