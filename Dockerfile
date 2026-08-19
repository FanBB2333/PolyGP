# PolyGP — plain openconnect on a minimal Debian base.
#
# No gpclient and no PPA: the tunnel is stock openconnect, and the SAML login is
# driven by autologin/gp_saml_login.py. Because openconnect runs with
# --script-tun + ocproxy, the whole TCP/IP stack is userspace: the container
# needs no NET_ADMIN, no /dev/net/tun and no root, and it exposes the VPN as a
# SOCKS5 port instead of touching anyone's routing table.
#
# The login needs a browser, and a headless server has no screen, so the image
# ships a virtual display (Xvfb) published over noVNC. You open the printed URL
# in your own browser, drive the real Chromium running inside the container, and
# the script captures the prelogin-cookie exactly as it does natively.
FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
# Optional: a PyPI mirror for the build (e.g. https://mirrors.zju.edu.cn/pypi/web/simple)
ARG PIP_INDEX_URL=

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openconnect ocproxy ca-certificates \
        python3 python3-venv \
        chromium \
        xvfb x11vnc novnc websockify \
        numlockx \
        procps \
 && rm -rf /var/lib/apt/lists/*

# Playwright drives the browser; the browser itself is Debian's chromium, so the
# usual ~170MB browser download is skipped (see POLYGP_CHROMIUM below).
RUN python3 -m venv /opt/polygp/venv \
 && /opt/polygp/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/polygp/venv/bin/pip install --no-cache-dir \
        ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} playwright

COPY hip/       /opt/polygp/hip/
COPY autologin/ /opt/polygp/autologin/
COPY scripts/entrypoint.sh /opt/polygp/entrypoint.sh
RUN chmod +x /opt/polygp/hip/polyu-hipreport.sh \
             /opt/polygp/autologin/gp_saml_login.py \
             /opt/polygp/entrypoint.sh

ENV PATH="/opt/polygp/venv/bin:$PATH" \
    POLYGP_CHROMIUM=/usr/bin/chromium \
    POLYGP_BROWSER_ARGS="--no-sandbox --disable-dev-shm-usage --disable-gpu"

# Non-root: nothing here needs privileges, and chromium is happier this way.
# X11 needs its socket dir to already exist, since a non-root Xvfb cannot create
# it ("_XSERVTransmkdir: euid != 0") and would leave the entrypoint waiting.
RUN useradd -m -u 1000 polygp && chown -R polygp:polygp /opt/polygp \
 && mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix
USER polygp
WORKDIR /home/polygp

EXPOSE 11937 6080
ENTRYPOINT ["/opt/polygp/entrypoint.sh"]
