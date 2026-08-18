#!/usr/bin/env bash
# PolyGP container entrypoint.
#
# Brings up a virtual display with a browser on it, published over noVNC, then
# runs the SAML login + openconnect tunnel. You open the noVNC URL from your own
# machine, drive the browser inside the container to complete NetID + MFA, and
# the tunnel comes up as a SOCKS5 port. Nothing here needs root or NET_ADMIN:
# openconnect runs with --script-tun + ocproxy, entirely in userspace.
set -euo pipefail

PORTAL="${PORTAL:-researchvpn.polyu.edu.hk}"
SOCKS_PORT="${SOCKS_PORT:-11937}"
VNC_PORT="${VNC_PORT:-6080}"
DISPLAY_NUM="${DISPLAY_NUM:-99}"
VNC_SCREEN="${VNC_SCREEN:-1280x900x24}"
SAML_ENDPOINT="${SAML_ENDPOINT:-gateway}"     # gateway | portal
LOGIN_TIMEOUT="${LOGIN_TIMEOUT:-600}"
export DISPLAY=":${DISPLAY_NUM}"

# VNC's password is truncated to 8 bytes by the protocol, so keep it to 8.
VNC_PASSWORD="${VNC_PASSWORD:-}"
generated=""
if [ -z "$VNC_PASSWORD" ]; then
	VNC_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 8)
	generated=" (generated for this run)"
fi

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

# --- virtual display ---------------------------------------------------------
Xvfb "$DISPLAY" -screen 0 "$VNC_SCREEN" -nolisten tcp &
xvfb_pid=$!
pids+=("$xvfb_pid")
for _ in $(seq 1 100); do
	[ -S "/tmp/.X11-unix/X${DISPLAY_NUM}" ] && break
	kill -0 "$xvfb_pid" 2>/dev/null || { echo "[polygp] Xvfb exited during startup" >&2; exit 1; }
	sleep 0.1
done
[ -S "/tmp/.X11-unix/X${DISPLAY_NUM}" ] \
	|| { echo "[polygp] Xvfb did not create /tmp/.X11-unix/X${DISPLAY_NUM}" >&2; exit 1; }

# --- VNC server on that display, loopback only; noVNC is the public face ------
passfile="$HOME/.polygp-vncpass"
x11vnc -storepasswd "$VNC_PASSWORD" "$passfile" >/dev/null 2>&1
x11vnc -display "$DISPLAY" -rfbauth "$passfile" -rfbport 5900 -localhost \
       -forever -shared -quiet >/dev/null 2>&1 &
pids+=($!)

# --- noVNC (websockify serves the web client and bridges to 5900) ------------
websockify --web=/usr/share/novnc "$VNC_PORT" 127.0.0.1:5900 >/dev/null 2>&1 &
pids+=($!)

cat <<BANNER
========================================================================
 PolyGP - connecting to PolyU GlobalProtect  (${PORTAL})
------------------------------------------------------------------------
 1. Open the browser UI from any machine that can reach this container:

        http://<this-host>:${VNC_PORT}/vnc.html

    VNC password: ${VNC_PASSWORD}${generated}

 2. A Chromium window is waiting there on the PolyU login page. Sign in
    with your NetID and approve MFA. (If POLYGP_NETID / POLYGP_NETPASS
    are set, the form is filled in for you and only MFA is left.)

 3. Once the login succeeds this window closes by itself, the HIP report
    is submitted, and the tunnel comes up as SOCKS5 on port ${SOCKS_PORT}.
    Point your proxy tool at it; no routes or DNS are touched anywhere.
========================================================================
BANNER

# --- login + tunnel ----------------------------------------------------------
# Not exec'd, so the trap above still tears the display stack down on exit.
endpoint_flag="--gateway"
[ "$SAML_ENDPOINT" = "portal" ] && endpoint_flag="--portal"

python3 /opt/polygp/autologin/gp_saml_login.py "$PORTAL" \
	"$endpoint_flag" \
	--socks-port "$SOCKS_PORT" \
	--socks-bind 0.0.0.0 \
	--timeout "$LOGIN_TIMEOUT" \
	"$@"
