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
CONTROL_PORT="${CONTROL_PORT:-11936}"
DISPLAY_NUM="${DISPLAY_NUM:-99}"
VNC_SCREEN="${VNC_SCREEN:-1280x900x24}"
SAML_ENDPOINT="${SAML_ENDPOINT:-gateway}"     # gateway | portal
LOGIN_TIMEOUT="${LOGIN_TIMEOUT:-600}"
export DISPLAY=":${DISPLAY_NUM}"

# VNC's password is truncated to 8 bytes by the protocol, so keep it to 8.
VNC_PASSWORD="${VNC_PASSWORD:-}"
generated=""
if [ -z "$VNC_PASSWORD" ]; then
	# Not `tr </dev/urandom | head -c 8`: head closes the pipe early, tr dies of
	# SIGPIPE, and pipefail turns that into a 141 exit for the whole script.
	VNC_PASSWORD=$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8)))')
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
# X11VNC_ARGS is an escape hatch for keyboard handling. x11vnc's default
# ("modtweak") forces the exact keysym the client asked for, which is correct
# when the client sends the already-shifted keysym ('A' for shift+a) as the RFB
# spec expects. A client that instead sends shift + the unshifted keysym gets
# lowercase; -nomodtweak fixes that case but breaks the spec-correct one, so
# there is no setting that satisfies both — pick the one matching your client.
x11vnc -display "$DISPLAY" -rfbauth "$passfile" -rfbport 5900 -localhost \
       -forever -shared -quiet ${X11VNC_ARGS:-} >/dev/null 2>&1 &
pids+=($!)

# --- noVNC (websockify serves the web client and bridges to 5900) ------------
websockify --web=/usr/share/novnc "$VNC_PORT" 127.0.0.1:5900 >/dev/null 2>&1 &
pids+=($!)

cat <<BANNER
========================================================================
 PolyGP - connecting to PolyU GlobalProtect  (${PORTAL})
------------------------------------------------------------------------
 Control panel:  http://<this-host>:${CONTROL_PORT}/
     /login   start a login      /logout  disconnect
     /status  JSON state         /logs    recent output

 Browser UI:     http://<this-host>:${VNC_PORT}/vnc.html
     VNC password: ${VNC_PASSWORD}${generated}

 A login opens the PolyU page on the container's display: complete
 NetID + MFA over the browser UI above. (With POLYGP_NETID /
 POLYGP_NETPASS set, the form is filled in and only MFA is left.)

 The tunnel then comes up as SOCKS5 on port ${SOCKS_PORT}. When the
 session expires, hit /login again — the container stays up.
========================================================================
BANNER

# --- control plane (owns the login + tunnel lifecycle) -----------------------
# Not exec'd, so the trap above still tears the display stack down on exit.
python3 /opt/polygp/autologin/control.py "$@"
