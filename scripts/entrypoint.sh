#!/usr/bin/env bash
# PolyGP container entrypoint.
#
# Brings up a virtual display with a browser on it, published over noVNC, then
# runs the control panel, SAML login and openconnect tunnel. The login stays
# idle until explicitly triggered, so you open noVNC from your own machine only
# when ready to authenticate. The tunnel comes up as a SOCKS5 port. Nothing
# here needs root or NET_ADMIN:
# openconnect runs with --script-tun + ocproxy, entirely in userspace.
set -euo pipefail

PORTAL="${PORTAL:-researchvpn.polyu.edu.hk}"
SOCKS_PORT="${SOCKS_PORT:-11937}"
VNC_PORT="${VNC_PORT:-6080}"
CONTROL_PORT="${CONTROL_PORT:-11936}"
DISPLAY_NUM="${DISPLAY_NUM:-99}"
VNC_SCREEN="${VNC_SCREEN:-1600x900x24}"
SAML_ENDPOINT="${SAML_ENDPOINT:-gateway}"     # gateway | portal
LOGIN_TIMEOUT="${LOGIN_TIMEOUT:-600}"
# The control process uses the same value to size Chromium and the panel's
# responsive noVNC frame.
export DISPLAY=":${DISPLAY_NUM}" VNC_SCREEN

# --- timezone: follow the public IP's location -------------------------------
# openconnect, the HIP report and the panel all read the container clock; in a
# bare container that is UTC. Set TZ from where the egress IP actually is (via
# ip-api.com) so timestamps read in local time. An explicit TZ wins, and any
# failure (offline, blocked, unknown zone) just leaves the previous value.
if [ -z "${TZ:-}" ]; then
	tz=$(curl -fsS --max-time "${GEOIP_TIMEOUT:-5}" \
	         "${GEOIP_URL:-http://ip-api.com/json/?fields=timezone}" 2>/dev/null \
	     | sed -n 's/.*"timezone" *: *"\([^"]*\)".*/\1/p') || true
	if [ -n "${tz:-}" ] && [ -f "/usr/share/zoneinfo/$tz" ]; then
		export TZ="$tz"
		echo "[polygp] timezone from IP: $TZ"
	else
		echo "[polygp] could not detect timezone from ip-api.com; using UTC" >&2
	fi
fi
export TZ="${TZ:-UTC}"

# VNC's password is truncated to 8 bytes by the protocol, so keep it to 8.
VNC_PASSWORD="${VNC_PASSWORD:-}"
generated=""
if [ -z "$VNC_PASSWORD" ]; then
	# Not `tr </dev/urandom | head -c 8`: head closes the pipe early, tr dies of
	# SIGPIPE, and pipefail turns that into a 141 exit for the whole script.
	VNC_PASSWORD=$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8)))')
	generated=" (generated for this run)"
fi

# The control panel builds a noVNC link carrying this password, so it has
# to reach control.py as an environment variable, not just a shell one.
export VNC_PASSWORD VNC_PORT CONTROL_PORT

# --- per-machine HIP identity ------------------------------------------------
# The HIP report claims a Windows machine's name/GUID/adapter. Rather than every
# container reporting the same one baked into the image, mint a fresh identity
# on first boot. Point POLYGP_HIP_CONF at a mounted volume (see compose.yml) and
# it persists across recreation; otherwise it is regenerated per container,
# which is harmless (PolyU does not validate these fields).
HIP_CONF="${POLYGP_HIP_CONF:-/opt/polygp/hip/hipreport.conf}"
export POLYGP_HIP_CONF="$HIP_CONF"
if [ ! -f "$HIP_CONF" ]; then
	if python3 /opt/polygp/hip/gen-hipreport-conf.py --out "$HIP_CONF" 2>&1; then
		:
	else
		echo "[polygp] warning: could not generate $HIP_CONF; using the bundled fallback" >&2
		unset POLYGP_HIP_CONF
	fi
fi

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

# --- virtual display ---------------------------------------------------------
# A container restart preserves its writable /tmp.  If the previous Xvfb was
# killed uncleanly, its lock and socket can survive even though no X server is
# listening anymore.  Remove only stale entries; never disturb a live Xvfb.
display_socket="/tmp/.X11-unix/X${DISPLAY_NUM}"
display_lock="/tmp/.X${DISPLAY_NUM}-lock"
display_owner=""
if [ -f "$display_lock" ]; then
	display_owner=$(tr -d '[:space:]' <"$display_lock" 2>/dev/null || true)
fi
if [[ "$display_owner" =~ ^[0-9]+$ ]] && [ -r "/proc/${display_owner}/cmdline" ]; then
	owner_cmd=$(tr '\0' ' ' <"/proc/${display_owner}/cmdline" 2>/dev/null || true)
	if [[ "$owner_cmd" == *Xvfb* ]]; then
		echo "[polygp] display :${DISPLAY_NUM} is already in use by Xvfb pid ${display_owner}" >&2
		exit 1
	fi
fi
if [ -e "$display_lock" ] || [ -e "$display_socket" ]; then
	rm -f -- "$display_lock" "$display_socket"
fi

Xvfb "$DISPLAY" -screen 0 "$VNC_SCREEN" -nolisten tcp &
xvfb_pid=$!
pids+=("$xvfb_pid")
for _ in $(seq 1 100); do
	kill -0 "$xvfb_pid" 2>/dev/null || { echo "[polygp] Xvfb exited during startup" >&2; exit 1; }
	[ -S "$display_socket" ] && break
	sleep 0.1
done
kill -0 "$xvfb_pid" 2>/dev/null && [ -S "$display_socket" ] \
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

# noVNC sends XK_KP_1 (not XK_1) for the numeric keypad, and X only turns a KP_
# keysym into a digit while NumLock is on — a fresh Xvfb starts with it off, so
# the keypad types Home/End/arrows instead of numbers. Set it here rather than
# right after Xvfb: an X server with no clients left resets itself and drops
# every modifier lock, so a numlockx run before x11vnc has attached is silently
# undone. Waiting for port 5900 means x11vnc is holding the display open.
# (Xvfb never updates the NumLock LED, so `numlockx status` and `xset q` still
# report "off" afterwards; the modifier itself does latch.)
for _ in $(seq 1 100); do
	python3 -c 'import socket,sys; sys.exit(0 if socket.socket().connect_ex(("127.0.0.1", 5900)) == 0 else 1)' \
		&& break
	sleep 0.1
done
numlockx on 2>/dev/null || echo "[polygp] warning: could not enable NumLock" >&2

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

 The container stays idle until you click Log in, or submit an MFA code in
 the control panel. That action creates a fresh SAML request and opens the
 PolyU page on the container's display. (With POLYGP_NETID / POLYGP_NETPASS
 set, click the login page once to fill the form; only MFA is left afterwards.)

 The tunnel then comes up as SOCKS5 on port ${SOCKS_PORT}. When the
 session expires, hit /login again — the container stays up.
========================================================================
BANNER

# --- control plane (owns the login + tunnel lifecycle) -----------------------
# Not exec'd, so the trap above still tears the display stack down on exit.
python3 /opt/polygp/autologin/control.py "$@"
