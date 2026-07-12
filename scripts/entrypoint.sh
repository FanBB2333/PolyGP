#!/usr/bin/env bash
# PolyGP container entrypoint: connect to PolyU GlobalProtect using the bundled HIP script.
# Runs as the non-root 'ubuntu' user and sudo's for the tun/route bits, because
# gpclient >= 2.6 refuses to run gpauth (webkit browser) as root.
set -euo pipefail

PORTAL="${PORTAL:-staffvpn.polyu.edu.hk}"
GP_USER="${GP_USER:-}"
GP_OS="${GP_OS:-Windows}"
GP_CLIENT_VERSION="${GP_CLIENT_VERSION:-6.2.8-243}"
HIP_SCRIPT="${HIP_SCRIPT:-/opt/polygp/hip/polyu-hipreport.sh}"
BIND_TAILSCALE="${BIND_TAILSCALE:-auto}"

user_arg=()
[ -n "$GP_USER" ] && user_arg=(--user "$GP_USER")

# --- Optional: bind the SAML auth server to the tailscale IP ---------------------
# gpauth decides which IP the auth server binds to by connecting a UDP socket to
# 1.1.1.1 and reading the local source IP. By pointing a 1.1.1.1/32 route at the
# tailscale interface, that source IP (hence the auth server) becomes the tailscale
# IP, so any tailnet device can open the auth URL directly — no SOCKS tunnel needed.
# Set BIND_TAILSCALE=0 to disable, =1 to require it (warn if no tailscale found).
ROUTE_ADDED=""
cleanup() { [ -n "$ROUTE_ADDED" ] && sudo ip route del 1.1.1.1/32 2>/dev/null || true; }
trap cleanup EXIT INT TERM

if [ "$BIND_TAILSCALE" != "0" ]; then
  ts_line=$(ip -o -4 addr show 2>/dev/null | awk '$4 ~ /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./ {print $2, $4; exit}')
  ts_if=$(printf '%s' "$ts_line" | cut -d' ' -f1)
  ts_ip=$(printf '%s' "$ts_line" | cut -d' ' -f2 | cut -d/ -f1)
  if [ -n "$ts_if" ] && [ -n "$ts_ip" ]; then
    if sudo ip route replace 1.1.1.1/32 dev "$ts_if" src "$ts_ip" 2>/dev/null; then
      ROUTE_ADDED=1
      echo "[polygp] auth server will bind tailscale IP ${ts_ip} (via ${ts_if}) — open the printed URL from any tailnet device"
    else
      echo "[polygp] WARN: failed to add tailscale route (missing NET_ADMIN?); using default bind"
    fi
  elif [ "$BIND_TAILSCALE" = "1" ]; then
    echo "[polygp] WARN: BIND_TAILSCALE=1 but no tailscale (100.64/10) interface found; using default bind"
  fi
fi

cat <<BANNER
========================================================================
 PolyGP - connecting to PolyU GlobalProtect  (${PORTAL})
------------------------------------------------------------------------
 Auth method: SAML (browser). A URL like
     http://<IP>:<port>/<uuid>
 will be printed below. Open it in a browser -> complete PolyU ADFS
 login + phone MFA -> paste the returned  globalprotectcallback:...
 string back into this terminal.

 PolyU uses two-stage auth (portal + gateway), so you authenticate
 TWICE (the second time is instant via ADFS SSO). A transient
   "status=512 ... Invalid username or password"
 in between is normal - just ignore it.
========================================================================
BANNER

# sudo: openconnect needs root for the tun; gpclient drops gpauth to $SUDO_USER
# (the non-root 'ubuntu' user), satisfying gpclient >= 2.6's non-root gpauth rule.
# Not exec'd, so the EXIT trap can remove the tailscale route afterwards.
sudo -E gpclient --fix-openssl connect "$PORTAL" \
    "${user_arg[@]}" \
    --os "$GP_OS" \
    --client-version "$GP_CLIENT_VERSION" \
    --hip "$HIP_SCRIPT" \
    --browser remote \
    -v
