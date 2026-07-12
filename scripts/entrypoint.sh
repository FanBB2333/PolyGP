#!/usr/bin/env bash
# PolyGP container entrypoint: connect to PolyU GlobalProtect using the bundled HIP script.
set -euo pipefail

PORTAL="${PORTAL:-staffvpn.polyu.edu.hk}"
GP_USER="${GP_USER:-}"
GP_OS="${GP_OS:-Windows}"
GP_CLIENT_VERSION="${GP_CLIENT_VERSION:-6.2.8-243}"
HIP_SCRIPT="${HIP_SCRIPT:-/opt/polygp/hip/polyu-hipreport.sh}"

user_arg=()
[ -n "$GP_USER" ] && user_arg=(--user "$GP_USER")

cat <<BANNER
========================================================================
 PolyGP - connecting to PolyU GlobalProtect  ($PORTAL)
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

# --fix-openssl: PolyU portal is a legacy server requiring legacy TLS renegotiation
# --browser remote: headless env; print a URL for the user to complete SAML
exec gpclient --fix-openssl connect "$PORTAL" \
    "${user_arg[@]}" \
    --os "$GP_OS" \
    --client-version "$GP_CLIENT_VERSION" \
    --hip "$HIP_SCRIPT" \
    --browser remote \
    -v
