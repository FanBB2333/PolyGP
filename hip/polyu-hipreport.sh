#!/bin/sh
# =============================================================================
# PolyU GlobalProtect HIP report generator  (openconnect / yuezk-gpclient HIP script)
# -----------------------------------------------------------------------------
# Emits the HIP report openconnect POSTs to the gateway, by filling
# hipreport.xml.tmpl with values from hipreport.conf plus the session details
# openconnect passes on the command line. Logic lives here; every machine- and
# identity-specific value lives in the config, so neither needs editing to
# change the other.
#
# Usage (openconnect invokes this as its HIP/CSD script and passes session args):
#   gpclient connect staffvpn.polyu.edu.hk --os Windows --hip /opt/polyu-hipreport.sh
#   # or directly with openconnect:
#   openconnect --protocol=gp --os=win --csd-wrapper=/opt/polyu-hipreport.sh \
#               --user=<user> staffvpn.polyu.edu.hk
#
# openconnect calls the script with "--key value" args:
#   --cookie <portal-cookie>  --client-ip <tunnel-ip>  --md5 <gateway-md5>
#   --client-os <os>  --client-version <ver>  --host-id <id>  --client-ipv6 <ip6>
# Those win over the config, which supplies the fallbacks. Output: the full HIP
# report XML on stdout.
#
# Written for POSIX sh (openconnect invokes it via /bin/sh) — no bashisms.
#
# Files (override paths with $POLYGP_HIP_CONF / $POLYGP_HIP_TEMPLATE):
#   hipreport.conf           your values      (gitignored)
#   hipreport.conf.example   fallback config  (committed)
#   hipreport.xml.tmpl       report shape, @NAME@ placeholders
# =============================================================================

set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# ---- 1) Load configuration ---------------------------------------------------
CONF="${POLYGP_HIP_CONF:-$DIR/hipreport.conf}"
[ -f "$CONF" ] || CONF="$DIR/hipreport.conf.example"
[ -f "$CONF" ] || { echo "hip: no config found (looked for $DIR/hipreport.conf)" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

TMPL="${POLYGP_HIP_TEMPLATE:-$DIR/hipreport.xml.tmpl}"
[ -f "$TMPL" ] || { echo "hip: template not found: $TMPL" >&2; exit 1; }

# ---- 2) Parse the session args openconnect passes (unknown args are skipped) --
COOKIE=""
MD5=""
CLIENT_IPV6=""
CLIENT_OS="Windows"

while [ $# -gt 0 ]; do
	case "$1" in
		--cookie)         COOKIE="${2:-}";         shift 2 ;;
		--md5)            MD5="${2:-}";            shift 2 ;;
		--client-ip)      CLIENT_IP="${2:-$CLIENT_IP}";           shift 2 ;;
		--client-ipv6)    CLIENT_IPV6="${2:-}";    shift 2 ;;
		--client-os)      CLIENT_OS="${2:-$CLIENT_OS}";           shift 2 ;;
		--client-version) CLIENT_VERSION="${2:-$CLIENT_VERSION}"; shift 2 ;;
		--host-id)        CLIENT_HOST_ID="${2:-}"; shift 2 ;;
		--md5=*)          MD5="${1#*=}";           shift ;;
		--cookie=*)       COOKIE="${1#*=}";        shift ;;
		--client-ip=*)    CLIENT_IP="${1#*=}";     shift ;;
		--host-id=*)      CLIENT_HOST_ID="${1#*=}"; shift ;;
		*)                shift ;;
	esac
done

# --host-id wins over the configured fallback, but only when non-empty
[ -n "${CLIENT_HOST_ID:-}" ] && HOST_ID="$CLIENT_HOST_ID"

# ---- 3) Prefer the live user-name from the portal cookie (...&user=<name>&...) -
COOKIE_USER=$(printf '%s' "$COOKIE" | tr '&;' '\n\n' | sed -n 's/^ *user=//p' | head -n1)
[ -n "$COOKIE_USER" ] && USER_NAME="$COOKIE_USER"

# ---- 4) Timestamps; stamp the definition date to "today" so it stays recent ---
NOW=$(date '+%m/%d/%Y %H:%M:%S')
DEF_MON=$(date +%m); DEF_MON=${DEF_MON#0}   # strip leading zero (POSIX/dash): "07" -> 7
DEF_DAY=$(date +%d); DEF_DAY=${DEF_DAY#0}   # ${VAR#0} strips one leading 0; "10"/"12" unaffected
DEF_YEAR=$(date +%Y)

# ---- 5) Fill the template ----------------------------------------------------
# Values are escaped for sed's replacement side (\, & and the | delimiter).
esc() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'; }

sed \
	-e "s|@MD5@|$(esc "$MD5")|g" \
	-e "s|@USER_NAME@|$(esc "$USER_NAME")|g" \
	-e "s|@DOMAIN@|$(esc "$DOMAIN")|g" \
	-e "s|@HOST_NAME@|$(esc "$HOST_NAME")|g" \
	-e "s|@HOST_ID@|$(esc "$HOST_ID")|g" \
	-e "s|@CLIENT_IP@|$(esc "$CLIENT_IP")|g" \
	-e "s|@CLIENT_IPV6@|$(esc "$CLIENT_IPV6")|g" \
	-e "s|@NOW@|$(esc "$NOW")|g" \
	-e "s|@CLIENT_VERSION@|$(esc "$CLIENT_VERSION")|g" \
	-e "s|@OS_NAME@|$(esc "$OS_NAME")|g" \
	-e "s|@OS_VENDOR@|$(esc "$OS_VENDOR")|g" \
	-e "s|@NIC_GUID@|$(esc "$NIC_GUID")|g" \
	-e "s|@NIC_DESC@|$(esc "$NIC_DESC")|g" \
	-e "s|@NIC_MAC@|$(esc "$NIC_MAC")|g" \
	-e "s|@AM_VENDOR@|$(esc "$AM_VENDOR")|g" \
	-e "s|@AM_NAME@|$(esc "$AM_NAME")|g" \
	-e "s|@AM_VERSION@|$(esc "$AM_VERSION")|g" \
	-e "s|@AM_DEFVER@|$(esc "$AM_DEFVER")|g" \
	-e "s|@AM_ENGVER@|$(esc "$AM_ENGVER")|g" \
	-e "s|@AM_PRODTYPE@|$(esc "$AM_PRODTYPE")|g" \
	-e "s|@AM_OSTYPE@|$(esc "$AM_OSTYPE")|g" \
	-e "s|@AM_RTP@|$(esc "$AM_RTP")|g" \
	-e "s|@DEF_MON@|$DEF_MON|g" \
	-e "s|@DEF_DAY@|$DEF_DAY|g" \
	-e "s|@DEF_YEAR@|$DEF_YEAR|g" \
	"$TMPL"
