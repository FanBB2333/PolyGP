#!/bin/sh
# =============================================================================
# PolyU GlobalProtect HIP report generator  (openconnect / yuezk-gpclient HIP script)
# -----------------------------------------------------------------------------
# Built from a HIP report (pan_gp_hrpt.xml) that a real official Windows GP client
# actually submitted and PolyU's gateway accepted. In practice PolyU's HIP object
# only strictly checks the anti-malware category (must contain "Microsoft Antivirus"
# = Windows Defender, real-time-protection=yes, recent virus-definition date);
# disk-encryption / patch-management pass even on the reference host (unencrypted,
# 7 missing patches), so the other categories here are kept as compliant stubs.
#
# Usage (openconnect invokes this as its HIP script and passes session args):
#   gpclient connect staffvpn.polyu.edu.hk --os Windows --hip /opt/polyu-hipreport.sh
#   # or directly with openconnect:
#   openconnect --protocol=gp --os=win --csd-wrapper=/opt/polyu-hipreport.sh \
#               --user=<user> staffvpn.polyu.edu.hk
#
# openconnect (yuezk fork) calls the script with "--key value" args:
#   --cookie <portal-cookie>  --client-ip <tunnel-ip>  --md5 <gateway-md5>
#   --client-os <os>  --client-version <ver>  --host-id <id>  --client-ipv6 <ip6>
# It parses these into the dynamic fields; everything else is hardcoded from the
# official report. Output: full HIP report XML on stdout (openconnect POSTs it).
# =============================================================================

set -eu

# ---- 1) Parse session args passed by openconnect (unknown args are skipped) ----
COOKIE=""
MD5=""
CLIENT_IP="0.0.0.0"          # fallback: reference tunnel IP, normally overridden by --client-ip
CLIENT_IPV6=""
CLIENT_OS="Windows"
CLIENT_VERSION="6.2.8-243"     # fallback: reference GP client version
HOST_ID="00000000-0000-0000-0000-000000000000"   # fallback: reference machine GUID

while [ $# -gt 0 ]; do
	case "$1" in
		--cookie)         COOKIE="${2:-}";         shift 2 ;;
		--md5)            MD5="${2:-}";            shift 2 ;;
		--client-ip)      CLIENT_IP="${2:-$CLIENT_IP}";       shift 2 ;;
		--client-ipv6)    CLIENT_IPV6="${2:-}";    shift 2 ;;
		--client-os)      CLIENT_OS="${2:-$CLIENT_OS}";       shift 2 ;;
		--client-version) CLIENT_VERSION="${2:-$CLIENT_VERSION}"; shift 2 ;;
		--host-id)        HOST_ID="${2:-$HOST_ID}"; shift 2 ;;
		--md5=*)          MD5="${1#*=}";           shift ;;
		--cookie=*)       COOKIE="${1#*=}";        shift ;;
		--client-ip=*)    CLIENT_IP="${1#*=}";     shift ;;
		--host-id=*)      HOST_ID="${1#*=}";       shift ;;
		*)                shift ;;
	esac
done

# ---- 2) Extract user-name from the portal cookie (form: ...&user=<name>&...) ----
USER_NAME=$(printf '%s' "$COOKIE" | tr '&;' '\n\n' | sed -n 's/^ *user=//p' | head -n1)
[ -n "$USER_NAME" ] || USER_NAME="zhaoyfan"          # fallback

# ---- 3) Dynamic timestamps; stamp the Defender virus-definition date to "today" ----
#         (PolyU checks anti-malware definition recency -> today keeps it passing)
NOW=$(date '+%m/%d/%Y %H:%M:%S')
DMON=$(date +%m); DMON=${DMON#0}     # strip leading zero (POSIX/dash): "07" -> 7
DDAY=$(date +%d); DDAY=${DDAY#0}     # ${VAR#0} strips one leading 0; "10"/"12" unaffected
DYEAR=$(date +%Y)

# Fixed host identifiers (change to your own Linux host if you like; PolyU doesn't strictly check)
HOST_NAME="EXAMPLE-HOST"
DOMAIN="HH"

# ---- 4) Emit the HIP report --------------------------------------------------
cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<hip-report>
	<md5-sum>${MD5}</md5-sum>
	<user-name>${USER_NAME}</user-name>
	<domain>${DOMAIN}</domain>
	<host-name>${HOST_NAME}</host-name>
	<host-id>${HOST_ID}</host-id>
	<ip-address>${CLIENT_IP}</ip-address>
	<ipv6-address>${CLIENT_IPV6}</ipv6-address>
	<generate-time>${NOW}</generate-time>
	<hip-report-version>4</hip-report-version>
	<categories>
		<entry name="host-info">
			<client-version>${CLIENT_VERSION}</client-version>
			<os>Microsoft Windows 10 Enterprise LTSC 2021 Evaluation , 64-bit</os>
			<os-vendor>Microsoft</os-vendor>
			<domain></domain>
			<host-name>${HOST_NAME}</host-name>
			<host-id>${HOST_ID}</host-id>
			<network-interface>
				<entry name="{00000000-0000-0000-0000-000000000000}">
					<description>PANGP Virtual Ethernet Adapter Secure</description>
					<mac-address>00-00-00-00-00-00</mac-address>
					<ip-address>
						<entry name="${CLIENT_IP}"/>
					</ip-address>
				</entry>
			</network-interface>
		</entry>
		<entry name="anti-malware">
			<list>
				<entry>
					<ProductInfo>
						<Prod vendor="Microsoft Corporation" name="Windows Defender" version="4.18.26060.3008" defver="1.455.84.0" engver="1.1.26060.3008" datemon="${DMON}" dateday="${DDAY}" dateyear="${DYEAR}" prodType="3" osType="1"/>
						<real-time-protection>yes</real-time-protection>
						<last-full-scan-time>n/a</last-full-scan-time>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="disk-backup">
			<list>
				<entry>
					<ProductInfo>
						<Prod vendor="Microsoft Corporation" name="Windows Backup and Restore" version="10.0.19041.1"/>
						<last-backup-time>n/a</last-backup-time>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="disk-encryption">
			<list>
				<entry>
					<ProductInfo>
						<Prod vendor="Microsoft Corporation" name="BitLocker Drive Encryption" version="10.0.19041.1"/>
						<drives>
							<entry>
								<drive-name>C:\\</drive-name>
								<enc-state>unencrypted</enc-state>
							</entry>
							<entry>
								<drive-name>All</drive-name>
								<enc-state>unencrypted</enc-state>
							</entry>
						</drives>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="firewall">
			<list>
				<entry>
					<ProductInfo>
						<Prod vendor="Microsoft Corporation" name="Windows Firewall" version="10.0.19041.1288"/>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
			</list>
		</entry>
		<entry name="patch-management">
			<list>
				<entry>
					<ProductInfo>
						<Prod vendor="Microsoft Corporation" name="Windows Update Agent" version="10.0.19041.1288"/>
						<is-enabled>yes</is-enabled>
					</ProductInfo>
				</entry>
			</list>
			<missing-patches></missing-patches>
		</entry>
		<entry name="data-loss-prevention">
			<list>
			</list>
		</entry>
	</categories>
</hip-report>
EOF
