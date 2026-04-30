#!/usr/bin/env bash
# ==============================================================================
# Supply Chain Attack Scanner — Ubuntu/Linux                          v2.5
# Live Feed + Historical IOCs
#
# ⚠️ VIBE-CODED NOTICE: 
# This script was vibe-coded (heavily assisted by AI). It's been tested 
# and gets the job done, but please read through the code before running 
# it with root privileges on your production machines!
# ==============================================================================
# Pulls the latest malicious package data from:
#   • OSV.dev bulk zip   (one HTTP request per ecosystem, parsed locally)
#   • OpenSSF malicious-packages feed (cloned via git, parsed locally)
# Then scans the local system, Docker containers, and Docker images.
#
# Usage:
#   sudo bash scan-supply-chain.sh                          # full run
#   sudo bash scan-supply-chain.sh --offline                # hardcoded list only
#   sudo bash scan-supply-chain.sh --output-json /var/log/sc.json
#   GITHUB_TOKEN=ghp_... sudo -E bash scan-supply-chain.sh  # auth GitHub
#
# Schedule daily (as root):
#   echo "0 7 * * * root bash /opt/scan-supply-chain.sh --output-json /var/log/sc-scan.json" \
#     | sudo tee /etc/cron.d/supply-chain-scan
#
# Dependencies (all standard on Ubuntu):
#   bash >= 4 (associative arrays), curl, python3
#   git (recommended; falls back to GitHub REST API)
#   jq (optional)
#   docker (optional — skipped if absent)
# ==============================================================================

# Restrict file creation perms — JSON reports etc.
umask 077

# IMPORTANT: We deliberately do NOT use `set -e` because many checks are best-
# effort and we want them to fail silently rather than abort the whole scan.
# `set -u` catches undefined-variable bugs; `pipefail` propagates pipeline
# failures we explicitly check.
set -uo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()    { echo -e "${CYAN}[*]${RESET} $*"; }
warn()   { echo -e "${YELLOW}[!]${RESET} $*"; }
hit()    { echo -e "${RED}[MATCH]${RESET} $*"; FINDINGS+=("$*"); FOUND=$((FOUND+1)); }
ok()     { echo -e "${GREEN}[ok]${RESET} $*"; }
header() { echo -e "\n${BOLD}${CYAN}=== $* ===${RESET}"; }

FOUND=0
SCANNED=0
FINDINGS=()
OUTPUT_JSON=""
SKIP_LIVE_FEED=0

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --offline|--skip-live-feed) SKIP_LIVE_FEED=1 ;;
        --output-json) OUTPUT_JSON="${2:-}"; shift ;;
        *) warn "Unknown argument: $1" ;;
    esac
    shift
done

# ── Set up scratch directory + cleanup trap (unconditionally, very early) ─────
TMPDIR_OSSF=$(mktemp -d)
MAIN_PID=$$
cleanup() {
    # Only the main process should clean up — prevents subshells from
    # firing the trap on their own exit.
    [[ $$ -eq $MAIN_PID ]] && rm -rf "$TMPDIR_OSSF"
}
trap cleanup EXIT

# ── Validate package names before passing to docker exec / shell  ─────────────
# Used to defend against shell injection from untrusted live-feed package names.
_pkg_name_safe() {
    [[ "$1" =~ ^[@a-zA-Z0-9._/+-]+$ ]]
}

# ── Malicious package store ───────────────────────────────────────────────────
# Associative array: key="ecosystem<US>pkgname"  value="ver1 ver2 *"
# We use the unit separator (\x1f, $'\x1f') as the key delimiter so package
# names containing colons (uncommon but legal in some ecosystems) don't break.
declare -A MALICIOUS_PKGS=()
US=$'\x1f'

merge_pkg() {
    local eco="$1" name="$2"; shift 2
    [[ -z "$eco" || -z "$name" ]] && return
    local key="${eco}${US}${name}"
    if [[ "${MALICIOUS_PKGS[$key]+_}" ]] && [[ "${MALICIOUS_PKGS[$key]}" == "*" ]]; then
        return   # already wildcard
    fi
    local new_vers="$*"
    if [[ "$new_vers" == "*" ]]; then
        MALICIOUS_PKGS[$key]="*"
    else
        local existing="${MALICIOUS_PKGS[$key]:-}"
        # Trim/normalise to space-separated unique list
        MALICIOUS_PKGS[$key]="$(printf '%s\n' $existing $new_vers | sort -u | tr '\n' ' ' | xargs || true)"
    fi
}

# Versions list assumption: bad-version strings never contain spaces.
# OSV records may use ranges (`>= 1.0.0, < 2.0.0`); we flatten only the
# enumerated `versions[]` field, which OSV recommends always be present.
is_bad_version() {
    local version="$1" bad_list="$2"
    [[ -z "$version" ]] && return 1
    [[ "$bad_list" == "*" ]] && return 0
    local bv
    for bv in $bad_list; do
        [[ "$version" == "$bv" ]] && return 0
    done
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — HARDCODED IOC LIST
# ══════════════════════════════════════════════════════════════════════════════

# ── S1ngularity / Nx (August 26 2025) ───────────────────────────────────────
# Malicious npm releases used postinstall hooks to collect secrets and publish
# them into attacker-created GitHub repos named with "s1ngularity-repository".
merge_pkg "npm" "nx" "21.5.0" "20.9.0" "20.10.0" "21.6.0" "20.11.0" "21.7.0" "21.8.0" "20.12.0"
for pkg in "@nx/devkit" "@nx/js" "@nx/workspace" "@nx/node"; do
    merge_pkg "npm" "$pkg" "21.5.0" "20.9.0"
done
merge_pkg "npm" "@nx/eslint" "21.5.0"
merge_pkg "npm" "@nx/key" "3.2.0"
merge_pkg "npm" "@nx/enterprise-cloud" "3.2.0"

# ── September 2025 npm crypto-theft + Shai-Hulud worm wave ──────────────────
# Curated high-signal subset of the CISA/Mend/Socket-reported npm incidents:
# massively downloaded packages, CrowdStrike packages, @ctrl/tinycolor family,
# and commonly observed Angular / NativeScript victims. Live feeds cover the
# long tail; this keeps offline mode useful without embedding a giant feed dump.
while IFS='|' read -r pkg versions; do
    [[ -z "$pkg" || "$pkg" == \#* ]] && continue
    merge_pkg "npm" "$pkg" $versions
done <<'EOF'
ansi-styles|6.2.2
backslash|0.2.1
chalk|5.6.1
chalk-template|1.1.1
color-convert|3.1.1
color-name|2.0.1
color-string|2.1.1
debug|4.4.2
error-ex|1.3.3
has-ansi|6.0.1
is-arrayish|0.3.3
proto-tinker-wc|0.1.87
simple-swizzle|0.2.3
slice-ansi|7.1.1
strip-ansi|7.1.1
supports-color|10.2.1
supports-hyperlinks|4.1.1
wrap-ansi|9.0.1
@ahmedhfarag/ngx-perfect-scrollbar|20.0.20
@ahmedhfarag/ngx-virtual-scroller|4.0.4
@crowdstrike/commitlint|8.1.1 8.1.2
@crowdstrike/falcon-shoelace|0.4.1 0.4.2
@crowdstrike/foundry-js|0.19.1 0.19.2
@crowdstrike/glide-core|0.34.2 0.34.3
@crowdstrike/logscale-dashboard|1.205.1 1.205.2
@crowdstrike/logscale-file-editor|1.205.1 1.205.2
@crowdstrike/logscale-parser-edit|1.205.1 1.205.2
@crowdstrike/logscale-search|1.205.1 1.205.2
@crowdstrike/tailwind-toucan-base|5.0.1 5.0.2
@ctrl/deluge|1.2.0 7.2.1 7.2.2
@ctrl/golang-template|1.4.2 1.4.3
@ctrl/magnet-link|4.0.3 4.0.4
@ctrl/ngx-codemirror|7.0.1 7.0.2
@ctrl/ngx-csv|6.0.1 6.0.2
@ctrl/ngx-emoji-mart|9.2.1 9.2.2
@ctrl/ngx-rightclick|4.0.1 4.0.2
@ctrl/qbittorrent|9.7.1 9.7.2
@ctrl/react-adsense|2.0.1 2.0.2
@ctrl/shared-torrent|6.3.1 6.3.2
@ctrl/tinycolor|4.1.1 4.1.2
@ctrl/torrent-file|4.1.1 4.1.2
@ctrl/transmission|7.3.1
@ctrl/ts-base32|4.0.1 4.0.2
angulartics2|14.1.1 14.1.2
ng2-file-upload|7.0.2 7.0.3 8.0.1 8.0.2 8.0.3 9.0.1
ngx-bootstrap|18.1.4 19.0.3 19.0.4 20.0.3 20.0.4 20.0.5 20.0.6
ngx-toastr|19.0.1 19.0.2
EOF

# ── CanisterWorm (TeamPCP, March 20-23 2026) ─────────────────────────────────
# NOTE: This is the initial Socket disclosure list (30 packages).
# JFrog later identified 47+ packages in total. Live feed (OpenSSF/OSV)
# covers the additional ones.
for pkg in api-agentv3 api-auth api-biddingv2 api-biddingv3 api-blocksv2 \
           api-couponsv2 api-couponsv3 api-dashboardv2 api-deliveriesv2 \
           api-deliveriesv3 api-financev2 api-giftcardsv3 api-identitiesv3 \
           api-inventoryv2 api-inventoryv3 api-logsv3 api-menuv2 api-menuv3 \
           api-notificationsv3 api-ordersv2 api-ordersv3 api-paymentsv2 \
           api-paymentsv3 api-productsv2 api-productsv3 api-reportingv3 \
           api-restaurantsv2 api-restaurantsv3 api-usersv2 api-usersv3; do
    merge_pkg "npm" "@emilgroup/${pkg}" "1.0.1"
done
merge_pkg "npm" "@teale.io/eslint-config" "1.8.11" "1.8.12"

# ── CanisterSprawl (TeamPCP, April 8-23 2026) ────────────────────────────────
merge_pkg "npm" "@automagik/genie" \
    "4.260421.33" "4.260421.34" "4.260421.35" "4.260421.36" \
    "4.260421.37" "4.260421.38" "4.260421.39" "4.260421.40"
merge_pkg "npm" "pgserve"                          "1.1.11" "1.1.12" "1.1.13" "1.1.14"
merge_pkg "npm" "@fairwords/websocket"             "1.0.38" "1.0.39"
merge_pkg "npm" "@fairwords/loopback-connector-es" "1.4.3"  "1.4.4"
merge_pkg "npm" "@openwebconcept/design-tokens"    "1.0.1"  "1.0.2"  "1.0.3"
merge_pkg "npm" "@openwebconcept/theme-owc"        "1.0.1"  "1.0.2"  "1.0.3"

# ── Checkmarx / Bitwarden (April 22 2026) ────────────────────────────────────
merge_pkg "npm" "@bitwarden/cli" "2026.4.0"

# ── Axios RAT (TeamPCP, March 31 2026) ───────────────────────────────────────
merge_pkg "npm" "axios"           "1.14.1" "0.30.4"
merge_pkg "npm" "plain-crypto-js" "*"

# ── dYdX (January 2026) ──────────────────────────────────────────────────────
merge_pkg "npm"  "@dydxprotocol/v4-client-js" "3.4.1" "1.22.1" "1.15.2" "1.0.31"
merge_pkg "PyPI" "dydx-v4-client"             "3.4.1" "1.22.1" "1.15.2" "1.0.31"

# ── Asurion-impersonation (April 1-8 2026, claimed red-team) ─────────────────
for pkg in sbxapps asurion-hub-web soluto-home-web asurion-core; do
    merge_pkg "npm" "$pkg" "*"
done

# ── Kubernetes-impersonation (April 2026) ────────────────────────────────────
merge_pkg "npm"  "kube-health-tools" "*"
merge_pkg "PyPI" "kube-node-health"  "*"

# ── LiteLLM (TeamPCP, March 24 2026) ─────────────────────────────────────────
merge_pkg "PyPI" "litellm" "1.82.7" "1.82.8"

# ── xinference (April 22 2026) ───────────────────────────────────────────────
merge_pkg "PyPI" "xinference" "2.6.0" "2.6.1" "2.6.2"

# ── Docker images ────────────────────────────────────────────────────────────
merge_pkg "Docker" "checkmarx/kics" "*"

# ── IOC artefacts ────────────────────────────────────────────────────────────
IOC_FILES=("/tmp/pglog" "/tmp/.pg_state" "/tmp/inventory.txt" "${HOME}/.config/sysmon/sysmon.py")
IOC_SCRIPTS=("env-compat.cjs" "public.pem" "sysmon.py" "litellm_init.pth")
# More-specific IOC strings (avoid bare "pgmon" -> matches PostgreSQL pg_monitor role).
# Each string is paired with a regex-anchored variant to cut FPs.
# NOTE: strings split via "" to prevent the script from flagging itself.
IOC_STRINGS=(
    "pkg-""telemetry" "pypi-""pth-exfil"
    "cjn37-""uyaaa-aaaac-qgnva-cai"
    "telemetry.""api-monitor.com"
    "audit.""checkmarx.cx"
    "scan.""aquasecurtiy.org"
    "models.""litellm.cloud"
    "pgmon.""service"
    ".config/""pgmon"
    "plain-""crypto-js"
    "s1ngularity-""repository"
    "Shai-""Hulud"
)
# Generic ICP canister regex — catches new wave canister IDs the worm may rotate to.
IOC_REGEX_ICP='[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-'"cai\.raw\.icp0\.io"

declare -A IOC_HASHES=(
    ["c19c4574d09e60636425f9555d3b63e8cb5c9d63ceb1c982c35e5a310c97a839"]="env-compat.cjs (CanisterSprawl payload)"
    ["834b6e5db5710b9308d0598978a0148a9dc832361f1fa0b7ad4343dcceba2812"]="public.pem (CanisterSprawl RSA key)"
)
IOC_HOSTS=(
    "telemetry.""api-monitor.com"
    "cjn37-""uyaaa-aaaac-qgnva-cai.raw.icp0.io"
    "audit.""checkmarx.cx"
    "scan.""aquasecurtiy.org"
    "models.""litellm.cloud"
)

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — LIVE FEED PULL
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║  Supply Chain Attack Scanner v2.5  (Ubuntu/Linux)               ║${RESET}"
echo -e "${BOLD}${CYAN}║  Live: OSV.dev bulk + OpenSSF mal-pkgs + Historical IOCs        ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo "Host : $(hostname)"
echo "User : $(whoami)"
echo "Date : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
[[ $EUID -ne 0 ]] && warn "Not running as root — some paths may be inaccessible. Re-run with sudo for full coverage."

if [[ $SKIP_LIVE_FEED -eq 0 ]]; then
    header "PULLING LIVE MALICIOUS PACKAGE FEEDS"

    # ── 2a. OpenSSF malicious-packages via shallow git clone ──────────────────
    # A `git clone --depth 1 --filter=blob:none --no-checkout` of the OpenSSF
    # malicious-packages repo is much faster than 2,000 sequential REST calls.
    # We then sparse-checkout just `osv/malicious/` and parse JSON locally.
    log "Cloning OpenSSF malicious-packages (shallow, blob-filter)..."
    OSSF_COUNT=0
    OSSF_RECORDS=0
    OSSF_T0=$SECONDS
    OSSF_REPO="${TMPDIR_OSSF}/ossf-malicious-packages"

    if command -v git &>/dev/null; then
        if git clone --quiet --depth 1 --filter=blob:none --no-checkout \
                "https://github.com/ossf/malicious-packages.git" "$OSSF_REPO" 2>/dev/null; then
            ( cd "$OSSF_REPO" && \
              git sparse-checkout init --cone 2>/dev/null && \
              git sparse-checkout set osv/malicious 2>/dev/null && \
              git checkout --quiet 2>/dev/null ) || true

            if [[ -d "${OSSF_REPO}/osv/malicious" ]]; then
                log "  Parsing OSV records from clone..."
                # Single Python pass — much faster than per-file shell loops.
                while IFS= read -r line; do
                    if [[ "$line" == PROG${US}* ]]; then
                        echo -e "  ${CYAN}[*]${RESET}  OpenSSF: ${line#PROG${US}}"
                    else
                        IFS=$US read -r eco name ver <<< "$line"
                        [[ -z "$name" ]] && continue
                        merge_pkg "$eco" "$name" "$ver"
                        OSSF_COUNT=$((OSSF_COUNT+1))
                    fi
                done < <(OSSF_DIR="${OSSF_REPO}/osv/malicious" \
                         OSSF_T0_ENV="$OSSF_T0" \
                         python3 - <<'PY' 2>/dev/null
import json, os, sys, time
US = "\x1f"
mal_dir = os.environ["OSSF_DIR"]
t0      = int(os.environ["OSSF_T0_ENV"])
files   = []
for root, _, fs in os.walk(mal_dir):
    for f in fs:
        if f.endswith(".json"):
            files.append(os.path.join(root, f))
total = len(files)
records = 0
for i, path in enumerate(files, 1):
    if i % 100 == 0:
        elapsed = int(time.time()) - t0
        print(f"PROG{US}{i}/{total} files parsed ({elapsed}s elapsed)...", flush=True)
    try:
        with open(path) as f:
            rec = json.load(f)
    except Exception:
        continue
    records += 1
    rec_id = rec.get("id", "")
    is_mal_record = rec_id.startswith("MAL-")
    for aff in rec.get("affected", []):
        pkg = aff.get("package", {}) or {}
        eco  = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        if not name:
            continue
        raw_vers = aff.get("versions")
        if raw_vers:
            vers = raw_vers
        elif is_mal_record:
            vers = ["*"]
        else:
            continue
        for v in vers:
            print(f"{eco}{US}{name}{US}{v}", flush=True)
# Final progress line
print(f"PROG{US}{total}/{total} files parsed (done)", flush=True)
PY
                         )
                # Approximate record count (one OSV record can yield many entries)
                OSSF_RECORDS=$(find "${OSSF_REPO}/osv/malicious" -name '*.json' 2>/dev/null | wc -l)
                log "  OpenSSF feed done: ${OSSF_RECORDS} records, ${OSSF_COUNT} package-version entries loaded in $(( SECONDS - OSSF_T0 ))s."
            else
                warn "  OpenSSF clone succeeded but osv/malicious/ missing."
            fi
        else
            warn "  Could not git-clone OpenSSF feed; falling back to REST API."
            # Fall back to REST API (slower, rate-limited).
            tree_json=$(curl -sf --max-time 30 \
                ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
                -H "User-Agent: SupplyChainScanner/2.2" \
                -H "Accept: application/vnd.github+json" \
                "https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1" \
                2>/dev/null) || tree_json=""
            if [[ -n "$tree_json" ]]; then
                if command -v jq &>/dev/null; then
                    osv_paths=$(echo "$tree_json" | jq -r '.tree[].path | select(test("^osv/malicious/.*\\.json$"))' 2>/dev/null | tail -2000) || osv_paths=""
                else
                    osv_paths=$(echo "$tree_json" | python3 -c "
import json,sys
data = json.load(sys.stdin)
paths = [t['path'] for t in data.get('tree',[])
         if t.get('path','').startswith('osv/malicious/') and t.get('path','').endswith('.json')]
print('\n'.join(paths[-2000:]))
" 2>/dev/null) || osv_paths=""
                fi
                # Count without using grep -c (which fails with set -e on no-match)
                OSSF_TOTAL=$(printf '%s\n' "$osv_paths" | grep -c . 2>/dev/null || true)
                [[ -z "$OSSF_TOTAL" ]] && OSSF_TOTAL=0
                log "  Fetching ${OSSF_TOTAL} OSV records via REST (progress every 100)..."
                OSSF_FETCHED=0
                while IFS= read -r opath; do
                    [[ -z "$opath" ]] && continue
                    tmpfile="${TMPDIR_OSSF}/rec.json"
                    if curl -sf --max-time 10 \
                        ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
                        "https://raw.githubusercontent.com/ossf/malicious-packages/main/${opath}" \
                        -o "$tmpfile" 2>/dev/null; then
                        while IFS=$US read -r eco name ver; do
                            [[ -z "$name" ]] && continue
                            merge_pkg "$eco" "$name" "$ver"
                            OSSF_COUNT=$((OSSF_COUNT+1))
                        done < <(python3 - "$tmpfile" 2>/dev/null <<'PY'
import json, sys, os
US = "\x1f"
try:
    with open(sys.argv[1]) as f:
        rec = json.load(f)
    rec_id = rec.get("id", "")
    is_mal_record = rec_id.startswith("MAL-")
    for aff in rec.get("affected", []):
        pkg = aff.get("package", {}) or {}
        eco  = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        if not name:
            continue
        raw_vers = aff.get("versions")
        if raw_vers:
            vers = raw_vers
        elif is_mal_record:
            vers = ["*"]
        else:
            continue
        for v in vers:
            print(f"{eco}{US}{name}{US}{v}")
except Exception:
    pass
PY
                        )
                    fi
                    OSSF_FETCHED=$((OSSF_FETCHED+1))
                    if (( OSSF_FETCHED % 100 == 0 )); then
                        OSSF_ELAPSED=$(( SECONDS - OSSF_T0 ))
                        echo -e "  ${CYAN}[*]${RESET}  OpenSSF (REST): ${OSSF_FETCHED}/${OSSF_TOTAL} records (${OSSF_ELAPSED}s)..."
                    fi
                done <<< "$osv_paths"
                # Final progress line
                if (( OSSF_FETCHED > 0 && OSSF_FETCHED % 100 != 0 )); then
                    echo -e "  ${CYAN}[*]${RESET}  OpenSSF (REST): ${OSSF_FETCHED}/${OSSF_TOTAL} records (done)"
                fi
                log "  OpenSSF feed (REST) done: ${OSSF_COUNT} entries from ${OSSF_FETCHED} records in $(( SECONDS - OSSF_T0 ))s."
            else
                warn "  OpenSSF REST fallback also failed."
            fi
        fi
    else
        warn "  git not installed; cannot fetch OpenSSF feed efficiently. Install git for best results."
    fi

    # ── 2b. OSV bulk zip (one HTTP request per ecosystem, parsed locally) ─────
    log "Fetching OSV bulk zips (npm + PyPI) — one download each, parsed locally..."
    OSV_COUNT=0
    OSV_RECORDS=0
    OSV_T0=$SECONDS
    OSV_ECOSYSTEMS=("npm" "PyPI")

    for ECO in "${OSV_ECOSYSTEMS[@]}"; do
        zip_url="https://storage.googleapis.com/osv-vulnerabilities/${ECO}/all.zip"
        zip_file="${TMPDIR_OSSF}/${ECO}_all.zip"

        log "  Downloading ${ECO} bulk zip (~30-80 MB)..."
        if ! curl -sf --max-time 300 "$zip_url" -o "$zip_file" 2>/dev/null; then
            warn "  Could not download ${ECO} bulk zip — skipping."
            continue
        fi
        log "  Scanning ${ECO} records locally (no further HTTP requests)..."

        ECO_RECORDS=0
        ECO_COUNT=0
        # Single Python pass: unzip in memory, filter malicious, emit US-delimited output.
        # Progress lines prefixed PROG<US> are routed differently from data lines.
        while IFS= read -r line; do
            if [[ "$line" == PROG${US}* ]]; then
                echo -e "  ${CYAN}[*]${RESET}  OSV ${ECO}: ${line#PROG${US}}"
            elif [[ "$line" == COUNT${US}* ]]; then
                ECO_RECORDS="${line#COUNT${US}}"
            else
                IFS=$US read -r pkg_eco pkg_name pkg_ver <<< "$line"
                [[ -z "$pkg_name" ]] && continue
                merge_pkg "$pkg_eco" "$pkg_name" "$pkg_ver"
                OSV_COUNT=$((OSV_COUNT+1))
                ECO_COUNT=$((ECO_COUNT+1))
            fi
        done < <(OSV_T0_ENV="$OSV_T0" \
                 python3 - "$zip_file" "$ECO" 2>/dev/null <<'PY'
import json, sys, time, os, zipfile, re

US = "\x1f"
zip_path  = sys.argv[1]
ecosystem = sys.argv[2]
t0        = int(os.environ.get("OSV_T0_ENV", "0"))

# Word-boundary regex filter -- avoids the substring false-positive trap.
# Without \b, "rat" matches "rate"/"operation"/"integration"; "compromised"
# matches summaries describing victims, not attackers; etc. The strongest
# signals (MAL-* IDs and database_specific.malicious=true) are checked first;
# this regex is only a fallback for ordinary advisories that happen to
# describe a malicious package without using those flags.
MAL_KEYWORD_PATTERNS = [
    r"malicious[-\s]?package",
    r"malicious\s+(?:npm|pypi|package|version|release)",
    r"malware",
    r"backdoor",
    r"crypto[-\s]?stealer",
    r"info[-\s]?stealer",
    r"credential[-\s]?stealer",
    r"credential[-\s]?stealing",
    r"data[-\s]?exfiltration",
    r"exfiltrates?",
    r"typosquat\w*",
    r"dependency[-\s]?confusion",
    r"account\s+takeover",
    r"package\s+takeover",
    r"compromised\s+(?:package|version|release|maintainer|account)",
    r"package\s+(?:was|is|been)\s+compromised",
    r"hijack(?:ed|ing)\s+(?:package|version|release|account)",
    r"supply[-\s]chain\s+(?:attack|compromise)",
]
MAL_KEYWORD_RE = re.compile(r"\b(?:" + "|".join(MAL_KEYWORD_PATTERNS) + r")\b", re.IGNORECASE)

malicious_records = 0
with zipfile.ZipFile(zip_path) as zf:
    names = zf.namelist()
    total = len(names)
    for i, name in enumerate(names, 1):
        if i % 1000 == 0:
            elapsed = int(time.time()) - t0
            print(f"PROG{US}{i}/{total} records scanned ({elapsed}s)...", flush=True)
        try:
            with zf.open(name) as f:
                rec = json.load(f)
        except Exception:
            continue
        rec_id  = rec.get("id", "")
        summary = rec.get("summary", "") or ""
        db_spec = rec.get("database_specific", {}) or {}
        is_mal_record = rec_id.startswith("MAL-")
        is_mal = (
            is_mal_record
            or db_spec.get("malicious") is True
            or bool(MAL_KEYWORD_RE.search(summary))
        )
        if not is_mal:
            continue
        malicious_records += 1
        for aff in rec.get("affected", []):
            pkg = aff.get("package", {}) or {}
            eco  = pkg.get("ecosystem", ecosystem)
            name = pkg.get("name", "")
            if not name:
                continue
            raw_vers = aff.get("versions")
            if raw_vers:
                vers = raw_vers
            elif is_mal_record:
                # MAL- records with no enumerated versions = the entire
                # malicious package is bad. Wildcard is correct here.
                vers = ["*"]
            else:
                # CVE/GHSA-style record without versions[] uses ranges.
                # Skipping prevents the false-positive cascade where every
                # CVE on a popular package marks all versions as bad.
                continue
            for v in vers:
                print(f"{eco}{US}{name}{US}{v}", flush=True)

# Final progress
elapsed = int(time.time()) - t0
print(f"PROG{US}{total}/{total} records scanned (done, {elapsed}s)", flush=True)
print(f"COUNT{US}{malicious_records}", flush=True)
PY
        )
        OSV_RECORDS=$((OSV_RECORDS + ECO_RECORDS))
        log "  ${ECO}: ${ECO_RECORDS} IOC records added, ${ECO_COUNT} package-version entries collected."
        rm -f "$zip_file"
    done
    log "  OSV bulk scan done: ${OSV_RECORDS} IOC records, ${OSV_COUNT} entries collected in $(( SECONDS - OSV_T0 ))s."

    log "Live feeds complete. IOC list now contains ${#MALICIOUS_PKGS[@]} unique packages to scan for."
else
    warn "Live feed skipped (--offline). Using hardcoded list only (${#MALICIOUS_PKGS[@]} packages)."
fi

log "IOC list size: ${#MALICIOUS_PKGS[@]} unique packages to scan for"

# ── Build ecosystem sub-lists ─────────────────────────────────────────────────
NPM_PKGS=()
PYPI_PKGS=()
DOCKER_PKGS=()
APT_PKGS=()
for key in "${!MALICIOUS_PKGS[@]}"; do
    [[ "$key" == "npm${US}"*    ]] && NPM_PKGS+=("${key#npm${US}}")
    [[ "$key" == "PyPI${US}"*   ]] && PYPI_PKGS+=("${key#PyPI${US}}")
    [[ "$key" == "Docker${US}"* ]] && DOCKER_PKGS+=("${key#Docker${US}}")
    [[ "$key" == "Debian${US}"* ]] && APT_PKGS+=("${key#Debian${US}}")
    [[ "$key" == "Ubuntu${US}"* ]] && APT_PKGS+=("${key#Ubuntu${US}}")
done
log "Breakdown — npm: ${#NPM_PKGS[@]}  PyPI: ${#PYPI_PKGS[@]}  Docker: ${#DOCKER_PKGS[@]}  apt: ${#APT_PKGS[@]}"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — IOC FILE / PERSISTENCE CHECK
# ══════════════════════════════════════════════════════════════════════════════

# Define search roots ONCE — broad enough for normal local installs, but still
# bounded to home/system package locations instead of blindly walking `/`.
SEARCH_ROOTS=()
PYTHON_ROOTS=()

add_search_root() {
    local root="$1" existing
    [[ -d "$root" ]] || return
    for existing in "${SEARCH_ROOTS[@]:-}"; do
        [[ "$existing" == "$root" ]] && return
    done
    SEARCH_ROOTS+=("$root")
}

add_python_root() {
    local root="$1" existing
    [[ -d "$root" ]] || return
    for existing in "${PYTHON_ROOTS[@]:-}"; do
        [[ "$existing" == "$root" ]] && return
    done
    PYTHON_ROOTS+=("$root")
}

# If the user is /home/mike, scan /home. If their home is elsewhere, scan that
# parent directory. Also include common package install locations on `/`.
if [[ "${HOME:-}" == /home/* ]]; then
    add_search_root "/home"
elif [[ -n "${HOME:-}" ]]; then
    add_search_root "$(dirname "$HOME")"
fi
add_search_root "/root"
add_search_root "/usr"
add_search_root "/usr/local"
add_search_root "/opt"
add_search_root "/srv"
add_search_root "/app"
add_search_root "/workspace"
add_search_root "/var/www"
add_search_root "/var/lib"

for proot in \
    /usr/lib/python3 /usr/lib/python3.* /usr/local/lib/python3.* \
    /opt/conda /opt/anaconda3 /opt/miniconda3 \
    "${HOME}/.local/lib" /root/.local/lib \
    "${HOME}/.cache/uv" /root/.cache/uv; do
    add_python_root "$proot"
done
# Pseudo-FS prune list (don't descend into these)
PRUNE_DIRS=(/proc /sys /dev /run /var/run /tmp/.dockerenv)

# Build a `find` prune expression for SEARCH_ROOTS scans.
build_prune_expr() {
    local first=1
    PRUNE_EXPR=()
    local d
    for d in "${PRUNE_DIRS[@]}"; do
        if [[ $first -eq 1 ]]; then
            PRUNE_EXPR+=(-path "$d" -prune)
            first=0
        else
            PRUNE_EXPR+=(-o -path "$d" -prune)
        fi
    done
}
build_prune_expr

discover_python_roots() {
    local root found
    log "Discovering Python venv/site-packages roots under: ${SEARCH_ROOTS[*]}"
    for root in "${SEARCH_ROOTS[@]}"; do
        [[ -d "$root" ]] || continue
        while IFS= read -r -d '' found; do
            if [[ "$(basename "$found")" == "pyvenv.cfg" ]]; then
                add_python_root "$(dirname "$found")"
            else
                add_python_root "$found"
            fi
        done < <(find "$root" -xdev -maxdepth 8 \( "${PRUNE_EXPR[@]}" \) -prune -o \
                      \( -name "node_modules" -o -name ".git" -o -name ".cache" \) -type d -prune -o \
                      \( -name "pyvenv.cfg" -type f -o -name "site-packages" -type d \) -print0 2>/dev/null || true)
    done
    log "  Python scan roots: ${#PYTHON_ROOTS[@]}"
}
discover_python_roots

print_scan_paths() {
    local path
    header "LOCAL SCAN PATHS"
    log "npm / filesystem roots (${#SEARCH_ROOTS[@]}):"
    for path in "${SEARCH_ROOTS[@]}"; do
        echo "  - $path"
    done
    log "Python venv/site-packages roots (${#PYTHON_ROOTS[@]}):"
    for path in "${PYTHON_ROOTS[@]}"; do
        echo "  - $path"
    done
}

echo ""
echo -e "${BOLD}${CYAN}+==================================================================+${RESET}"
echo -e "${BOLD}${CYAN}|  Now scanning this system against the IOC list collected above   |${RESET}"
echo -e "${BOLD}${CYAN}|  Any [MATCH] lines from this point forward indicate findings on  |${RESET}"
echo -e "${BOLD}${CYAN}|  YOUR system, not just IOC list contents.                        |${RESET}"
echo -e "${BOLD}${CYAN}+==================================================================+${RESET}"
print_scan_paths

header "IOC FILES AND PERSISTENCE ARTEFACTS"
for f in "${IOC_FILES[@]}"; do
    SCANNED=$((SCANNED+1))
    if [[ -e "$f" ]]; then hit "IOC file found: $f"
    else ok "Not present: $f"; fi
done

# pgmon worm persistence (systemd user service)
SCANNED=$((SCANNED+1))
if systemctl --user list-unit-files 2>/dev/null | grep -q '^pgmon\.service'; then
    hit "pgmon.service is registered as a systemd user unit (CanisterWorm/Sprawl persistence!)"
elif systemctl --user is-active pgmon.service 2>/dev/null | grep -q '^active'; then
    hit "pgmon.service is ACTIVE under systemd --user (worm persistence!)"
else
    ok "pgmon.service not present in user systemd"
fi

# sysmon.py (LiteLLM worm persistence)
SCANNED=$((SCANNED+1))
sysmon_paths=("${HOME}/.config/sysmon/sysmon.py" "/root/.config/sysmon/sysmon.py")
for sp in "${sysmon_paths[@]}"; do
    [[ -f "$sp" ]] && hit "LiteLLM worm persistence (sysmon.py): $sp"
done

# litellm_init.pth — restricted to Python install roots (was: find / -maxdepth 12)
SCANNED=$((SCANNED+1))
for proot in "${PYTHON_ROOTS[@]}"; do
    [[ -d "$proot" ]] || continue
    while IFS= read -r pth_path; do
        [[ -n "$pth_path" ]] && hit "LiteLLM .pth persistence: $pth_path"
    done < <(find "$proot" -xdev -maxdepth 8 -name "litellm_init.pth" 2>/dev/null | head -10 || true)
done

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — npm PACKAGE SCAN
# ══════════════════════════════════════════════════════════════════════════════

header "npm PACKAGE SCAN  (${#NPM_PKGS[@]} packages in IOC list)"
log "Collecting package.json files (depth ≤ 12)..."

# Read package.json safely via stdin — avoids shell-interpolating user paths.
read_package_json() {
    local pjson="$1"
    [[ -r "$pjson" ]] || { echo "|||"; return; }
    python3 - "$pjson" 2>/dev/null <<'PY' || echo "|||"
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    t = "true" if any(k in d for k in ("_id", "_integrity", "_resolved")) else "false"
    p = "true" if d.get("private") else "false"
    print(f"{d.get('name','')}|{d.get('version','')}|{p}|{t}")
except Exception:
    print("|||")
PY
}

check_package_json() {
    local pjson="$1"
    local name version is_priv has_tags key bad
    IFS='|' read -r name version is_priv has_tags < <(read_package_json "$pjson")
    [[ -z "$name" ]] && return

    # False positive mitigation: skip if private or not an installed dependency
    [[ "$is_priv" == "true" ]] && return
    if [[ "$pjson" != */node_modules/* && "$has_tags" != "true" ]]; then
        return
    fi
    key="npm${US}${name}"
    if [[ "${MALICIOUS_PKGS[$key]+_}" ]]; then
        SCANNED=$((SCANNED+1))
        bad="${MALICIOUS_PKGS[$key]}"
        if is_bad_version "$version" "$bad"; then
            hit "npm: ${name}@${version} — MALICIOUS at $(dirname "$pjson")"
        else
            ok "npm: ${name}@${version} — version OK"
        fi
    fi
}

# Collect all package.json paths once into an array, skipping double-nested
# node_modules and pseudo filesystems.
PJSON_FILES=()
for root in "${SEARCH_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' pj; do
        # Skip double-nested node_modules
        [[ "$pj" == */node_modules/*/node_modules/* ]] && continue
        PJSON_FILES+=("$pj")
    done < <(find "$root" -xdev -maxdepth 12 \( "${PRUNE_EXPR[@]}" \) -prune -o \
                          -name "package.json" -type f -print0 2>/dev/null || true)
done
log "  Found ${#PJSON_FILES[@]} package.json files."

for pj in "${PJSON_FILES[@]}"; do
    check_package_json "$pj"
done

# Lock file scan for injected deps (plain-crypto-js from Axios attack)
log "Scanning lock files for malicious injected dependencies..."
for root in "${SEARCH_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' lf; do
        SCANNED=$((SCANNED+1))
        if grep -lE 'plain-crypto-js|"axios": "1\.14\.1"|"axios": "0\.30\.4"' "$lf" 2>/dev/null >/dev/null; then
            hit "Lock file contains malicious Axios/plain-crypto-js: $lf"
        fi
    done < <(find "$root" -xdev -maxdepth 10 \( "${PRUNE_EXPR[@]}" \) -prune -o \
                  \( -name "package-lock.json" -o -name "yarn.lock" \) -type f -print0 2>/dev/null || true)
done

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — PyPI PACKAGE SCAN
# ══════════════════════════════════════════════════════════════════════════════

header "PyPI PACKAGE SCAN  (${#PYPI_PKGS[@]} packages in IOC list)"

# PEP 503 normalisation: lowercase, replace runs of [-_.] with single hyphen.
pypi_canonical() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[-_.]+/-/g'
}

for pkgname in "${PYPI_PKGS[@]:-}"; do
    [[ -z "$pkgname" ]] && continue
    key="PyPI${US}${pkgname}"
    bad="${MALICIOUS_PKGS[$key]:-}"

    # 5a. pip show
    for pip_cmd in pip3 pip python3 python; do
        command -v "$pip_cmd" &>/dev/null || continue
        # `pip show` output is parsed by line — no shell interpolation.
        ver=$($pip_cmd show "$pkgname" 2>/dev/null | awk '/^Version:/{print $2; exit}' || true)
        if [[ -n "$ver" ]]; then
            SCANNED=$((SCANNED+1))
            if is_bad_version "$ver" "$bad"; then
                hit "PyPI (pip): ${pkgname}==${ver} — MALICIOUS!"
            else
                ok "PyPI (pip): ${pkgname}==${ver} — version OK"
            fi
            break
        fi
    done

    # 5b. .dist-info directories — restricted to Python roots, with proper regex
    # PyPI normalises hyphens/underscores in dist-info dir names per PEP 503.
    pkg_canonical=$(pypi_canonical "$pkgname")
    for proot in "${PYTHON_ROOTS[@]}"; do
        [[ -d "$proot" ]] || continue
        while IFS= read -r dist; do
            [[ -z "$dist" ]] && continue
            local_name=$(basename "$dist")
            # Pull version out via Python with a robust regex
            ver=$(DIST_NAME_ENV="$local_name" PKG_ENV="$pkgname" \
                  python3 - <<'PY' 2>/dev/null
import os, re, sys
n = os.environ["DIST_NAME_ENV"]
p = os.environ["PKG_ENV"]
# Underscore/hyphen variants
p_norm = re.sub(r'[-_.]+', '[-_.]', re.escape(p))
m = re.match(rf'^(?:{p_norm})-(?P<ver>[^-].*)\.dist-info$', n, re.IGNORECASE)
if m:
    print(m.group("ver"))
PY
                  ) || ver=""
            [[ -z "$ver" ]] && continue
            SCANNED=$((SCANNED+1))
            if is_bad_version "$ver" "$bad"; then
                hit "PyPI dist-info: ${pkgname}==${ver} — MALICIOUS at $dist"
            else
                ok "PyPI dist-info: ${pkgname}==${ver} — version OK"
            fi
        done < <(find "$proot" -xdev -maxdepth 10 -type d -name "*.dist-info" 2>/dev/null \
                 | grep -iE "/${pkg_canonical//-/[-_.]}-[^/]+\.dist-info$" 2>/dev/null \
                 | head -10 || true)
    done
done

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — APT / DPKG SCAN (Ubuntu)
# ══════════════════════════════════════════════════════════════════════════════

header "APT / DPKG SCAN"
log "Checking dpkg database for packages flagged by live OSV feed..."

if [[ ${#APT_PKGS[@]} -gt 0 ]] && command -v dpkg-query &>/dev/null; then
    for pkg in "${APT_PKGS[@]}"; do
        _pkg_name_safe "$pkg" || { warn "Skipping unsafe package name: $pkg"; continue; }
        bad="${MALICIOUS_PKGS["Debian${US}${pkg}"]:-${MALICIOUS_PKGS["Ubuntu${US}${pkg}"]:-}}"
        ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
        if [[ -n "$ver" ]]; then
            SCANNED=$((SCANNED+1))
            if is_bad_version "$ver" "$bad"; then
                hit "apt/dpkg: ${pkg}=${ver} — MALICIOUS!"
            else
                ok "apt/dpkg: ${pkg}=${ver} — version OK"
            fi
        fi
    done
else
    ok "No Debian/Ubuntu packages in current IOC list (live feed may add some)."
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — DOCKER SCAN
# ══════════════════════════════════════════════════════════════════════════════

header "DOCKER SCAN"
if command -v docker &>/dev/null && docker info &>/dev/null; then
    log "Docker found and reachable."

    # 7a. Flagged images — use grep -F (fixed string) so dots aren't regex
    for img in "${DOCKER_PKGS[@]:-}"; do
        [[ -z "$img" ]] && continue
        SCANNED=$((SCANNED+1))
        mapfile -t matches < <(docker images --format "{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}" 2>/dev/null \
                              | grep -F "$img" 2>/dev/null || true)
        if [[ ${#matches[@]} -gt 0 ]]; then
            for m in "${matches[@]}"; do
                hit "Docker image: $m — flagged as compromised. Verify digest."
            done
        else
            ok "Docker image not present: $img"
        fi
    done

    # 7b. Layer-history heuristic
    log "Checking image layer histories..."
    while IFS= read -r iid; do
        [[ -z "$iid" ]] && continue
        iname=$(docker images --format "{{.Repository}}:{{.Tag}}" --filter "id=$iid" 2>/dev/null | head -1)
        hist=$(docker history --no-trunc "$iid" 2>/dev/null || true)
        SCANNED=$((SCANNED+1))
        if echo "$hist" | grep -qiE "pgserve|automagik|emilgroup|pgmon\.service|check-env\.js|litellm.*1\.82|xinference.*2\.6|axios.*1\.14\.1|plain-crypto-js"; then
            hit "Docker image ${iname} ($iid): suspicious layer references"
        fi
    done < <(docker images -q 2>/dev/null | sort -u)

    # 7c. Running container scan — uses env-var passing for safety
    log "Scanning running containers..."
    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | tr -d '/')
        log "  Container: ${cname} ($cid)"

        # IOC files (no untrusted input)
        for ioc in "/tmp/pglog" "/tmp/.pg_state" "/root/.config/sysmon/sysmon.py"; do
            SCANNED=$((SCANNED+1))
            if docker exec "$cid" sh -c 'test -e "$1" && echo yes' _ "$ioc" 2>/dev/null | grep -q yes; then
                hit "Container ${cname}: IOC file $ioc"
            fi
        done

        # pgmon — look for the systemd unit, not the bare string
        SCANNED=$((SCANNED+1))
        if docker exec "$cid" sh -c 'find /etc/systemd /root/.config/systemd 2>/dev/null | grep -F pgmon.service' 2>/dev/null | grep -q pgmon; then
            hit "Container ${cname}: pgmon.service systemd unit present"
        fi

        # npm packages — pass package name via $1 to avoid shell injection
        for pkgname in "${NPM_PKGS[@]:-}"; do
            [[ -z "$pkgname" ]] && continue
            _pkg_name_safe "$pkgname" || continue
            SCANNED=$((SCANNED+1))
            key="npm${US}${pkgname}"
            bad="${MALICIOUS_PKGS[$key]:-}"
            # NB: using $1 inside the container shell, with `_` as $0
            result=$(docker exec "$cid" sh -c \
                'find / -maxdepth 14 -path "*/node_modules/$1/package.json" 2>/dev/null | head -5' \
                _ "$pkgname" 2>/dev/null || true)
            while IFS= read -r f; do
                [[ -z "$f" ]] && continue
                # Read version safely via stdin redirection
                ver=$(docker exec "$cid" sh -c \
                    'cat "$1" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(\"version\",\"\"))" 2>/dev/null \
                     || node -e "console.log(require(\"$1\").version||\"\")" 2>/dev/null' \
                    _ "$f" 2>/dev/null | tr -d '\r\n' || true)
                if [[ -n "$ver" ]]; then
                    if is_bad_version "$ver" "$bad"; then
                        hit "Container ${cname}: npm ${pkgname}@${ver} — MALICIOUS at $f"
                    else
                        ok "Container ${cname}: npm ${pkgname}@${ver} — OK"
                    fi
                fi
            done <<< "$result"
        done

        # PyPI packages
        for pkgname in "${PYPI_PKGS[@]:-}"; do
            [[ -z "$pkgname" ]] && continue
            _pkg_name_safe "$pkgname" || continue
            SCANNED=$((SCANNED+1))
            key="PyPI${US}${pkgname}"
            bad="${MALICIOUS_PKGS[$key]:-}"
            ver=$(docker exec "$cid" sh -c \
                'pip show "$1" 2>/dev/null | awk "/^Version:/{print \$2; exit}"' \
                _ "$pkgname" 2>/dev/null | tr -d '\r\n' || true)
            if [[ -n "$ver" ]]; then
                if is_bad_version "$ver" "$bad"; then
                    hit "Container ${cname}: PyPI ${pkgname}==${ver} — MALICIOUS!"
                else
                    ok "Container ${cname}: PyPI ${pkgname}==${ver} — OK"
                fi
            fi
        done
    done < <(docker ps -q 2>/dev/null)
else
    warn "Docker not found or daemon not reachable — skipping container/image scan."
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — IOC SCRIPT / STRING / HASH SCANS
# ══════════════════════════════════════════════════════════════════════════════

header "IOC SCRIPT FILES"
for ioc_script in "${IOC_SCRIPTS[@]}"; do
    SCANNED=$((SCANNED+1))
    for root in "${SEARCH_ROOTS[@]}"; do
        [[ -d "$root" ]] || continue
        while IFS= read -r hit_path; do
            [[ -n "$hit_path" ]] && hit "IOC script '${ioc_script}' at: $hit_path"
        done < <(find "$root" -maxdepth 12 \( "${PRUNE_EXPR[@]}" \) -prune -o \
                              -name "$ioc_script" -type f -print 2>/dev/null | head -20 || true)
    done
done

header "IOC STRING SEARCH"
log "  Building combined regex for all strings in one pass..."
SCANNED=$((SCANNED+1))
COMBINED_REGEX=""
for str in "${IOC_STRINGS[@]}"; do
    escaped_str=$(echo "$str" | sed 's/\./\\./g')
    if [[ -z "$COMBINED_REGEX" ]]; then
        COMBINED_REGEX="$escaped_str"
    else
        COMBINED_REGEX="$COMBINED_REGEX|$escaped_str"
    fi
done

for root in "${SEARCH_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    # grep -E (extended regex), searching all IOC strings in one pass
    while IFS= read -r hit_path; do
        [[ -n "$hit_path" ]] && hit "IOC string match in: $hit_path"
    done < <(grep -rlE "$COMBINED_REGEX" "$root" \
                --include="*.js" --include="*.cjs" --include="*.mjs" \
                --include="*.py" --include="*.json" \
                --include="*.npmrc" --include=".npmrc" \
                --include="*.env"   --include=".env" \
                --include="*.sh"    --include="*.yaml" --include="*.yml" \
                --exclude-dir=".git" --exclude-dir=".vscode" \
                --exclude-dir="History" --exclude-dir="workspaceStorage" \
                --exclude-dir="node_modules" --exclude-dir="test-logs" \
                --exclude="scan-supply-chain.sh" --exclude="Scan-SupplyChain.ps1" \
                2>/dev/null | head -10 || true)
done

# Generic ICP canister regex — catches new IDs the worm rotates to.
log "  Regex: ICP canister IDs"
SCANNED=$((SCANNED+1))
for root in "${SEARCH_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r hit_path; do
        [[ -n "$hit_path" ]] && hit "ICP canister exfil URL pattern in: $hit_path"
    done < <(grep -rlE "$IOC_REGEX_ICP" "$root" \
                --include="*.js" --include="*.cjs" --include="*.mjs" \
                --include="*.py" --include="*.json" \
                --exclude-dir=".git" --exclude-dir=".vscode" \
                --exclude-dir="History" --exclude-dir="workspaceStorage" \
                --exclude-dir="node_modules" --exclude-dir="test-logs" \
                --exclude="scan-supply-chain.sh" --exclude="Scan-SupplyChain.ps1" \
                2>/dev/null | head -10 || true)
done

header "IOC FILE HASH CHECK"
for fname in "env-compat.cjs" "public.pem"; do
    for root in "${SEARCH_ROOTS[@]}"; do
        [[ -d "$root" ]] || continue
        while IFS= read -r fpath; do
            [[ -z "$fpath" ]] && continue
            SCANNED=$((SCANNED+1))
            # `--` ends sha256sum option parsing; tr removes any backslash
            # escape prefix it adds for paths with special chars.
            hash=$(sha256sum -- "$fpath" 2>/dev/null | cut -d' ' -f1 | tr -d '\\' || true)
            if [[ -n "${IOC_HASHES[$hash]+_}" ]]; then
                hit "HASH MATCH: $fpath => $hash (${IOC_HASHES[$hash]})"
            else
                ok "Hash OK: $fpath ($hash)"
            fi
        done < <(find "$root" -maxdepth 12 \( "${PRUNE_EXPR[@]}" \) -prune -o \
                              -name "$fname" -type f -print 2>/dev/null | head -20 || true)
    done
done

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — NETWORK AND CONFIG CHECKS
# ══════════════════════════════════════════════════════════════════════════════

header "NETWORK CONNECTIONS TO IOC ENDPOINTS"
SCANNED=$((SCANNED+1))
if command -v ss &>/dev/null; then
    established=$(ss -tn state established 2>/dev/null || true)
    for ioc_host in "${IOC_HOSTS[@]}"; do
        resolved_ips=$(getent hosts "$ioc_host" 2>/dev/null | awk '{print $1}' || true)
        for ip in $resolved_ips; do
            if echo "$established" | grep -qF "$ip"; then
                hit "Active connection to IOC host $ioc_host ($ip)"
            fi
        done
    done
    ok "Network connection check complete."
else
    warn "ss not available — skipping network connection check."
fi

header ".npmrc AND /etc/hosts CHECK"
# Iterate npmrc files explicitly, including bare ~/.npmrc
shopt -s nullglob
NPMRC_FILES=(/root/.npmrc /home/*/.npmrc /etc/npmrc)
shopt -u nullglob
for npmrc in "${NPMRC_FILES[@]}"; do
    [[ -f "$npmrc" ]] || continue
    SCANNED=$((SCANNED+1))
    # Use grep -E (POSIX ERE), no -P (Perl) which isn't always available
    if grep -E '^[[:space:]]*registry[[:space:]]*=[[:space:]]*https?://' "$npmrc" 2>/dev/null \
        | grep -vE 'registry[[:space:]]*=[[:space:]]*https?://registry\.npmjs\.org' >/dev/null; then
        hit "Suspicious registry redirect in $npmrc"
    else
        ok "$npmrc registry OK"
    fi
done

SCANNED=$((SCANNED+1))
if grep -qiE '^[^#]*[[:space:]]registry\.npmjs' /etc/hosts 2>/dev/null; then
    hit "/etc/hosts contains npmjs redirect — possible registry hijack"
else
    ok "/etc/hosts clean"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

header "SCAN SUMMARY"
echo ""
echo -e "${BOLD}Total checks performed        : $SCANNED${RESET}"
echo -e "${BOLD}Malicious packages in IOC list: ${#MALICIOUS_PKGS[@]}${RESET}"
echo -e "${BOLD}Indicators found              : $FOUND${RESET}"
echo ""

if [[ $FOUND -gt 0 ]]; then
    echo -e "${RED}${BOLD}FINDINGS — TAKE IMMEDIATE ACTION:${RESET}"
    for f in "${FINDINGS[@]}"; do echo -e "  ${RED}•${RESET} $f"; done
    echo ""
    echo -e "${YELLOW}${BOLD}RECOMMENDED ACTIONS:${RESET}"
    echo "  1. Remove/uninstall all flagged packages immediately."
    echo "  2. ROTATE ALL credentials on this machine:"
    echo "     npm tokens, SSH keys, AWS/GCP/Azure creds, GitHub PATs, API keys, .env secrets"
    echo "  3. Stop worm persistence if found:"
    echo "     systemctl --user stop pgmon.service && systemctl --user disable pgmon.service"
    echo "  4. Audit npm publish history for unauthorised releases from your namespaces."
    echo "  5. Review CI/CD pipeline logs for installs of affected versions."
    echo "  6. Run: npm config set ignore-scripts true"
    echo "  7. If PyPI credentials present: check Python envs for .pth injection."
else
    echo -e "${GREEN}${BOLD}✓ No known supply chain indicators found on this host.${RESET}"
    echo ""
    echo -e "${YELLOW}Recommendations:${RESET}"
    echo "  - Schedule this script daily:  echo '0 7 * * * root bash /opt/scan-supply-chain.sh --output-json /var/log/sc-scan.json' | sudo tee /etc/cron.d/supply-chain-scan"
    echo "  - Run on all developer machines, build agents, and CI runners."
    echo "  - Pin exact package versions in lock files / requirements.txt."
    echo "  - Run: npm config set ignore-scripts true  in all CI/CD pipelines."
fi

echo ""
echo -e "${CYAN}Live data sources:${RESET}"
echo "  OSV.dev bulk zip  : https://storage.googleapis.com/osv-vulnerabilities/<eco>/all.zip"
echo "  OpenSSF mal-pkgs  : https://github.com/ossf/malicious-packages"
echo "  Socket tracker    : https://socket.dev/supply-chain-attacks/canistersprawl"
echo ""
echo "Report generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ── Optional JSON output ──────────────────────────────────────────────────────
# Pass everything via env vars so user-supplied paths/strings can never break
# out of the Python source code below.
if [[ -n "$OUTPUT_JSON" ]]; then
    # Build findings JSON safely
    findings_json=$(printf '%s\0' "${FINDINGS[@]:-}" | python3 -c '
import json, sys
items = sys.stdin.buffer.read().split(b"\0")
items = [i.decode("utf-8", errors="replace") for i in items if i]
print(json.dumps(items))
' 2>/dev/null || echo "[]")

    HOSTNAME_VAL="$(hostname)" \
    USER_VAL="$(whoami)" \
    SCANNED_VAL="$SCANNED" \
    FOUND_VAL="$FOUND" \
    IOC_SIZE_VAL="${#MALICIOUS_PKGS[@]}" \
    LIVE_FEED_VAL="$([[ $SKIP_LIVE_FEED -eq 0 ]] && echo true || echo false)" \
    FINDINGS_JSON_VAL="$findings_json" \
    OUTPUT_PATH_VAL="$OUTPUT_JSON" \
    python3 - <<'PY'
import json, os
from datetime import datetime, timezone
report = {
    "timestamp":        datetime.now(timezone.utc).isoformat(),
    "hostname":         os.environ["HOSTNAME_VAL"],
    "user":             os.environ["USER_VAL"],
    "total_checks":     int(os.environ["SCANNED_VAL"]),
    "findings_count":   int(os.environ["FOUND_VAL"]),
    "ioc_list_size":    int(os.environ["IOC_SIZE_VAL"]),
    "live_feed_pulled": os.environ["LIVE_FEED_VAL"] == "true",
    "findings":         json.loads(os.environ["FINDINGS_JSON_VAL"]),
}
out_path = os.environ["OUTPUT_PATH_VAL"]
with open(out_path, "w") as f:
    json.dump(report, f, indent=2)
print(f"JSON report written to: {out_path}")
PY
fi

# ── Cron setup hint ───────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}# To schedule daily at 07:00 UTC as root:${RESET}"
echo "echo '0 7 * * * root bash $(realpath "$0") --output-json /var/log/sc-scan.json' | sudo tee /etc/cron.d/supply-chain-scan"
