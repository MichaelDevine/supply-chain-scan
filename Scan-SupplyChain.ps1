#Requires -Version 5.1
<#
.SYNOPSIS
    Supply Chain Attack Scanner -- Live Feed + Historical IOCs   v2.5

    ⚠️ VIBE-CODED NOTICE: 
    This script was vibe-coded (heavily assisted by AI). It's been tested 
    and gets the job done, but please read through the code before running 
    it with Administrative privileges on your production machines!

.DESCRIPTION
    Pulls the latest malicious package data from:
      * OSV.dev bulk zip   (one HTTP request per ecosystem, parsed locally)
      * OpenSSF malicious-packages feed (cloned via git, parsed locally)
    Then cross-references everything installed on this machine, in Docker
    containers, and in local Docker images.

    The hardcoded list of recent high-profile IOCs (CanisterWorm,
    CanisterSprawl, Axios, LiteLLM, dYdX, Bitwarden, etc.) is kept as a
    local fallback in case the live feeds are unreachable.

    PowerShell 7+ is recommended (5-10x faster JSON parsing); 5.1 works.

.PARAMETER SkipLiveFeed
    Skip the live OSV / OpenSSF feed pull (use hardcoded list only).

.PARAMETER OfflineOnly
    Alias for -SkipLiveFeed.

.PARAMETER OutputJson
    Path to write a JSON report file (optional). Useful for SIEM ingestion.

.PARAMETER GitHubToken
    Optional GitHub token to raise the unauthenticated rate limit
    (60/hour) to 5,000/hour. Falls back to $env:GITHUB_TOKEN if set.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Scan-SupplyChain.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Scan-SupplyChain.ps1 -SkipLiveFeed
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Scan-SupplyChain.ps1 -OutputJson C:\Logs\sc-scan.json
.EXAMPLE
    $env:GITHUB_TOKEN = 'ghp_...'; .\Scan-SupplyChain.ps1
.NOTES
    Run as Administrator for full coverage of all user profiles, Docker, and system directories.
#>

param(
    [switch]$SkipLiveFeed,
    [switch]$OfflineOnly,
    [string]$OutputJson  = "",
    [string]$GitHubToken = ""
)

if ($OfflineOnly) { $SkipLiveFeed = $true }

# IMPORTANT: We deliberately do NOT use Set-StrictMode -Version Latest because
# many OSV records lack optional fields (e.g. database_specific) and strict
# mode would throw on every property access -- those throws got swallowed by
# try/catch in the prior version, silently dropping valid records. We use
# Set-StrictMode -Version 2.0 instead (catches uninitialized var typos but
# allows missing object properties).
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'SilentlyContinue'

# Resolve GitHub token from parameter or environment
if (-not $GitHubToken -and $env:GITHUB_TOKEN) { $GitHubToken = $env:GITHUB_TOKEN }

# ── Console helpers ───────────────────────────────────────────────────────────
function Write-Header { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Hit    { param($m) Write-Host "[MATCH] $m" -ForegroundColor Red;   $script:Findings += $m; $script:Found++ }
function Write-OK     { param($m) Write-Host "[ok]    $m" -ForegroundColor Green }
function Write-Info   { param($m) Write-Host "[*]     $m" -ForegroundColor Cyan }
function Write-Warn   { param($m) Write-Host "[!]     $m" -ForegroundColor Yellow }

$script:Found    = 0
$script:Scanned  = 0
$script:Findings = @()

# ── Combined malicious package map (live feeds + hardcoded list) ──────────────
# Key = "ecosystem:pkgname", Value = string[] of bad versions ("*" = any)
$MaliciousPkgs = @{}

# ── Map OSV ecosystem names to our internal labels ────────────────────────────
$EcosystemMap = @{
    "npm"       = "npm";  "PyPI" = "PyPI"; "Go"  = "Go"
    "crates.io" = "Rust"; "Maven"= "Maven";"NuGet"= "NuGet"
    "Hex"       = "Hex";  "Pub"  = "Pub";  "RubyGems"="RubyGems"
}

# ── Validate package names against shell injection ────────────────────────────
function Test-SafePackageName {
    param([string]$Name)
    return $Name -match '^[@a-zA-Z0-9._/+-]+$'
}

function Merge-Pkg {
    param([string]$Eco, [string]$Name, [string[]]$Versions)
    if (-not $Eco -or -not $Name) { return }
    $key = "${Eco}:${Name}"
    if (-not $MaliciousPkgs.ContainsKey($key)) { $MaliciousPkgs[$key] = @() }
    if ($MaliciousPkgs[$key] -contains "*") { return }
    if ($Versions -contains "*") {
        $MaliciousPkgs[$key] = @("*")
    } else {
        # Trim each version, drop empties, dedupe
        $trimmed = $Versions | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $MaliciousPkgs[$key] = ($MaliciousPkgs[$key] + $trimmed) | Sort-Object -Unique
    }
}

# =============================================================================
#  SECTION 1 -- HARDCODED IOC LIST  (always applied, regardless of live feed)
# =============================================================================

$HardcodedIOCs = @(
    # ── CanisterWorm  (TeamPCP, March 20-23 2026) ─────────────────────────
    # NOTE: Initial Socket disclosure list (30 packages). JFrog later
    # identified 47+ in total -- live feed (OpenSSF/OSV) covers extras.
    @{ E="npm"; N="@emilgroup/api-agentv3";           V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-auth";              V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-biddingv2";         V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-biddingv3";         V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-blocksv2";          V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-couponsv2";         V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-couponsv3";         V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-dashboardv2";       V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-deliveriesv2";      V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-deliveriesv3";      V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-financev2";         V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-giftcardsv3";       V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-identitiesv3";      V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-inventoryv2";       V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-inventoryv3";       V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-logsv3";            V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-menuv2";            V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-menuv3";            V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-notificationsv3";   V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-ordersv2";          V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-ordersv3";          V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-paymentsv2";        V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-paymentsv3";        V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-productsv2";        V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-productsv3";        V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-reportingv3";       V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-restaurantsv2";     V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-restaurantsv3";     V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-usersv2";           V=@("1.0.1") }
    @{ E="npm"; N="@emilgroup/api-usersv3";           V=@("1.0.1") }
    @{ E="npm"; N="@teale.io/eslint-config";          V=@("1.8.11","1.8.12") }

    # ── CanisterSprawl  (TeamPCP, April 8-23 2026) ────────────────────────
    @{ E="npm"; N="@automagik/genie";                 V=@("4.260421.33","4.260421.34","4.260421.35","4.260421.36","4.260421.37","4.260421.38","4.260421.39","4.260421.40") }
    @{ E="npm"; N="pgserve";                          V=@("1.1.11","1.1.12","1.1.13","1.1.14") }
    @{ E="npm"; N="@fairwords/websocket";             V=@("1.0.38","1.0.39") }
    @{ E="npm"; N="@fairwords/loopback-connector-es"; V=@("1.4.3","1.4.4") }
    @{ E="npm"; N="@openwebconcept/design-tokens";    V=@("1.0.1","1.0.2","1.0.3") }
    @{ E="npm"; N="@openwebconcept/theme-owc";        V=@("1.0.1","1.0.2","1.0.3") }

    # ── Checkmarx / Bitwarden  (April 22 2026) ────────────────────────────
    @{ E="npm"; N="@bitwarden/cli";                   V=@("2026.4.0") }

    # ── Axios RAT  (TeamPCP, March 31 2026) ───────────────────────────────
    @{ E="npm"; N="axios";                            V=@("1.14.1","0.30.4") }
    @{ E="npm"; N="plain-crypto-js";                  V=@("*") }

    # ── dYdX  (January 2026) ──────────────────────────────────────────────
    @{ E="npm";  N="@dydxprotocol/v4-client-js";      V=@("3.4.1","1.22.1","1.15.2","1.0.31") }
    @{ E="PyPI"; N="dydx-v4-client";                  V=@("3.4.1","1.22.1","1.15.2","1.0.31") }

    # ── Asurion-impersonation  (April 1-8 2026, claimed red-team) ─────────
    @{ E="npm"; N="sbxapps";                          V=@("*") }
    @{ E="npm"; N="asurion-hub-web";                  V=@("*") }
    @{ E="npm"; N="soluto-home-web";                  V=@("*") }
    @{ E="npm"; N="asurion-core";                     V=@("*") }

    # ── Kubernetes-impersonation  (April 2026) ────────────────────────────
    @{ E="npm";  N="kube-health-tools";               V=@("*") }
    @{ E="PyPI"; N="kube-node-health";                V=@("*") }

    # ── LiteLLM  (TeamPCP, March 24 2026) ─────────────────────────────────
    @{ E="PyPI"; N="litellm";                         V=@("1.82.7","1.82.8") }

    # ── xinference  (April 22 2026) ───────────────────────────────────────
    @{ E="PyPI"; N="xinference";                      V=@("2.6.0","2.6.1","2.6.2") }

    # ── Docker images ─────────────────────────────────────────────────────
    @{ E="Docker"; N="checkmarx/kics";                V=@("*") }
)

foreach ($ioc in $HardcodedIOCs) {
    Merge-Pkg $ioc.E $ioc.N $ioc.V
}

# ── S1ngularity / Nx (August 26 2025) ───────────────────────────────────────
# Malicious npm releases used postinstall hooks to collect secrets and publish
# them into attacker-created GitHub repos named with "s1ngularity-repository".
Merge-Pkg "npm" "nx" @("21.5.0","20.9.0","20.10.0","21.6.0","20.11.0","21.7.0","21.8.0","20.12.0")
foreach ($pkg in @("@nx/devkit","@nx/js","@nx/workspace","@nx/node")) {
    Merge-Pkg "npm" $pkg @("21.5.0","20.9.0")
}
Merge-Pkg "npm" "@nx/eslint" @("21.5.0")
Merge-Pkg "npm" "@nx/key" @("3.2.0")
Merge-Pkg "npm" "@nx/enterprise-cloud" @("3.2.0")

# ── September 2025 npm crypto-theft + Shai-Hulud worm wave ──────────────────
# Curated high-signal subset of the CISA/Mend/Socket-reported npm incidents:
# massively downloaded packages, CrowdStrike packages, @ctrl/tinycolor family,
# and commonly observed Angular / NativeScript victims. Live feeds cover the
# long tail; this keeps offline mode useful without embedding a giant feed dump.
$HardcodedNpmVersionLines = @'
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
'@
foreach ($line in ($HardcodedNpmVersionLines -split "`n")) {
    $trimmedLine = $line.Trim()
    if (-not $trimmedLine -or $trimmedLine.StartsWith('#')) { continue }
    $parts = $trimmedLine -split '\|', 2
    if ($parts.Count -ne 2) { continue }
    $versions = $parts[1] -split '\s+' | Where-Object { $_ }
    Merge-Pkg "npm" $parts[0] $versions
}

# IOC artefacts left on disk by the worms
# NOTE: Linux paths are speculative on Windows hosts (only relevant if WSL or
# a Linux container ran the malicious package). Windows-native locations are
# checked separately.
$IOC_Files   = @(
    "$env:TEMP\pglog",
    "$env:TEMP\.pg_state",
    "$env:TEMP\inventory.txt",
    # Speculative Windows locations the worm might use
    "$env:APPDATA\sysmon\sysmon.py",
    "$env:LOCALAPPDATA\sysmon\sysmon.py"
)
$IOC_Scripts = @("env-compat.cjs","public.pem","sysmon.py","litellm_init.pth")

# IOC strings -- more specific than v2.0 to reduce false positives.
# Bare "pgmon" matches PostgreSQL pg_monitor role; we look for the systemd
# unit name and config-dir path instead.
# NOTE: Split strings with '+' to prevent the scanner from flagging itself.
$IOC_Strings = @(
    ('pkg-'+'telemetry'), ('pypi-'+'pth-exfil'),
    ('cjn37-'+'uyaaa-aaaac-qgnva-cai'),
    ('telemetry.'+'api-monitor.com'),
    ('audit.'+'checkmarx.cx'), ('scan.'+'aquasecurtiy.org'),
    ('models.'+'litellm.cloud'),
    ('pgmon.'+'service'), ('.config/'+'pgmon'),
    ('plain-'+'crypto-js'),
    ('s1ngularity-'+'repository'), ('Shai-'+'Hulud')
)
# Generic ICP canister regex -- catches new wave canister IDs the worm rotates to
$IOC_RegexICP = '[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-' + 'cai\.raw\.icp0\.io'

$IOC_Hashes = @{
    "c19c4574d09e60636425f9555d3b63e8cb5c9d63ceb1c982c35e5a310c97a839" = "env-compat.cjs (CanisterSprawl payload)"
    "834b6e5db5710b9308d0598978a0148a9dc832361f1fa0b7ad4343dcceba2812" = "public.pem (CanisterSprawl RSA key)"
}
$IOC_Hosts = @(
    ('telemetry.'+'api-monitor.com'), ('cjn37-'+'uyaaa-aaaac-qgnva-cai.raw.icp0.io'),
    ('audit.'+'checkmarx.cx'), ('scan.'+'aquasecurtiy.org'), ('models.'+'litellm.cloud')
)

# Malicious-keyword regex filter -- uses WORD BOUNDARIES (\b) to avoid the
# substring false-positive trap. Without \b, "rat" matches "rate", "operation",
# "integration"; "compromised" matches summaries describing victims, etc.
#
# Anchored to whole words/phrases. We deliberately keep this list tight - it's
# a SUMMARY-text fallback only. The strongest signals (MAL-* IDs and
# database_specific.malicious=true) are checked first.
$MalKeywordPatterns = @(
    'malicious[-\s]?package',
    'malicious\s+(?:npm|pypi|package|version|release)',
    'malware',
    'backdoor',
    'crypto[-\s]?stealer',
    'info[-\s]?stealer',
    'credential[-\s]?stealer',
    'credential[-\s]?stealing',
    'data[-\s]?exfiltration',
    'exfiltrates?',
    'typosquat\w*',
    'dependency[-\s]?confusion',
    'account\s+takeover',
    'package\s+takeover',
    'compromised\s+(?:package|version|release|maintainer|account)',
    'package\s+(?:was|is|been)\s+compromised',
    'hijack(?:ed|ing)\s+(?:package|version|release|account)',
    'supply[-\s]chain\s+(?:attack|compromise)'
)
$MalKeywordRegex = '(?i)\b(' + ($MalKeywordPatterns -join '|') + ')\b'

# =============================================================================
#  SECTION 2 -- LIVE FEED PULL
# =============================================================================

Write-Host ""
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host "|  Supply Chain Attack Scanner  v2.5                              |" -ForegroundColor Cyan
Write-Host "|  Live: OSV.dev bulk + OpenSSF mal-pkgs + Historical IOCs        |" -ForegroundColor Cyan
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host "Host : $env:COMPUTERNAME"
Write-Host "User : $env:USERDOMAIN\$env:USERNAME"
Write-Host "Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Write-Host "PS   : $($PSVersionTable.PSVersion)$(if ($PSVersionTable.PSVersion.Major -lt 7) { ' (PS 7+ recommended for performance)' })"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Admin: $isAdmin$(if (-not $isAdmin) { ' -- re-run as Administrator for full coverage' })"

if (-not $SkipLiveFeed) {
    Write-Header "PULLING LIVE MALICIOUS PACKAGE FEEDS"

    # ── 2a. OpenSSF malicious-packages via shallow git clone ──────────────────
    # A shallow git clone is dramatically faster than 2,000 sequential REST
    # calls and not subject to the 60/hour unauthenticated rate limit.
    Write-Info "Fetching OpenSSF malicious-packages..."
    $ossf_count   = 0
    $ossf_records = 0
    $ossf_sw      = [System.Diagnostics.Stopwatch]::StartNew()

    $gitAvailable = $null -ne (Get-Command git -ErrorAction SilentlyContinue)
    $useGit       = $gitAvailable
    $tmpRepo      = Join-Path $env:TEMP "ossf-malicious-packages-$(Get-Random)"

    if ($useGit) {
        Write-Info "  Cloning ossf/malicious-packages (shallow, blob-filter)..."
        & git clone --quiet --depth 1 --filter=blob:none --no-checkout `
            "https://github.com/ossf/malicious-packages.git" $tmpRepo 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmpRepo)) {
            Write-Warn "  git clone failed; falling back to GitHub REST API."
            $useGit = $false
        } else {
            Push-Location $tmpRepo
            & git sparse-checkout init --cone 2>$null
            & git sparse-checkout set osv/malicious 2>$null
            & git checkout --quiet 2>$null
            Pop-Location
        }
    } else {
        Write-Warn "  git not installed; using GitHub REST API (slower, rate-limited)."
    }

    if ($useGit -and (Test-Path (Join-Path $tmpRepo "osv/malicious"))) {
        Write-Info "  Parsing OSV records from clone..."
        $osvDir = Join-Path $tmpRepo "osv/malicious"
        $allFiles = @(Get-ChildItem $osvDir -Recurse -Filter "*.json" -File -ErrorAction SilentlyContinue)
        $total = $allFiles.Count
        $i = 0
        foreach ($file in $allFiles) {
            $i++
            if ($i % 100 -eq 0) {
                $elapsed = [int]$ossf_sw.Elapsed.TotalSeconds
                Write-Host "  [*]  OpenSSF: $i/$total files parsed ($elapsed`s elapsed)..." -ForegroundColor Cyan
            }
            try {
                $rec = Get-Content $file.FullName -Raw | ConvertFrom-Json
                $ossf_records++
                # OpenSSF malicious-packages should all have MAL- IDs but we
                # check defensively in case the feed structure changes.
                $rec_id = if ($rec.PSObject.Properties.Name -contains 'id') { [string]$rec.id } else { '' }
                $is_mal_record = $rec_id -match '^MAL-'
                if ($rec.PSObject.Properties.Name -contains 'affected') {
                    foreach ($aff in $rec.affected) {
                        if (-not ($aff.PSObject.Properties.Name -contains 'package')) { continue }
                        $pkg = $aff.package
                        if (-not $pkg) { continue }
                        $eco_raw = if ($pkg.PSObject.Properties.Name -contains 'ecosystem') { [string]$pkg.ecosystem } else { '' }
                        $name    = if ($pkg.PSObject.Properties.Name -contains 'name')      { [string]$pkg.name }      else { '' }
                        $eco     = $EcosystemMap[$eco_raw]
                        if (-not $eco) { $eco = $eco_raw }
                        $hasVersions = ($aff.PSObject.Properties.Name -contains 'versions') -and $aff.versions -and (@($aff.versions).Count -gt 0)
                        if ($hasVersions) {
                            $vers = [string[]]$aff.versions
                        } elseif ($is_mal_record) {
                            $vers = @("*")
                        } else {
                            continue
                        }
                        if ($name) {
                            Merge-Pkg $eco $name $vers
                            $ossf_count++
                        }
                    }
                }
            } catch { }
        }
        # Final progress
        if ($total -gt 0 -and ($i % 100 -ne 0)) {
            $elapsed = [int]$ossf_sw.Elapsed.TotalSeconds
            Write-Host "  [*]  OpenSSF: $i/$total files parsed (done, $elapsed`s)" -ForegroundColor Cyan
        }
        Write-Info "  OpenSSF feed done: $ossf_records IOC records, $ossf_count package-version entries collected in $([int]$ossf_sw.Elapsed.TotalSeconds)s."
        Remove-Item $tmpRepo -Recurse -Force -ErrorAction SilentlyContinue
    } elseif (-not $useGit) {
        # REST API fallback (rate-limited, slow)
        try {
            $headers = @{ "User-Agent" = "SupplyChainScanner/2.5"; "Accept" = "application/vnd.github+json" }
            if ($GitHubToken) { $headers["Authorization"] = "Bearer $GitHubToken" }
            $tree = Invoke-RestMethod -Uri "https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1" `
                                      -Headers $headers -TimeoutSec 30
            $osv_files = $tree.tree |
                         Where-Object { $_.path -like "osv/malicious/*.json" } |
                         Select-Object -Last 2000
            $ossf_total = $osv_files.Count
            Write-Info "  Fetching $ossf_total records via REST (progress every 100)..."
            $raw_base = "https://raw.githubusercontent.com/ossf/malicious-packages/main/"
            $ossf_i   = 0
            foreach ($file in $osv_files) {
                $ossf_i++
                try {
                    $rec = Invoke-RestMethod -Uri "$raw_base$($file.path)" -Headers $headers -TimeoutSec 10
                    $ossf_records++
                    $rec_id = if ($rec.PSObject.Properties.Name -contains 'id') { [string]$rec.id } else { '' }
                    $is_mal_record = $rec_id -match '^MAL-'
                    if ($rec.PSObject.Properties.Name -contains 'affected') {
                        foreach ($aff in $rec.affected) {
                            if (-not ($aff.PSObject.Properties.Name -contains 'package')) { continue }
                            $pkg = $aff.package
                            if (-not $pkg) { continue }
                            $eco_raw = if ($pkg.PSObject.Properties.Name -contains 'ecosystem') { [string]$pkg.ecosystem } else { '' }
                            $name    = if ($pkg.PSObject.Properties.Name -contains 'name')      { [string]$pkg.name }      else { '' }
                            $eco     = $EcosystemMap[$eco_raw]
                            if (-not $eco) { $eco = $eco_raw }
                            $hasVersions = ($aff.PSObject.Properties.Name -contains 'versions') -and $aff.versions -and (@($aff.versions).Count -gt 0)
                            if ($hasVersions) {
                                $vers = [string[]]$aff.versions
                            } elseif ($is_mal_record) {
                                $vers = @("*")
                            } else {
                                continue
                            }
                            if ($name) {
                                Merge-Pkg $eco $name $vers
                                $ossf_count++
                            }
                        }
                    }
                } catch { }
                if ($ossf_i % 100 -eq 0) {
                    $elapsed = [int]$ossf_sw.Elapsed.TotalSeconds
                    Write-Host "  [*]  OpenSSF (REST): $ossf_i/$ossf_total fetched ($elapsed`s elapsed)..." -ForegroundColor Cyan
                }
            }
            if ($ossf_total -gt 0 -and ($ossf_i % 100 -ne 0)) {
                $elapsed = [int]$ossf_sw.Elapsed.TotalSeconds
                Write-Host "  [*]  OpenSSF (REST): $ossf_i/$ossf_total fetched (done, $elapsed`s)" -ForegroundColor Cyan
            }
            Write-Info "  OpenSSF feed (REST) done: $ossf_records IOC records, $ossf_count entries collected in $([int]$ossf_sw.Elapsed.TotalSeconds)s."
        } catch {
            Write-Warn "  Could not reach OpenSSF GitHub feed: $_"
        }
    }

    # ── 2b. OSV bulk zip (one HTTP request per ecosystem, parsed locally) ─────
    Write-Info "Fetching OSV bulk zips (npm + PyPI) -- one download each, parsed locally..."
    $osv_count   = 0
    $osv_records = 0
    $osv_sw      = [System.Diagnostics.Stopwatch]::StartNew()
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    foreach ($eco in @("npm","PyPI")) {
        $zip_url  = "https://storage.googleapis.com/osv-vulnerabilities/$eco/all.zip"
        $zip_path = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "osv_${eco}_all.zip")
        Write-Info "  Downloading $eco bulk zip (~30-80 MB)..."
        $dlSw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            # Use System.Net.WebClient for slightly faster + simpler download.
            # Invoke-WebRequest in PS 5.1 has no progress unless interactive.
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent","SupplyChainScanner/2.5")
            $wc.DownloadFile($zip_url, $zip_path)
            $wc.Dispose()
            Write-Info "    Downloaded $eco zip in $([int]$dlSw.Elapsed.TotalSeconds)s ($([math]::Round((Get-Item $zip_path).Length/1MB,1)) MB)."
        } catch {
            Write-Warn "  Could not download $eco bulk zip -- skipping."
            continue
        }
        Write-Info "  Scanning $eco records locally..."
        $eco_count   = 0
        $eco_records = 0
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($zip_path)
            $entries = $zip.Entries
            $total   = $entries.Count
            $i       = 0
            foreach ($entry in $entries) {
                $i++
                if ($i % 1000 -eq 0) {
                    $elapsed = [int]$osv_sw.Elapsed.TotalSeconds
                    Write-Host "  [*]  OSV ${eco}: $i/$total records scanned, $eco_records IOCs collected ($elapsed`s)..." -ForegroundColor Cyan
                }
                $rec = $null
                try {
                    $stream = $entry.Open()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $jsonText = $reader.ReadToEnd()
                    $reader.Close(); $stream.Close()
                    $rec = $jsonText | ConvertFrom-Json
                } catch { continue }
                if (-not $rec) { continue }

                $rec_id  = if ($rec.PSObject.Properties.Name -contains 'id')      { [string]$rec.id }      else { '' }
                $summary = if ($rec.PSObject.Properties.Name -contains 'summary') { [string]$rec.summary } else { '' }
                $db_spec = if ($rec.PSObject.Properties.Name -contains 'database_specific') { $rec.database_specific } else { $null }
                $is_mal  = $false
                if ($rec_id -match "^MAL-") { $is_mal = $true }
                elseif ($db_spec -and ($db_spec.PSObject.Properties.Name -contains 'malicious') -and $db_spec.malicious -eq $true) {
                    $is_mal = $true
                }
                elseif ($summary -and ($summary -match $MalKeywordRegex)) {
                    $is_mal = $true
                }
                if (-not $is_mal) { continue }

                $eco_records++
                if (-not ($rec.PSObject.Properties.Name -contains 'affected')) { continue }
                foreach ($aff in $rec.affected) {
                    if (-not ($aff.PSObject.Properties.Name -contains 'package')) { continue }
                    $pkg = $aff.package
                    if (-not $pkg) { continue }
                    $pkg_eco_raw = if ($pkg.PSObject.Properties.Name -contains 'ecosystem') { [string]$pkg.ecosystem } else { '' }
                    $pkg_name    = if ($pkg.PSObject.Properties.Name -contains 'name')      { [string]$pkg.name }      else { '' }
                    $pkg_eco     = $EcosystemMap[$pkg_eco_raw]
                    if (-not $pkg_eco) { $pkg_eco = $pkg_eco_raw }
                    $hasVersions = ($aff.PSObject.Properties.Name -contains 'versions') -and $aff.versions -and (@($aff.versions).Count -gt 0)
                    if ($hasVersions) {
                        $pkg_vers = [string[]]$aff.versions
                    } elseif ($rec_id -match '^MAL-') {
                        # MAL- records with no enumerated versions = the entire
                        # malicious package is bad. Wildcard is correct here.
                        $pkg_vers = @("*")
                    } else {
                        # CVE/GHSA-style record without versions[] uses ranges instead.
                        # We can't accurately match exact versions from ranges in this
                        # script; skipping prevents the false-positive cascade where
                        # every CVE on a popular package marks all versions as bad.
                        continue
                    }
                    if ($pkg_name) {
                        Merge-Pkg $pkg_eco $pkg_name $pkg_vers
                        $eco_count++
                    }
                }
            }
            $zip.Dispose()
            # Final progress
            if ($total -gt 0 -and ($i % 1000 -ne 0)) {
                $elapsed = [int]$osv_sw.Elapsed.TotalSeconds
                Write-Host "  [*]  OSV ${eco}: $i/$total records scanned (done, $elapsed`s)" -ForegroundColor Cyan
            }
            Write-Info "  $eco : $eco_records IOC records added, $eco_count package-version entries collected."
            $osv_count   += $eco_count
            $osv_records += $eco_records
        } catch {
            Write-Warn "  Error scanning $eco zip: $_"
        } finally {
            Remove-Item $zip_path -ErrorAction SilentlyContinue
        }
    }
    Write-Info "  OSV bulk scan done: $osv_records IOC records, $osv_count entries collected in $([int]$osv_sw.Elapsed.TotalSeconds)s."

    Write-Info "Live feeds complete. IOC list now contains $($MaliciousPkgs.Count) unique packages to scan for."
} else {
    Write-Warn "Live feed skipped (-SkipLiveFeed). Using hardcoded list only ($($MaliciousPkgs.Count) packages)."
}

# ── Convenience sub-maps by ecosystem ────────────────────────────────────────
$NpmTargets    = @{}
$PypiTargets   = @{}
$DockerTargets = @{}
foreach ($key in $MaliciousPkgs.Keys) {
    if ($key -like "npm:*")    { $NpmTargets[$key.Substring(4)]   = $MaliciousPkgs[$key] }
    if ($key -like "PyPI:*")   { $PypiTargets[$key.Substring(5)]  = $MaliciousPkgs[$key] }
    if ($key -like "Docker:*") { $DockerTargets[$key.Substring(7)]= $MaliciousPkgs[$key] }
}

# PyPI package names are case-insensitive and treat -, _, and . as equivalent.
# Keep a normalized target map whose values are version-set hashtables so both
# package and version checks are hash lookups.
$PypiCanonicalTargets = @{}
$PypiCanonicalNames   = @{}
foreach ($pkgName in $PypiTargets.Keys) {
    $canonical = ($pkgName.ToLower() -replace '[-_.]+', '-')
    if (-not $PypiCanonicalTargets.ContainsKey($canonical)) {
        $PypiCanonicalTargets[$canonical] = @{ Any = $false; Versions = @{} }
        $PypiCanonicalNames[$canonical] = $pkgName
    }
    if ($PypiTargets[$pkgName] -contains "*") {
        $PypiCanonicalTargets[$canonical].Any = $true
        $PypiCanonicalTargets[$canonical].Versions.Clear()
    } else {
        if ($PypiCanonicalTargets[$canonical].Any) { continue }
        foreach ($version in $PypiTargets[$pkgName]) {
            $trimmedVersion = $version.Trim()
            if ($trimmedVersion) { $PypiCanonicalTargets[$canonical].Versions[$trimmedVersion] = $true }
        }
    }
}
Write-Info "IOC breakdown -- npm: $($NpmTargets.Count)  PyPI: $($PypiTargets.Count)  Docker: $($DockerTargets.Count)"

# =============================================================================
#  HELPER FUNCTIONS
# =============================================================================

function Test-BadVersion {
    param([string]$Version, [string[]]$BadVersions)
    if (-not $Version) { return $false }
    $v = $Version.Trim()
    return ($BadVersions -contains "*") -or ($BadVersions -contains $v)
}

function Test-BadPypiVersion {
    param([string]$Version, [hashtable]$Target)
    if (-not $Version -or -not $Target) { return $false }
    if ($Target.Any) { return $true }
    return $Target.Versions.ContainsKey($Version.Trim())
}

function Get-FileSHA256 {
    param([string]$Path)
    try { (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLower() } catch { "" }
}

# Fast package.json reader using regex -- 5-10x faster than ConvertFrom-Json
# on PS 5.1 for large monorepos. We only need name + version.
function Read-PackageJsonFast {
    param([string]$Path)
    try {
        $content = Get-Content $Path -Raw -ErrorAction Stop
        $name    = ""
        $version = ""
        $private = $false
        $hasTags = $false
        if ($content -match '"name"\s*:\s*"([^"]+)"')    { $name    = $matches[1] }
        if ($content -match '"version"\s*:\s*"([^"]+)"') { $version = $matches[1] }
        if ($content -match '"private"\s*:\s*true')      { $private = $true }
        if ($content -match '"_(id|integrity|resolved)"\s*:') { $hasTags = $true }
        return @{ Name = $name; Version = $version; Private = $private; HasNpmTags = $hasTags }
    } catch { return $null }
}

# PEP 503 normalization for PyPI package names
function Get-PyPiCanonical {
    param([string]$Name)
    return ($Name.ToLower() -replace '[-_.]+', '-')
}

function Read-DistInfoMetadataFast {
    param([string]$DistInfoPath)
    $metadataPath = Join-Path $DistInfoPath "METADATA"
    if (Test-Path $metadataPath) {
        try {
            $name = ""
            $version = ""
            foreach ($line in (Get-Content $metadataPath -TotalCount 80 -ErrorAction Stop)) {
                if (-not $name -and $line -match '^Name:\s*(.+)$') { $name = $matches[1].Trim() }
                elseif (-not $version -and $line -match '^Version:\s*(.+)$') { $version = $matches[1].Trim() }
                if ($name -and $version) { return @{ Name = $name; Version = $version } }
            }
        } catch { }
    }

    if ((Split-Path $DistInfoPath -Leaf) -match '^(?<name>.+)-(?<version>[^-]+)\.dist-info$') {
        return @{ Name = $matches['name']; Version = $matches['version'] }
    }
    return $null
}

# Get-ChildItem wrapper that filters reparse points (junctions to other users'
# profiles, mounted drives, etc.) to avoid double-scanning.
function Get-ChildItemSafe {
    param([string]$Path, [string]$Filter, [int]$Depth = 12)
    Get-ChildItem -Path $Path -Filter $Filter -Recurse -Depth $Depth `
                  -ErrorAction SilentlyContinue -Force `
                  -Attributes !ReparsePoint
}

# Common search roots -- wrapped in @() so $null doesn't propagate as scalar.
# If the user is C:\Users\mike, scan C:\Users. Also scan common package/tool
# locations on the system drive without recursively walking the whole drive.
$SystemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
$SearchRoots = @(@(
    $env:USERPROFILE,$env:APPDATA,$env:LOCALAPPDATA,
    "${SystemDrive}\Users","${SystemDrive}\Program Files","${SystemDrive}\Program Files (x86)",
    "${SystemDrive}\ProgramData","${SystemDrive}\src","${SystemDrive}\code",
    "${SystemDrive}\projects","${SystemDrive}\dev","${SystemDrive}\workspace",
    "${SystemDrive}\tools","${SystemDrive}\opt"
) | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)

# Python-only roots for narrower dist-info / .pth scans (vs. global SearchRoots)
$PythonRoots = @(@(
    "$env:LOCALAPPDATA\Programs\Python",
    "$env:APPDATA\Python",
    "$env:LOCALAPPDATA\uv",
    "${SystemDrive}\Python*",
    "${SystemDrive}\Users\*\AppData\Local\Programs\Python",
    "${SystemDrive}\Users\*\AppData\Local\uv",
    "${SystemDrive}\ProgramData\Anaconda3","${SystemDrive}\ProgramData\miniconda3",
    "${SystemDrive}\tools\miniconda3","${SystemDrive}\tools\Anaconda3"
) | ForEach-Object { Resolve-Path $_ -ErrorAction SilentlyContinue } |
    ForEach-Object { $_.Path } | Where-Object { $_ } | Sort-Object -Unique)

Write-Info "Discovering Python venv/site-packages roots under: $($SearchRoots -join ', ')"
$DiscoveredPythonRoots = @(foreach ($root in $SearchRoots) {
    Get-ChildItemSafe -Path $root -Filter "pyvenv.cfg" -Depth 8 |
        Where-Object { $_.FullName -notmatch '\\(node_modules|\.git)\\' } |
        ForEach-Object { $_.DirectoryName }
    Get-ChildItemSafe -Path $root -Filter "site-packages" -Depth 10 |
        Where-Object { $_.PSIsContainer -and $_.FullName -notmatch '\\(node_modules|\.git)\\' } |
        ForEach-Object { $_.FullName }
})
$PythonRoots = @(($PythonRoots + $DiscoveredPythonRoots) |
    Where-Object { $_ -and (Test-Path $_) } |
    Sort-Object -Unique)
Write-Info "  Python scan roots: $($PythonRoots.Count)"

function Write-ScanPaths {
    Write-Header "LOCAL SCAN PATHS"
    Write-Info "npm / filesystem roots ($($SearchRoots.Count)):"
    foreach ($path in $SearchRoots) { Write-Host "  - $path" }
    Write-Info "Python venv/site-packages roots ($($PythonRoots.Count)):"
    foreach ($path in $PythonRoots) { Write-Host "  - $path" }
}

# =============================================================================
#  SECTION 3 -- IOC FILE / PERSISTENCE CHECK
# =============================================================================

Write-Host ""
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-Host "|  Now scanning this system against the IOC list collected above   |" -ForegroundColor Cyan
Write-Host "|  Any [MATCH] lines from this point forward indicate findings on  |" -ForegroundColor Cyan
Write-Host "|  YOUR system, not just IOC list contents.                        |" -ForegroundColor Cyan
Write-Host "+==================================================================+" -ForegroundColor Cyan
Write-ScanPaths

Write-Header "IOC FILES AND PERSISTENCE ARTEFACTS"
foreach ($f in $IOC_Files) {
    $script:Scanned++
    if (Test-Path $f) { Write-Hit "IOC file: $f" } else { Write-OK "Not present: $f" }
}

# litellm_init.pth -- restricted to known Python roots (was: SearchRoots)
$script:Scanned++
foreach ($pyroot in $PythonRoots) {
    if (-not (Test-Path $pyroot)) { continue }
    Get-ChildItemSafe -Path $pyroot -Filter "litellm_init.pth" -Depth 8 |
        Select-Object -First 5 |
        ForEach-Object { Write-Hit "LiteLLM .pth persistence: $($_.FullName)" }
}

# =============================================================================
#  SECTION 4 -- npm PACKAGE SCAN
# =============================================================================

Write-Header "npm PACKAGE SCAN  ($($NpmTargets.Count) packages in IOC list)"
Write-Info "Collecting package.json files (depth <= 12)..."
$AllPackageJsons = @(foreach ($root in $SearchRoots) {
    Get-ChildItemSafe -Path $root -Filter "package.json" -Depth 12 |
        Where-Object { $_.FullName -notmatch '\\node_modules\\.*\\node_modules\\' }
})
Write-Info "Inspecting $($AllPackageJsons.Count) package.json files..."

foreach ($pj in $AllPackageJsons) {
    $info = Read-PackageJsonFast $pj.FullName
    if (-not $info -or -not $info.Name) { continue }

    # False positive mitigation: internal source folders vs installed dependencies
    if ($info.Private) { continue }
    if ($pj.FullName -notmatch '\\node_modules\\' -and -not $info.HasNpmTags) { continue }

    if ($NpmTargets.ContainsKey($info.Name)) {
        $script:Scanned++
        if (Test-BadVersion $info.Version $NpmTargets[$info.Name]) {
            Write-Hit "npm: $($info.Name)@$($info.Version) -- MALICIOUS at $($pj.DirectoryName)"
        } else {
            Write-OK  "npm: $($info.Name)@$($info.Version) -- version OK"
        }
    }
}

# Lock file check
Write-Info "Checking lock files for malicious injected dependencies..."
foreach ($root in $SearchRoots) {
    foreach ($lockFilter in @("package-lock.json","yarn.lock")) {
        Get-ChildItemSafe -Path $root -Filter $lockFilter -Depth 10 |
        ForEach-Object {
            $script:Scanned++
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match 'plain-crypto-js|"axios": "1\.14\.1"|"axios": "0\.30\.4"') {
                Write-Hit "Lock file contains malicious Axios/plain-crypto-js: $($_.FullName)"
            }
        }
    }
}

# =============================================================================
#  SECTION 5 -- PyPI PACKAGE SCAN
# =============================================================================

Write-Header "PyPI PACKAGE SCAN  ($($PypiTargets.Count) packages in IOC list)"
Write-Info "Building installed PyPI package inventory..."
$PypiInstalled = @{}

$pipAvailable = $null -ne (Get-Command pip -ErrorAction SilentlyContinue)
if ($pipAvailable) {
    Write-Info "  Reading active pip environment with 'pip list --format=freeze'..."
    $pipOut = pip list --format=freeze 2>$null
    $pipLines = if ($pipOut -is [string]) { $pipOut -split "`r?`n" } else { @($pipOut) }
    $pipCount = 0
    foreach ($line in $pipLines) {
        if ($line -notmatch '^([^=\s]+)==(.+)$') { continue }
        $name = $matches[1].Trim()
        $version = $matches[2].Trim()
        if (-not $name -or -not $version) { continue }
        $canonical = Get-PyPiCanonical $name
        $recordKey = "pip|$canonical|$version"
        if (-not $PypiInstalled.ContainsKey($recordKey)) {
            $PypiInstalled[$recordKey] = @{ Name = $name; Version = $version; Source = "active pip environment" }
            $pipCount++
        }
    }
    Write-Info "  Active pip inventory: $pipCount package(s)."
} else {
    Write-Warn "  pip command not found; using .dist-info filesystem inventory only."
}

Write-Info "  Collecting .dist-info directories under $($PythonRoots.Count) Python root(s)..."
$distInfoCount = 0
$rootIndex = 0
foreach ($base in $PythonRoots) {
    $rootIndex++
    if (-not (Test-Path $base)) { continue }
    Write-Info "    [$rootIndex/$($PythonRoots.Count)] $base"
    Get-ChildItemSafe -Path $base -Filter "*.dist-info" -Depth 10 |
    Where-Object { $_.PSIsContainer } |
    ForEach-Object {
        $metadata = Read-DistInfoMetadataFast $_.FullName
        if (-not $metadata -or -not $metadata.Name -or -not $metadata.Version) { return }
        $canonical = Get-PyPiCanonical $metadata.Name
        $recordKey = "dist|$canonical|$($metadata.Version)|$($_.FullName)"
        if (-not $PypiInstalled.ContainsKey($recordKey)) {
            $PypiInstalled[$recordKey] = @{ Name = $metadata.Name; Version = $metadata.Version; Source = $_.FullName }
            $distInfoCount++
        }
    }
}
Write-Info "  .dist-info inventory: $distInfoCount package record(s)."
Write-Info "Cross-checking $($PypiInstalled.Count) installed PyPI package record(s) against $($PypiCanonicalTargets.Count) normalized IOC package name(s)..."

$pyMatches = 0
foreach ($record in $PypiInstalled.Values) {
    $canonical = Get-PyPiCanonical $record.Name
    if (-not $PypiCanonicalTargets.ContainsKey($canonical)) { continue }
    $script:Scanned++
    $displayName = $PypiCanonicalNames[$canonical]
    $version = [string]$record.Version
    if (Test-BadPypiVersion $version $PypiCanonicalTargets[$canonical]) {
        Write-Hit "PyPI: $($record.Name)==$version -- MALICIOUS at $($record.Source)"
        $pyMatches++
    } else {
        Write-OK "PyPI: $($record.Name)==$version -- OK (matched IOC package '$displayName')"
    }
}
Write-Info "PyPI scan complete: $($PypiInstalled.Count) installed package record(s), $pyMatches malicious version match(es)."

# =============================================================================
#  SECTION 6 -- DOCKER SCAN
# =============================================================================

Write-Header "DOCKER SCAN"
$dockerAvailable = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
$dockerRunning   = $false
if ($dockerAvailable) {
    & docker info 2>$null | Out-Null
    $dockerRunning = ($LASTEXITCODE -eq 0)
}

if ($dockerAvailable -and $dockerRunning) {
    Write-Info "Docker found and reachable."

    # 6a. Flagged images -- use -SimpleMatch (fixed string) so dots aren't regex
    foreach ($img in $DockerTargets.Keys) {
        $script:Scanned++
        $hits = docker images --format "{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}" 2>$null |
                Select-String -SimpleMatch $img
        if ($hits) {
            foreach ($h in $hits) { Write-Hit "Docker image $($h.Line) -- flagged as compromised." }
        } else {
            Write-OK "Not present: $img"
        }
    }

    # 6b. Image layer history heuristic
    Write-Info "Checking image build histories..."
    $allImageIds = @(docker images -q 2>$null | Sort-Object -Unique)
    foreach ($iid in $allImageIds) {
        if (-not $iid) { continue }
        $iname = (docker images --format "{{.Repository}}:{{.Tag}}" --filter "id=$iid" 2>$null | Select-Object -First 1)
        $hist  = docker history --no-trunc $iid 2>$null
        $script:Scanned++
        if ($hist -match "pgserve|automagik|emilgroup|pgmon\.service|check-env\.js|litellm.*1\.82|xinference.*2\.6|axios.*1\.14\.1|plain-crypto-js") {
            Write-Hit "Docker image ${iname} ($iid): suspicious layer references"
        }
    }

    # 6c. Running container scan -- uses bulk docker exec calls, not per-IOC.
    # Old approach: foreach IOC pkg -> docker exec find. With 200K IOCs that's
    # 200K * ~100ms = ~6 hours per container. New approach: single bulk listing
    # per container, then in-memory hash lookup.
    Write-Info "Scanning running containers..."
    $containers = @(docker ps -q 2>$null | Where-Object { $_ })
    if ($containers.Count -eq 0) {
        Write-Info "  No running containers."
    }
    $cidx = 0
    foreach ($cid in $containers) {
        $cidx++
        if (-not $cid) { continue }
        $cname = (docker inspect --format "{{.Name}}" $cid 2>$null) -replace '^/',''
        Write-Info "  [$cidx/$($containers.Count)] Container: $cname ($cid)"

        # ── IOC files (3 quick checks) ─────────────────────────────────────
        foreach ($ioc in @("/tmp/pglog","/tmp/.pg_state","/root/.config/sysmon/sysmon.py")) {
            $script:Scanned++
            $exists = docker exec $cid sh -c 'test -e "$1" && echo yes' _ $ioc 2>$null
            if ($exists -eq "yes") { Write-Hit "Container ${cname}: IOC file $ioc" }
        }

        # ── pgmon.service systemd unit ─────────────────────────────────────
        $script:Scanned++
        $pgmonFind = docker exec $cid sh -c 'find /etc/systemd /root/.config/systemd 2>/dev/null | grep -F pgmon.service' 2>$null
        if ($pgmonFind) { Write-Hit "Container ${cname}: pgmon.service systemd unit present" }

        # ── npm packages: ONE find call, then hashtable lookup per result ──
        Write-Info "    Listing npm packages..."
        $npmSw = [System.Diagnostics.Stopwatch]::StartNew()
        # Single docker exec: list every node_modules/<name>/package.json plus
        # its version, separated by tabs. Limit total output to keep Docker exec
        # responsive on huge containers.
        $npmListScript = @'
find / -maxdepth 14 -type f -path "*/node_modules/*/package.json" \
       ! -path "*/node_modules/*/node_modules/*" 2>/dev/null | head -20000 | \
while read -r pj; do
    name=$(awk -v RS=, -v FS=':' '/"name"/{gsub(/[ "\t]/,"",$2); print $2; exit}' "$pj" 2>/dev/null)
    ver=$(awk -v RS=, -v FS=':' '/"version"/{gsub(/[ "\t]/,"",$2); print $2; exit}' "$pj" 2>/dev/null)
    [ -n "$name" ] && [ -n "$ver" ] && printf '%s\t%s\t%s\n' "$name" "$ver" "$pj"
done
'@
        $npmList = docker exec $cid sh -c $npmListScript 2>$null
        $npmLines = if ($npmList -is [string]) { $npmList -split "`r?`n" } else { @($npmList) }
        $npmLines = @($npmLines | Where-Object { $_ })
        Write-Info "    Found $($npmLines.Count) npm package(s) in $([int]$npmSw.Elapsed.TotalSeconds)s. Cross-checking..."

        $npmHits = 0
        $npmChecked = 0
        foreach ($line in $npmLines) {
            $parts = $line -split "`t", 3
            if ($parts.Count -lt 3) { continue }
            $pname = $parts[0].Trim()
            $pver  = $parts[1].Trim()
            $ppath = $parts[2].Trim()
            if (-not $pname -or -not $pver) { continue }
            $npmChecked++
            # Hash lookup (case-sensitive -- npm package names are case-sensitive)
            if ($NpmTargets.ContainsKey($pname)) {
                $script:Scanned++
                if (Test-BadVersion $pver $NpmTargets[$pname]) {
                    Write-Hit "Container ${cname}: npm $pname@$pver -- MALICIOUS at $ppath"
                    $npmHits++
                }
                # Don't print "OK" lines for every single non-match -- far too noisy
                # in containers with thousands of packages. Counts shown in summary.
            }
        }
        Write-Info "    npm scan: $npmChecked packages checked, $npmHits matches."

        # ── PyPI packages: ONE pip list call, then hashtable lookup ────────
        Write-Info "    Listing PyPI packages..."
        $pyiSw = [System.Diagnostics.Stopwatch]::StartNew()
        # `pip list --format=freeze` outputs name==version per line.
        # Try python3 first, fall back to python.
        $pipListScript = @'
if command -v pip3 >/dev/null 2>&1; then
    pip3 list --format=freeze 2>/dev/null
elif command -v pip >/dev/null 2>&1; then
    pip list --format=freeze 2>/dev/null
fi
'@
        $pipList = docker exec $cid sh -c $pipListScript 2>$null
        $pipLines = if ($pipList -is [string]) { $pipList -split "`r?`n" } else { @($pipList) }
        $pipLines = @($pipLines | Where-Object { $_ -match '^[A-Za-z0-9_.-]+==' })
        Write-Info "    Found $($pipLines.Count) PyPI package(s) in $([int]$pyiSw.Elapsed.TotalSeconds)s. Cross-checking..."

        $pyiHits = 0
        $pyiChecked = 0
        foreach ($line in $pipLines) {
            $parts = $line -split '==', 2
            if ($parts.Count -lt 2) { continue }
            $pname = $parts[0].Trim()
            $pver  = $parts[1].Trim()
            if (-not $pname) { continue }
            $pyiChecked++
            # PyPI is case-insensitive AND hyphen/underscore-equivalent; normalise
            $pname_norm = ($pname.ToLower() -replace '[-_.]+', '-')
            $matchedKey = $null
            foreach ($k in $PypiTargets.Keys) {
                if (($k.ToLower() -replace '[-_.]+', '-') -eq $pname_norm) {
                    $matchedKey = $k; break
                }
            }
            if ($matchedKey) {
                $script:Scanned++
                if (Test-BadVersion $pver $PypiTargets[$matchedKey]) {
                    Write-Hit "Container ${cname}: PyPI $pname==$pver -- MALICIOUS!"
                    $pyiHits++
                }
            }
        }
        Write-Info "    PyPI scan: $pyiChecked packages checked, $pyiHits matches."
    }
} elseif ($dockerAvailable) {
    Write-Warn "Docker installed but daemon not reachable -- skipping container/image scan."
} else {
    Write-Warn "Docker not found -- skipping container/image scan."
}

# =============================================================================
#  SECTION 7 -- IOC SCRIPT / STRING / HASH SCANS
# =============================================================================

Write-Header "IOC SCRIPT FILES"
foreach ($iocScript in $IOC_Scripts) {
    $script:Scanned++
    foreach ($root in $SearchRoots) {
        Get-ChildItemSafe -Path $root -Filter $iocScript -Depth 12 |
            Select-Object -First 20 |
            ForEach-Object { Write-Hit "IOC script '$iocScript' at: $($_.FullName)" }
    }
}

Write-Header "IOC STRING SEARCH"
$scanExtensions = @{
    ".js" = $true; ".cjs" = $true; ".mjs" = $true; ".py" = $true; ".json" = $true
    ".npmrc" = $true; ".env" = $true; ".sh" = $true; ".yaml" = $true; ".yml" = $true
}
$scanExactNames = @{ ".npmrc" = $true; ".env" = $true }
$maxTextScanBytes = 2MB
$escapedIocStrings = $IOC_Strings | ForEach-Object { [regex]::Escape($_) }
$IOC_CombinedRegex = "(?i)(" + ($escapedIocStrings -join "|") + ")"
Write-Info "  Collecting candidate text files once per root (max $([int]($maxTextScanBytes / 1MB)) MB each)..."
$script:Scanned++

$textCandidates = New-Object System.Collections.Generic.List[object]
$seenTextCandidatePaths = @{}
foreach ($root in $SearchRoots) {
    Write-Info "    Inventorying text candidates under $root"
    $rootCount = 0
    Get-ChildItemSafe -Path $root -Filter "*" -Depth 12 |
    Where-Object {
        -not $_.PSIsContainer -and
        $_.Length -le $maxTextScanBytes -and
        ($scanExtensions.ContainsKey($_.Extension.ToLower()) -or $scanExactNames.ContainsKey($_.Name.ToLower())) -and
        $_.FullName -notmatch '(?i)[\/](Code[\/]User[\/](History|workspaceStorage)|node_modules|test-logs|\.git|\.vscode|\.cache|__pycache__|dist|build|coverage)[\/]' -and
        $_.Name -notmatch '^(?i)(scan-supply-chain\.sh|Scan-SupplyChain\.ps1)$'
    } |
    ForEach-Object {
        if (-not $seenTextCandidatePaths.ContainsKey($_.FullName)) {
            $seenTextCandidatePaths[$_.FullName] = $true
            $textCandidates.Add($_) | Out-Null
            $rootCount++
        }
    }
    Write-Info "      $rootCount candidate file(s)."
}
Write-Info "  Searching $($textCandidates.Count) candidate file(s) for IOC strings and ICP URLs..."

$iocStringHits = 0
$icpHits = 0
$checkedTextFiles = 0
foreach ($file in $textCandidates) {
    $checkedTextFiles++
    if ($checkedTextFiles % 500 -eq 0) { Write-Info "    Checked $checkedTextFiles/$($textCandidates.Count) text file(s)..." }
    Select-String -Path $file.FullName -Pattern @($IOC_CombinedRegex, $IOC_RegexICP) -ErrorAction SilentlyContinue |
    ForEach-Object {
        $matchValue = $_.Matches[0].Value
        if ($matchValue -match $IOC_RegexICP) {
            if ($icpHits -lt 5) { Write-Hit "ICP canister exfil URL pattern in: $($_.Path)" }
            $icpHits++
        } else {
            if ($iocStringHits -lt 20) { Write-Hit "IOC '$matchValue' in: $($_.Path)" }
            $iocStringHits++
        }
    }
}
Write-Info "  IOC string search complete: $checkedTextFiles file(s) checked, $iocStringHits IOC string hit(s), $icpHits ICP URL hit(s)."

Write-Header "IOC FILE HASH CHECK"
foreach ($root in $SearchRoots) {
    foreach ($fname in @("env-compat.cjs","public.pem")) {
        Get-ChildItemSafe -Path $root -Filter $fname -Depth 12 |
        Select-Object -First 20 |
        ForEach-Object {
            $script:Scanned++
            $hash = Get-FileSHA256 $_.FullName
            if ($hash -and $IOC_Hashes.ContainsKey($hash)) {
                Write-Hit "HASH MATCH: $($_.FullName) ($($IOC_Hashes[$hash]))"
            } elseif ($hash) {
                Write-OK "Hash OK: $($_.FullName) ($hash)"
            }
        }
    }
}

# =============================================================================
#  SECTION 8 -- NETWORK AND CONFIG CHECKS
# =============================================================================

Write-Header "NETWORK CONNECTIONS TO IOC ENDPOINTS"
$script:Scanned++
$tcpCmdAvailable = $null -ne (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
if ($tcpCmdAvailable) {
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($iocHost in $IOC_Hosts) {
            try {
                $ips = [System.Net.Dns]::GetHostAddresses($iocHost) | ForEach-Object { $_.IPAddressToString }
                foreach ($ip in $ips) {
                    $match = $conns | Where-Object { $_.RemoteAddress -eq $ip }
                    if ($match) {
                        foreach ($m in $match) { Write-Hit "Active connection to IOC $iocHost ($ip) port $($m.RemotePort) PID $($m.OwningProcess)" }
                    }
                }
            } catch { }
        }
        Write-OK "Network connection check complete."
    } catch { Write-Warn "Could not enumerate connections." }
} else {
    Write-Warn "Get-NetTCPConnection unavailable on this system -- skipping connection check."
}

Write-Header ".npmrc AND HOSTS FILE"
$npmrcPaths = @("$env:USERPROFILE\.npmrc","$env:APPDATA\npm\etc\npmrc") +
              @(Get-ChildItem "C:\Users\*\.npmrc" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
foreach ($npmrc in ($npmrcPaths | Sort-Object -Unique)) {
    if (-not (Test-Path $npmrc)) { continue }
    $script:Scanned++
    $content = Get-Content $npmrc -Raw -ErrorAction SilentlyContinue
    if ($content -match 'registry\s*=\s*https?://(?!registry\.npmjs\.org)') {
        Write-Hit "Suspicious registry redirect in $npmrc"
    } else { Write-OK "$npmrc registry OK" }
}
$script:Scanned++
$hostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
# Skip comment lines when checking for redirects
$hostsActive = $hostsContent | Where-Object { $_ -and ($_ -notmatch '^\s*#') }
if ($hostsActive -match "registry\.npmjs") {
    Write-Hit "hosts file contains npmjs redirect -- possible registry hijack"
} else { Write-OK "hosts file clean" }

# =============================================================================
#  SECTION 9 -- SUMMARY
# =============================================================================

Write-Header "SCAN SUMMARY"
Write-Host ""
Write-Host "Total checks performed         : $($script:Scanned)" -ForegroundColor White
Write-Host "Malicious packages in IOC list : $($MaliciousPkgs.Count)" -ForegroundColor White
Write-Host "Indicators found               : $($script:Found)" -ForegroundColor $(if ($script:Found -gt 0) {"Red"} else {"Green"})
Write-Host ""

if ($script:Found -gt 0) {
    Write-Host "FINDINGS -- TAKE IMMEDIATE ACTION:" -ForegroundColor Red
    foreach ($f in $script:Findings) { Write-Host "  * $f" -ForegroundColor Red }
    Write-Host ""
    Write-Host "RECOMMENDED ACTIONS:" -ForegroundColor Yellow
    Write-Host "  1. Remove/uninstall all flagged packages immediately."
    Write-Host "  2. ROTATE ALL credentials: npm tokens, SSH keys, AWS/GCP/Azure, GitHub PATs, .env secrets."
    Write-Host "  3. Audit npm publish history for unauthorised releases."
    Write-Host "  4. Review CI/CD pipeline logs for affected package installs."
    Write-Host "  5. Run: npm config set ignore-scripts true"
    Write-Host "  6. Check Python envs for .pth injection if PyPI credentials were present."
} else {
    Write-Host "No known supply chain indicators found on this host." -ForegroundColor Green
    Write-Host ""
    Write-Host "Recommendations:" -ForegroundColor Yellow
    Write-Host "  - Schedule this script daily via Task Scheduler."
    Write-Host "  - Run on all developer machines, build agents, and CI runners."
    Write-Host "  - Pin exact package versions in lock files."
    Write-Host "  - Run: npm config set ignore-scripts true  in CI/CD pipelines."
}

Write-Host ""
Write-Host "Live data sources:" -ForegroundColor Cyan
Write-Host "  OSV.dev bulk zip  : https://storage.googleapis.com/osv-vulnerabilities/<eco>/all.zip"
Write-Host "  OpenSSF mal-pkgs  : https://github.com/ossf/malicious-packages"
Write-Host "  Socket tracker    : https://socket.dev/supply-chain-attacks/canistersprawl"
Write-Host ""
Write-Host "Report generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# ── Optional JSON report ──────────────────────────────────────────────────────
if ($OutputJson) {
    $report = [ordered]@{
        Timestamp      = (Get-Date -Format "o")
        Hostname       = $env:COMPUTERNAME
        User           = "$env:USERDOMAIN\$env:USERNAME"
        TotalChecks    = $script:Scanned
        FindingsCount  = $script:Found
        Findings       = $script:Findings
        IOCListSize    = $MaliciousPkgs.Count
        LiveFeedPulled = (-not $SkipLiveFeed)
    }
    try {
        $report | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputJson -Encoding UTF8
        Write-Host "JSON report written to: $OutputJson" -ForegroundColor Cyan
    } catch {
        Write-Warn "Could not write JSON report: $_"
    }
}

# ── Task Scheduler setup hint ─────────────────────────────────────────────────
Write-Host ""
Write-Host "To schedule daily at 07:00 (run once as Administrator):" -ForegroundColor DarkGray
Write-Host '  $action  = New-ScheduledTaskAction -Execute "powershell.exe" `' -ForegroundColor DarkGray
Write-Host '             -Argument "-ExecutionPolicy Bypass -File ""C:\Scripts\Scan-SupplyChain.ps1"" -OutputJson C:\Logs\sc-scan.json"' -ForegroundColor DarkGray
Write-Host '  $trigger = New-ScheduledTaskTrigger -Daily -At 07:00' -ForegroundColor DarkGray
Write-Host '  Register-ScheduledTask -TaskName "SupplyChainScan" -Action $action -Trigger $trigger -RunLevel Highest' -ForegroundColor DarkGray
