# Supply Chain Attack Scanner — Documentation

**Version:** 2.2  
**Last updated:** April 2026  
**Platforms:** Windows 11 (`Scan-SupplyChain.ps1`) · Ubuntu/Linux (`scan-supply-chain.sh`)

> **What's new in 2.2:** Hardened against shell injection in Docker exec calls; fixed PyPI version detection (was silently broken on Windows); replaced GitHub REST API with shallow `git clone` for the OpenSSF feed (10–20x faster, no rate limits); expanded malicious-keyword filter to catch typosquats, RATs, and info-stealers; restricted system-wide `find` to specific roots for ~50x speedup; added GitHub token support; PowerShell 7+ now strongly recommended.

---

## Overview

This toolkit scans your system, Docker containers, and Docker images for packages compromised in recent open-source supply chain attacks. It combines two strategies:

1. **Live feed pull** — on each run it fetches the latest malicious package data from authoritative, machine-readable sources (OSV.dev and the OpenSSF Malicious Packages repository), so the IOC list stays current without you needing to update the script.
2. **Hardcoded historical IOC list** — a curated baseline of high-profile attacks from 2026, used as a fallback when the live feeds are unreachable and to ensure coverage of incidents that may not yet be in the live databases.

---

## Live Data Sources

| Source | Method | What it covers |
|---|---|---|
| **OSV.dev bulk zip** | `storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip` | Google/OpenSSF aggregated feed; one HTTP request per ecosystem |
| **OpenSSF malicious-packages** | shallow `git clone --filter=blob:none` of `github.com/ossf/malicious-packages` | Community-curated OSV-format reports; over 15,000 entries |
| **OSV API** | `api.osv.dev/v1/query` | Per-package query API; used by OSV-Scanner and deps.dev |

The OSV.dev dump publishes a per-ecosystem `all.zip` containing every record for that ecosystem. The scanner downloads the `npm` and `PyPI` zips in a single request each, then filters and parses them entirely locally — no further HTTP calls are made during the OSV scan phase.

The OpenSSF feed is cloned via a shallow `git clone --depth 1 --filter=blob:none --no-checkout`, then sparse-checked-out to just `osv/malicious/`. This pulls all records in one git operation instead of 2,000 sequential REST calls. If `git` is unavailable, the scanner falls back to the GitHub REST API (slower; rate-limited to 60/hour without a `GITHUB_TOKEN`).

---

## Campaigns Covered by the Hardcoded IOC List

| Campaign | Ecosystem | Date | Packages |
|---|---|---|---|
| **S1ngularity / Nx** | npm | August 26 2025 | `nx`, `@nx/devkit`, `@nx/js`, `@nx/workspace`, `@nx/node`, `@nx/eslint`, `@nx/key`, `@nx/enterprise-cloud` |
| **Shai-Hulud / September npm compromise** | npm | September 2025 | Curated high-signal set including `chalk`, `debug`, `@ctrl/tinycolor`, `@crowdstrike/*`, `ngx-bootstrap`, `ngx-toastr`, `ng2-file-upload` |
| **CanisterWorm** (TeamPCP) | npm | March 20–23 2026 | `@emilgroup/*` (30+ packages), `@teale.io/eslint-config` |
| **CanisterSprawl** (TeamPCP) | npm | April 8–23 2026 | `@automagik/genie`, `pgserve`, `@fairwords/*`, `@openwebconcept/*` |
| **Axios RAT** (TeamPCP) | npm | March 31 2026 | `axios` 1.14.1 / 0.30.4, `plain-crypto-js` |
| **Checkmarx / Bitwarden** | npm + Docker | April 22 2026 | `@bitwarden/cli` 2026.4.0, `checkmarx/kics` Docker images |
| **LiteLLM** (TeamPCP) | PyPI | March 24 2026 | `litellm` 1.82.7, 1.82.8 |
| **xinference** | PyPI | April 22 2026 | `xinference` 2.6.0–2.6.2 |
| **dYdX** | npm + PyPI | January 2026 | `@dydxprotocol/v4-client-js`, `dydx-v4-client` |
| **Kubernetes-impersonation** | npm + PyPI | April 2026 | `kube-health-tools`, `kube-node-health` |
| **Asurion-impersonation** | npm | April 1–8 2026 | `sbxapps`, `asurion-hub-web`, `soluto-home-web`, `asurion-core` |

---

## Files

| File | Platform | Purpose |
|---|---|---|
| `Scan-SupplyChain.ps1` | Windows 11 | PowerShell scanner |
| `scan-supply-chain.sh` | Ubuntu / Linux | Bash scanner |

---

## Requirements

### Windows (`Scan-SupplyChain.ps1`)
- **PowerShell 7+ recommended** (5–10x faster JSON parsing than 5.1; PS 5.1 still works)
- `pip` in PATH (for PyPI scanning) — Python 3 itself is no longer required on the host
- `git` in PATH (recommended; falls back to REST API if absent)
- Docker Desktop (optional — skipped if absent)
- Internet access for live feed (or use `-SkipLiveFeed`)
- Optional: `$env:GITHUB_TOKEN` or `-GitHubToken` parameter to raise the GitHub rate limit when falling back to REST

### Ubuntu (`scan-supply-chain.sh`)
- Bash 4+ (uses associative arrays; macOS default `bash` 3.2 is **not** supported — install via Homebrew)
- `curl` (`sudo apt install curl`)
- Python 3 (`sudo apt install python3`) — used for zip parsing, package.json reading, JSON output
- `git` (recommended; `sudo apt install git`) — for shallow OpenSSF clone
- `jq` — optional; only used by the REST API fallback path
- Docker (optional — skipped if absent)
- Internet access for live feed (or use `--offline`)
- Optional: `GITHUB_TOKEN` environment variable for REST fallback path

---

## Usage

### Windows

```powershell
# Full run — pulls live feed, scans everything
powershell -ExecutionPolicy Bypass -File Scan-SupplyChain.ps1

# Offline / air-gapped — hardcoded IOC list only
powershell -ExecutionPolicy Bypass -File Scan-SupplyChain.ps1 -SkipLiveFeed

# Write a JSON report for SIEM ingestion
powershell -ExecutionPolicy Bypass -File Scan-SupplyChain.ps1 -OutputJson C:\Logs\sc-scan.json

# With GitHub token (raises REST API rate limit from 60/hr to 5,000/hr if git is unavailable)
$env:GITHUB_TOKEN = 'ghp_yourtoken'; .\Scan-SupplyChain.ps1
# OR
.\Scan-SupplyChain.ps1 -GitHubToken 'ghp_yourtoken'
```

Run as **Administrator** for full coverage of all user profiles, Docker, and system directories. PowerShell 7+ is strongly recommended for performance; install via `winget install Microsoft.PowerShell` or download from https://github.com/PowerShell/PowerShell/releases.

### Ubuntu

```bash
# Full run
sudo bash scan-supply-chain.sh

# Offline
sudo bash scan-supply-chain.sh --offline

# With JSON report
sudo bash scan-supply-chain.sh --output-json /var/log/sc-scan.json

# With GitHub token for REST fallback (when git isn't installed)
GITHUB_TOKEN=ghp_yourtoken sudo -E bash scan-supply-chain.sh
```

Run with **`sudo`** for full coverage of all user home directories, Docker, and system paths.

---

## What Each Script Checks

### npm Packages
Walks the user's home parent and common package/tool locations on the main OS drive for `package.json` files up to 12 directories deep, matching every known malicious package name and exact bad version. On Linux, a user such as `/home/mike` causes `/home` to be scanned, plus common root-filesystem package locations such as `/usr`, `/usr/local`, `/opt`, `/srv`, `/app`, `/workspace`, `/var/www`, and `/var/lib`, while staying on each selected filesystem. On Windows, the scanner covers the system drive's user, Program Files, ProgramData, and common dev/tool roots such as `C:\src`, `C:\dev`, `C:\workspace`, `C:\tools`, and `C:\opt`. It also scans `package-lock.json` and `yarn.lock` files for injected malicious dependencies (e.g. `plain-crypto-js` from the Axios attack).

### PyPI Packages
Builds a normalized in-memory map of malicious PyPI package names and bad versions, then inventories installed Python packages once via `pip list --format=freeze` and discovered `.dist-info` metadata. Each installed package is checked against the map, so local venvs and Python installs are scanned without looping the full IOC list for every environment.

### OSV Bulk Feed (npm + PyPI)
Downloads the full `all.zip` for the `npm` and `PyPI` ecosystems from the OSV data dump — one HTTP request per ecosystem. All filtering and parsing is done locally in Python using the standard `zipfile` module, with no further network calls. Records are flagged as malicious if their ID starts with `MAL-`, their `database_specific.malicious` field is `true`, or their summary contains keywords such as "malicious", "malware", "backdoor", or "supply chain". Progress is printed every 1,000 records. The entire OSV phase typically completes in under three minutes on a typical broadband connection.

### Docker Images and Containers
- Checks local images against the flagged image list (e.g. `checkmarx/kics`)
- Runs a layer history heuristic on all local images to detect compromised package names in `RUN` commands
- For every **running** container: checks IOC files (`/tmp/pglog`, `/tmp/.pg_state`, `sysmon.py`), checks for the `pgmon` worm persistence service, and scans npm and PyPI packages inside the container's filesystem via `docker exec`

### IOC Artefacts
- **Files:** `/tmp/pglog`, `/tmp/.pg_state`, `/tmp/inventory.txt` (S1ngularity/Nx), `sysmon.py` (LiteLLM worm), `litellm_init.pth`
- **Scripts:** `check-env.js`, `deploy.js`, `env-compat.cjs`, `public.pem`
- **Strings:** `cjn37-uyaaa-aaaac-qgnva-cai`, `telemetry.api-monitor`, `pgmon`, `audit.checkmarx.cx`, `plain-crypto-js`, `s1ngularity-repository`, `Shai-Hulud`, and others. Candidate text files are inventoried once per root, de-duplicated, capped at 2 MB per file, and noisy build/cache directories are skipped before the combined IOC regex and ICP URL regex are checked.
- **SHA-256 hashes:** known malicious `env-compat.cjs` and `public.pem` files

### Worm Persistence (Ubuntu)
Checks for the `pgmon` systemd user service installed by CanisterWorm/CanisterSprawl and the `sysmon.service` installed by the LiteLLM worm.

### Network Connections
Resolves known IOC exfiltration hostnames and compares against active TCP connections to detect active data exfiltration.

### Configuration
Checks all `.npmrc` files for unexpected registry redirects (which would divert `npm install` to an attacker-controlled registry), and checks `/etc/hosts` (Linux) or `C:\Windows\System32\drivers\etc\hosts` (Windows) for npmjs redirects.

---

## Output

### Console
Colour-coded output:
- `[MATCH]` in red — a confirmed indicator found
- `[ok]` in green — check passed
- `[*]` in cyan — informational, including live progress during feed fetching
- `[!]` in yellow — warning

During the live feed phase, progress lines are printed regularly so you can confirm the script is running:
- **OpenSSF feed:** every 100 files fetched, showing count and elapsed time
- **OSV bulk zip:** every 1,000 records scanned locally, showing count and elapsed time

### JSON Report (optional)
```json
{
  "timestamp": "2026-04-26T07:00:00+00:00",
  "hostname": "devbox01",
  "user": "michael",
  "total_checks": 1842,
  "findings_count": 0,
  "ioc_list_size": 312,
  "live_feed_pulled": true,
  "findings": []
}
```

Suitable for ingestion into Splunk, Elasticsearch, Datadog, or any SIEM that accepts JSON log files.

---

## Scheduling for Daily Runs

### Windows — Task Scheduler

Run once as Administrator:

```powershell
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
           -Argument '-ExecutionPolicy Bypass -File "C:\Scripts\Scan-SupplyChain.ps1" -OutputJson "C:\Logs\sc-scan.json"'
$trigger = New-ScheduledTaskTrigger -Daily -At 07:00
Register-ScheduledTask -TaskName "SupplyChainScan" -Action $action -Trigger $trigger -RunLevel Highest
```

### Ubuntu — cron

```bash
echo '0 7 * * * root bash /opt/scan-supply-chain.sh --output-json /var/log/sc-scan.json' \
  | sudo tee /etc/cron.d/supply-chain-scan
```

---

## If You Find a Match

1. **Remove the flagged package** from your environment and any CI/CD pipelines immediately.
2. **Rotate all credentials** that could have been accessible on the affected machine:
   - npm tokens (`~/.npmrc`, `NPM_TOKEN` environment variable)
   - SSH private keys (`~/.ssh/`)
   - AWS, GCP, Azure credentials
   - GitHub personal access tokens
   - Any API keys stored in environment variables or `.env` files
3. **Stop worm persistence** if `pgmon` was found (Linux):
   ```bash
   systemctl --user stop pgmon.service
   systemctl --user disable pgmon.service
   ```
4. **Audit your npm publish history** — if an npm token was stolen, the worm may have republished malicious versions of packages you maintain.
5. **Check CI/CD pipeline logs** for installs of affected package versions.
6. **Harden future installs:**
   ```bash
   npm config set ignore-scripts true
   ```

---

## Limitations

- **Running containers only** — for Docker images that are not currently running, the scanner uses a layer-history heuristic rather than a full filesystem scan. To deep-scan a non-running image, start a temporary container from it before running the scanner:
  ```bash
  docker run --rm -d --entrypoint sleep myimage:tag 3600
  sudo bash scan-supply-chain.sh
  ```
- **OSV zip size** — the `npm/all.zip` can be 30–80 MB. On a slow or metered connection, use `--offline` / `-SkipLiveFeed` and rely on the hardcoded baseline instead.
- **OSV covers npm and PyPI only** — the bulk zip approach currently downloads zips for `npm` and `PyPI`. Other ecosystems (Go, Rust, Maven, etc.) are not bulk-scanned; they would require additional zip downloads or the OpenSSF feed to cover them.
- **Live feed latency** — newly reported malicious packages may take hours to days to appear in the OSV/OpenSSF feeds after initial disclosure. The hardcoded list covers the highest-profile incidents as a backstop.
- **Version pinning** — the scanner matches exact version strings. Packages installed via commit SHAs or non-semver identifiers may not match. OSV records that use ranges (`>= 1.0.0, < 2.0.0`) without an enumerated `versions[]` field will fall back to wildcard (`*`).
- **CanisterWorm partial list** — the hardcoded baseline includes the 30 `@emilgroup/*` packages from the original Socket disclosure. JFrog later identified 47+ packages in total; the additional ones come in via the live feed.
- **PowerShell 5.1 is slower** — `ConvertFrom-Json` in PS 5.1 is ~5–10x slower than PS 7+. Scanning the OSV bulk zip on PS 5.1 may take several minutes; PS 7+ completes in under a minute. Install PS 7 via `winget install Microsoft.PowerShell`.
- **No macOS version** — the bash script will run on macOS with minor path adjustments, but the apt/dpkg section and systemd checks will be silently skipped. macOS's default `bash` is 3.2 which lacks associative arrays — install `bash` via Homebrew (`brew install bash`) and use `/opt/homebrew/bin/bash`.

---

## Further Reading

- OSV.dev: https://osv.dev
- OpenSSF Malicious Packages: https://github.com/ossf/malicious-packages
- Socket CanisterSprawl tracker: https://socket.dev/supply-chain-attacks/canistersprawl
- StepSecurity CanisterWorm writeup: https://www.stepsecurity.io/blog/canisterworm-how-a-self-propagating-npm-worm-is-spreading-backdoors-across-the-ecosystem
- Red Hat supply chain advisory: https://access.redhat.com/security/vulnerabilities/RHSB-2026-001
- SANS Axios compromise briefing: https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan
