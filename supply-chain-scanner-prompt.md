# Prompt: Generate a Supply Chain Attack Scanner

Use the prompt below (in the grey box) to ask an AI assistant to create a supply chain scanner tailored to your environment. Customise the bracketed fields before sending.

---

## The Prompt

```
I need a supply chain attack scanner script for [PLATFORM: Windows PowerShell / Ubuntu bash / macOS zsh].

Please create a complete, production-ready script that does the following:

Design goal: make the scanner inventory what is installed locally, then cross-check those installed records against in-memory IOC maps. Avoid the slow shape of looping every IOC package and probing the filesystem or package manager once per IOC. Use progress output for every long-running phase.

---

### 1. Live feed pull (run on every execution)

Pull the latest malicious package data from these authoritative, machine-readable sources and merge them into a working IOC list:

- **OpenSSF malicious-packages repository** (GitHub):
  https://github.com/ossf/malicious-packages
  Use a shallow `git clone --depth 1 --filter=blob:none --no-checkout` followed by `git sparse-checkout set osv/malicious` and `git checkout`. This pulls all OSV records in a single git operation rather than thousands of REST calls. If `git` is not installed, fall back to the GitHub tree API: `https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1`, then download each file from `https://raw.githubusercontent.com/ossf/malicious-packages/main/<path>`. Support an optional `GITHUB_TOKEN` environment variable (or `-GitHubToken` parameter) to raise the unauthenticated rate limit from 60/hour to 5,000/hour.

- **OSV.dev bulk zip** (Google/OpenSSF):
  Download the full ecosystem zip for each ecosystem you care about:
  `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip`
  Download the `npm` and `PyPI` zips (one HTTP request each). Unzip and parse all records **locally** in a single pass — do not make further HTTP calls per record. Filter to malicious entries using a broad keyword list: ID starts with `MAL-`, or `database_specific.malicious == true`, or `summary` contains any of: "malicious", "malware", "backdoor", "supply chain", "credential steal/credential-steal", "compromised", "typosquat", "account takeover", "info stealer/infostealer", "crypto stealer/cryptostealer", "rat", "trojan", "data exfil", "exfiltrat". Print a progress line every 1,000 records so the user can see activity. Delete the zip file after parsing. This should complete in under three minutes on a typical connection.

Parse each OSV record's `affected[].package.{ecosystem,name}` and `affected[].versions[]` fields. If `versions` is empty, treat as wildcard (`*` = any version is suspect).

Map OSV ecosystem names to internal labels: npm→npm, PyPI→PyPI, Go→Go, crates.io→Rust, Maven→Maven, NuGet→NuGet, Debian→Debian, Ubuntu→Ubuntu.

Store merged malicious packages in an in-memory map keyed by ecosystem + normalized package name. For npm, package names are case-sensitive. For PyPI, normalize names per PEP 503: lowercase and collapse `-`, `_`, and `.` runs to `-`. For package values, store bad versions as a version-set/hash table plus an explicit wildcard flag, not as a flat list that must be scanned repeatedly.

---

### 2. Hardcoded IOC baseline (always applied, even offline)

Always check for these specific packages regardless of live feed availability. Use these as a fallback and a guaranteed baseline:

**npm — S1ngularity / Nx (August 26 2025):**
- `nx` — bad versions: `21.5.0`, `20.9.0`, `20.10.0`, `21.6.0`, `20.11.0`, `21.7.0`, `21.8.0`, `20.12.0`
- `@nx/devkit`, `@nx/js`, `@nx/workspace`, `@nx/node` — bad versions: `21.5.0`, `20.9.0`
- `@nx/eslint` — bad version: `21.5.0`
- `@nx/key`, `@nx/enterprise-cloud` — bad version: `3.2.0`

**npm — September 2025 npm crypto-theft / Shai-Hulud wave:**
Include this curated high-signal offline baseline. Live feeds should cover the long tail, but these keep offline mode useful:
- `ansi-styles` `6.2.2`, `backslash` `0.2.1`, `chalk` `5.6.1`, `chalk-template` `1.1.1`, `color-convert` `3.1.1`, `color-name` `2.0.1`, `color-string` `2.1.1`, `debug` `4.4.2`, `error-ex` `1.3.3`, `has-ansi` `6.0.1`, `is-arrayish` `0.3.3`, `proto-tinker-wc` `0.1.87`, `simple-swizzle` `0.2.3`, `slice-ansi` `7.1.1`, `strip-ansi` `7.1.1`, `supports-color` `10.2.1`, `supports-hyperlinks` `4.1.1`, `wrap-ansi` `9.0.1`
- `@ahmedhfarag/ngx-perfect-scrollbar` `20.0.20`, `@ahmedhfarag/ngx-virtual-scroller` `4.0.4`
- `@crowdstrike/commitlint` `8.1.1` `8.1.2`, `@crowdstrike/falcon-shoelace` `0.4.1` `0.4.2`, `@crowdstrike/foundry-js` `0.19.1` `0.19.2`, `@crowdstrike/glide-core` `0.34.2` `0.34.3`, `@crowdstrike/logscale-dashboard` `1.205.1` `1.205.2`, `@crowdstrike/logscale-file-editor` `1.205.1` `1.205.2`, `@crowdstrike/logscale-parser-edit` `1.205.1` `1.205.2`, `@crowdstrike/logscale-search` `1.205.1` `1.205.2`, `@crowdstrike/tailwind-toucan-base` `5.0.1` `5.0.2`
- `@ctrl/deluge` `1.2.0` `7.2.1` `7.2.2`, `@ctrl/golang-template` `1.4.2` `1.4.3`, `@ctrl/magnet-link` `4.0.3` `4.0.4`, `@ctrl/ngx-codemirror` `7.0.1` `7.0.2`, `@ctrl/ngx-csv` `6.0.1` `6.0.2`, `@ctrl/ngx-emoji-mart` `9.2.1` `9.2.2`, `@ctrl/ngx-rightclick` `4.0.1` `4.0.2`, `@ctrl/qbittorrent` `9.7.1` `9.7.2`, `@ctrl/react-adsense` `2.0.1` `2.0.2`, `@ctrl/shared-torrent` `6.3.1` `6.3.2`, `@ctrl/tinycolor` `4.1.1` `4.1.2`, `@ctrl/torrent-file` `4.1.1` `4.1.2`, `@ctrl/transmission` `7.3.1`, `@ctrl/ts-base32` `4.0.1` `4.0.2`
- `angulartics2` `14.1.1` `14.1.2`, `ng2-file-upload` `7.0.2` `7.0.3` `8.0.1` `8.0.2` `8.0.3` `9.0.1`, `ngx-bootstrap` `18.1.4` `19.0.3` `19.0.4` `20.0.3` `20.0.4` `20.0.5` `20.0.6`, `ngx-toastr` `19.0.1` `19.0.2`

**npm — CanisterWorm (TeamPCP, March 20–23 2026):**
- `@emilgroup/api-agentv3`, `@emilgroup/api-auth`, `@emilgroup/api-biddingv2`,
  `@emilgroup/api-biddingv3`, `@emilgroup/api-blocksv2`, `@emilgroup/api-couponsv2`,
  `@emilgroup/api-couponsv3`, `@emilgroup/api-dashboardv2`, `@emilgroup/api-deliveriesv2`,
  `@emilgroup/api-deliveriesv3`, `@emilgroup/api-financev2`, `@emilgroup/api-giftcardsv3`,
  `@emilgroup/api-identitiesv3`, `@emilgroup/api-inventoryv2`, `@emilgroup/api-inventoryv3`,
  `@emilgroup/api-logsv3`, `@emilgroup/api-menuv2`, `@emilgroup/api-menuv3`,
  `@emilgroup/api-notificationsv3`, `@emilgroup/api-ordersv2`, `@emilgroup/api-ordersv3`,
  `@emilgroup/api-paymentsv2`, `@emilgroup/api-paymentsv3`, `@emilgroup/api-productsv2`,
  `@emilgroup/api-productsv3`, `@emilgroup/api-reportingv3`, `@emilgroup/api-restaurantsv2`,
  `@emilgroup/api-restaurantsv3`, `@emilgroup/api-usersv2`, `@emilgroup/api-usersv3`
  — all bad at version `1.0.1`
- `@teale.io/eslint-config` — bad versions: `1.8.11`, `1.8.12`

**npm — CanisterSprawl (TeamPCP, April 8–23 2026):**
- `@automagik/genie` — bad versions: `4.260421.33` through `4.260421.40`
- `pgserve` — bad versions: `1.1.11`, `1.1.12`, `1.1.13`, `1.1.14`
- `@fairwords/websocket` — bad versions: `1.0.38`, `1.0.39`
- `@fairwords/loopback-connector-es` — bad versions: `1.4.3`, `1.4.4`
- `@openwebconcept/design-tokens` — bad versions: `1.0.1`, `1.0.2`, `1.0.3`
- `@openwebconcept/theme-owc` — bad versions: `1.0.1`, `1.0.2`, `1.0.3`

**npm — Checkmarx/Bitwarden (April 22 2026):**
- `@bitwarden/cli` — bad version: `2026.4.0`

**npm — Axios RAT (TeamPCP, March 31 2026):**
- `axios` — bad versions: `1.14.1`, `0.30.4`
- `plain-crypto-js` — all versions (`*`)

**npm — dYdX (January 2026):**
- `@dydxprotocol/v4-client-js` — bad versions: `3.4.1`, `1.22.1`, `1.15.2`, `1.0.31`

**npm — Asurion-impersonation (April 2026):**
- `sbxapps`, `asurion-hub-web`, `soluto-home-web`, `asurion-core` — all versions (`*`)

**npm — Kubernetes-impersonation (April 2026):**
- `kube-health-tools` — all versions (`*`)

**PyPI — LiteLLM (TeamPCP, March 24 2026):**
- `litellm` — bad versions: `1.82.7`, `1.82.8`

**PyPI — xinference (April 2026):**
- `xinference` — bad versions: `2.6.0`, `2.6.1`, `2.6.2`

**PyPI — dYdX:**
- `dydx-v4-client` — bad versions: `3.4.1`, `1.22.1`, `1.15.2`, `1.0.31`

**PyPI — Kubernetes-impersonation:**
- `kube-node-health` — all versions (`*`)

**Docker images:**
- `checkmarx/kics` — all versions (`*`) — compromised April 22 2026

---

### 3. What to scan

**npm packages:**
Walk bounded search roots for `package.json` files (depth ≤ 12). For each one, read `name` and `version` fields and compare against the in-memory npm IOC map. Skip double-nested `node_modules`. Avoid false positives from source folders: skip `private: true` packages and skip non-`node_modules` package.json files that lack npm install metadata such as `_id`, `_integrity`, or `_resolved`. Also scan `package-lock.json` and `yarn.lock` for the string `plain-crypto-js` or Axios versions `1.14.1`/`0.30.4`.

**PyPI packages:**
Do NOT query `pip show <package>` once per target. Instead:
- Build a normalized in-memory PyPI target map keyed by PEP 503 canonical package name. Each value is a version-set/hash table plus wildcard flag.
- Discover Python installs, virtual environments, and `site-packages` directories under the same bounded search roots.
- Inventory installed packages once using `pip list --format=freeze` for the active environment if `pip` exists.
- Inventory discovered `.dist-info` directories once by reading each `METADATA` file's `Name:` and `Version:` fields; fall back to parsing the directory name only if metadata is absent.
- Cross-check each installed package record against the normalized PyPI map. Print progress while discovering Python roots, inventorying `.dist-info`, and cross-checking.

**[PLATFORM-SPECIFIC — add as appropriate:]**
- **Ubuntu:** Scan `dpkg` for any Debian/Ubuntu ecosystem packages from the live feed.
- **Windows:** Check `%APPDATA%`, `%LOCALAPPDATA%`, all user profiles under the system drive's `Users` directory, Program Files, ProgramData, and common dev/tool roots such as `C:\src`, `C:\code`, `C:\projects`, `C:\dev`, `C:\workspace`, `C:\tools`, and `C:\opt`. Use the actual `$env:SystemDrive` instead of hardcoding `C:`.
- **Linux:** If the user is `/home/name`, scan `/home` plus bounded package/app roots such as `/usr`, `/usr/local`, `/opt`, `/srv`, `/app`, `/workspace`, `/var/www`, and `/var/lib`. Use `-xdev` where practical to avoid crossing mounted filesystems.

**Docker (if installed):**
- Check local images against the flagged Docker image list.
- Run a layer-history heuristic (`docker history --no-trunc`) on all local images, flagging any that reference compromised package names in their build layers.
- For running containers (`docker ps`): use `docker exec` to check IOC files, the `pgmon` persistence artefact, and scan npm/PyPI packages inside the container. Do not deep-scan stopped containers by default; explain that stopped containers cannot be inspected with `docker exec` and that full offline image/container export scanning should be an optional future/deep-scan mode.
- Inside each running container, list installed npm/PyPI packages in bulk, then cross-check in memory. Do not run one `docker exec` per IOC package.

**IOC artefacts to look for:**
- Files: `/tmp/pglog`, `/tmp/.pg_state`, `/tmp/inventory.txt`, `sysmon.py`, `litellm_init.pth`
- Script names: `env-compat.cjs`, `public.pem`, `sysmon.py`, `litellm_init.pth`
- Strings in `.js`, `.cjs`, `.mjs`, `.py`, `.json`, `.npmrc`, `.env`, `.sh`, `.yaml`, `.yml` files. Treat these IOC strings as fixed strings: escape them before building any combined regex so dots and other metacharacters are not interpreted:
  `cjn37-uyaaa-aaaac-qgnva-cai`, `telemetry.api-monitor.com`,
  `audit.checkmarx.cx`, `scan.aquasecurtiy.org`, `models.litellm.cloud`,
  `plain-crypto-js`, `pkg-telemetry`, `pypi-pth-exfil`,
  `pgmon.service`, `.config/pgmon`, `s1ngularity-repository`, `Shai-Hulud`
  ⚠️ **Do NOT search for the bare string `pgmon`** — that matches the legitimate PostgreSQL `pg_monitor` role and causes many false positives. Use `pgmon.service` and `.config/pgmon` instead.
- Optimize IOC string search: build a candidate file inventory once per root, de-duplicate paths from overlapping roots, skip noisy directories (`node_modules`, `.git`, `.vscode`, `.cache`, `__pycache__`, `dist`, `build`, `coverage`, editor history/workspace storage, test logs), cap text scanning to small files (for example ≤ 2 MB), and scan each candidate once with a combined escaped-IOC-string pattern plus the ICP URL regex. Print progress every few hundred files.
- Generic regex pattern for ICP canister exfiltration URLs (catches new canister IDs the worm rotates to): `[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-cai\.raw\.icp0\.io`
- SHA-256 file hashes:
  - `c19c4574d09e60636425f9555d3b63e8cb5c9d63ceb1c982c35e5a310c97a839` → `env-compat.cjs` (CanisterSprawl payload)
  - `834b6e5db5710b9308d0598978a0148a9dc832361f1fa0b7ad4343dcceba2812` → `public.pem` (CanisterSprawl RSA key)
- Make sure file-extension include patterns match BOTH bare `.env`/`.npmrc` and any-prefix `*.env`/`*.npmrc` — many grep implementations treat `--include='*.env'` as requiring at least one character before `.env`.

**Persistence artefacts (Linux):**
- `pgmon` systemd user service (CanisterWorm/Sprawl)
- `sysmon.service` (LiteLLM worm)
- `litellm_init.pth` files in Python site-packages

**Network:**
Resolve these IOC hostnames and compare against active TCP connections:
`telemetry.api-monitor.com`, `cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io`,
`audit.checkmarx.cx`, `scan.aquasecurtiy.org`, `models.litellm.cloud`

**Configuration:**
- Check all `.npmrc` files for unexpected registry redirects (anything other than `registry.npmjs.org`)
- Check `/etc/hosts` (Linux) or `C:\Windows\System32\drivers\etc\hosts` (Windows) for npmjs redirects

---

### 4. Output format

- Colour-coded console output: red for `[MATCH]`, green for `[ok]`, cyan for informational
- Print progress during the live feed phase so users know it is running: every 100 files for the OpenSSF feed, every 1,000 records for the OSV bulk zip scan, including elapsed time in each progress line
- Print progress during local scans too: search roots discovered, Python roots discovered, npm package.json count, PyPI inventory count, IOC text candidate count, and periodic progress while scanning candidate text files.
- Support a `--output-json <path>` (Linux) or `-OutputJson <path>` (Windows) flag to write a structured JSON report containing: timestamp, hostname, user, total_checks, findings_count, ioc_list_size, live_feed_pulled, findings[]
- Print a summary at the end listing all findings and recommended remediation steps
- Print the command to schedule the script as a daily cron job (Linux) or Task Scheduler task (Windows)
- If generating a small repository instead of a single script, put the user-facing documentation in `README.md` at the Git repository root so GitHub renders it automatically.

---

### 5. Flags / parameters

- `--offline` or `-SkipLiveFeed`: skip the live feed pull; use only the hardcoded list
- `--output-json <path>` or `-OutputJson <path>`: write JSON report
- No required arguments; the script should run cleanly with zero arguments

---

### 6. Additional requirements

**Functional:**
- No external dependencies beyond what ships with [PLATFORM] and common dev tools (curl/Invoke-WebRequest, Python 3, pip, git, jq optional)
- Gracefully skip sections when tools are absent (e.g. Docker not installed → skip Docker section with a warning; `Get-NetTCPConnection` unavailable → skip network check)
- Handle errors silently; do not abort the whole scan if one check fails
- Run without interaction
- All Docker container commands use `docker exec` to run inside the container's Linux filesystem (important for Windows hosts running Linux containers via Docker Desktop)
- Prefer one inventory pass followed by in-memory lookups over repeated per-IOC filesystem or package-manager calls. This is especially important for PyPI and container scans.

**Security (treat live feed as untrusted input):**
- Validate package names against a safe-character regex (`^[@a-zA-Z0-9._/+-]+$`) before passing them to any shell command. Skip names that don't match.
- When passing user-supplied or feed-supplied strings to `docker exec sh -c '...'`, use positional parameters: `docker exec $cid sh -c 'cmd "$1"' _ "$pkg"`. Never interpolate strings directly into the script body.
- Never interpolate user paths into Python `-c` source code; pass via `sys.argv` or stdin.
- For JSON output, pass file paths and finding strings via environment variables to the Python interpreter, not by string interpolation.
- Use `umask 077` (Linux) or restrictive ACLs (Windows) before writing the JSON report.

**Correctness:**
- **Bash:** Do NOT use `set -e` — many checks involve `head -N` after `find`, which causes SIGPIPE that aborts the script. Use `set -uo pipefail` instead and add `|| true` to pipelines whose failure shouldn't abort.
- **Bash:** Place `-maxdepth` BEFORE other tests in `find` (some `find` versions reject the wrong order).
- **Bash:** Avoid `grep -P` (Perl regex) — use POSIX `-E` for portability.
- **Bash:** Use `grep -F` (fixed-string) for IOC string matching — IOC strings often contain dots that grep would interpret as regex any-character.
- **PowerShell:** Do NOT use `Set-StrictMode -Version Latest`. Many OSV records lack optional fields (e.g. `database_specific`); strict mode throws on missing properties, and those throws get swallowed by `try/catch` — silently dropping valid malicious records. Use `Set-StrictMode -Version 2.0` (catches uninitialized variables but allows missing properties), and gate property access with `$rec.PSObject.Properties.Name -contains 'foo'`.
- **PowerShell:** `pip show | Select-String "^Version:"` returns a `MatchInfo` object whose `.ToString()` includes the line-number prefix (`InputStream:N:Version: 1.2.3`). Don't `.ToString()` it — use `Where-Object { $_ -match '^Version:\s*(.+)$' }` and read `$matches[1]` instead.
- **PowerShell:** Prefer `pip list --format=freeze` plus `.dist-info` metadata inventory over `pip show` loops. For PyPI package checks, use a normalized package-name hashtable and per-package version-set hashtable so package and version checks are constant-time.
- **PowerShell:** `Get-ChildItem` should use `-Attributes !ReparsePoint` to avoid scanning junctions and double-counting symlinked profiles.
- **PowerShell:** PS 5.1's `ConvertFrom-Json` is slow; for large `package.json` files use a regex (`'"name"\s*:\s*"([^"]+)"'`) — 5-10x faster.
- **PowerShell:** For IOC text scanning, do not run `Get-ChildItem` once per extension across the same roots. Collect candidate files once with `Get-ChildItem -Filter "*"`, filter extensions/names in memory, de-duplicate by full path, and then call `Select-String` once per candidate file with all patterns.
- **Both:** PyPI `.dist-info` directory names use the project's chosen separator (hyphen OR underscore between tokens) per PEP 503. Build a regex that accepts both: split the canonical (lowercase, hyphen-normalized) name on `-`, regex-escape each token, and rejoin with `[-_]`.
- **Both:** Restrict full-filesystem scans (`find /` or `Get-ChildItem C:\`) to specific search roots (`/home`, `/opt`, `C:\Users`, etc.) and prune pseudo filesystems (`/proc`, `/sys`, `/dev`). A naive `find / -maxdepth 12` can take many minutes on a system with NFS mounts or large data directories.
- **Both:** When checking `/etc/hosts` (or Windows `hosts` file) for redirects, skip lines starting with `#` (comments).

---

### Additional context about my environment

[OPTIONAL — add details here, for example:]
- My npm packages are mostly in: [e.g. C:\code\ or /home/user/projects/]
- I use [Anaconda / system Python / pyenv / uv]
- I have [N] Docker containers running typically
- I need the JSON output to be ingested by [Splunk / Datadog / Elasticsearch]
- My CI/CD system is [GitHub Actions / GitLab CI / Jenkins]
```

---

## Tips for Best Results

**Specify your Python setup.** The scanners use Python's standard `zipfile` and `json` modules for OSV bulk zip parsing — no third-party packages needed. If you use `uv`, `poetry`, or `conda`, mention it for the PyPI scanning section, as dist-info locations differ.

**Mention your project layout.** If your code lives in non-standard directories (e.g. `/data/repos`, `D:\Projects`), add them as search roots.

**Ask for CI/CD integration.** The prompt above generates a standalone script. If you want a GitHub Actions workflow, GitLab CI job, or Jenkins pipeline step instead, say so explicitly.

**Ask for a SIEM-ready variant.** If you need the JSON structured in a specific schema (e.g. Elastic Common Schema or OCSF), include a sample of the expected format in the prompt.

**Slow or metered connections.** The OSV bulk zips for npm and PyPI can be 30–80 MB each. On a slow connection, ask the AI to add a `--skip-osv-bulk` flag that skips the zip downloads and uses only the hardcoded list and the OpenSSF per-file feed.

**Keep it updated.** The hardcoded IOC list reflects attacks known as of April 2026. When running the prompt again in the future, ask the AI to search for recent supply chain attacks first, then generate the script — this keeps the baseline current even before the live feeds catch up.

---

## Data Sources Reference

| Source | Type | URL |
|---|---|---|
| OSV.dev bulk zip | Data dump (per-ecosystem zip) | `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip` |
| OSV.dev API | REST API | https://osv.dev · https://google.github.io/osv.dev/api/ |
| OpenSSF malicious-packages | GitHub repo (OSV format) | https://github.com/ossf/malicious-packages |
| Socket.dev supply chain tracker | Web (CanisterSprawl) | https://socket.dev/supply-chain-attacks/canistersprawl |
| StepSecurity blog | Research | https://www.stepsecurity.io/blog/ |
| Red Hat RHSB-2026-001 | Advisory | https://access.redhat.com/security/vulnerabilities/RHSB-2026-001 |
| JFrog Security Research | Research | https://research.jfrog.com |
| SANS Internet Storm Center | Research | https://isc.sans.edu |
