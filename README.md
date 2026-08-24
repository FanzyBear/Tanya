<p align="center">
  <pre>
  ████████╗ █████╗ ███╗   ██╗██╗   ██╗  █████╗        _._     _,-'""`-._
     ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝ ██╔══██╗    (,-.`._,'(       |\`-/|
     ██║   ███████║██╔██╗ ██║ ╚████╔╝  ███████║         `-.-' \ )-`( , o o)
     ██║   ██╔══██║██║╚██╗██║  ╚██╔╝   ██╔══██║              `-    \`_`"'-
     ██║   ██║  ██║██║ ╚████║   ██║    ██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═╝  ╚═╝
  </pre>
</p>

<p align="center">
  <b>Bug Bounty Web Recon Pipeline</b><br>
  v6.3 &nbsp;·&nbsp; Go + Bubbletea TUI &nbsp;·&nbsp; 17 modules &nbsp;·&nbsp; Authorized targets only
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&logo=go" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL2-lightgrey?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat-square" />
</p>

---

## Overview

Tanya is a single compiled Go binary that orchestrates a 17-module web recon pipeline. Point it at a domain and it runs subdomain enumeration, HTTP probing, JS analysis, vulnerability scanning, and more — all chained automatically with a full-screen TUI showing live progress.

No Docker. No config files required. No Python dependency hell. Build once, run anywhere.

> **Authorization required.** Only scan systems you own or are explicitly permitted to test — a bug bounty program you're enrolled in, a signed pentest engagement, or your own infrastructure.

---

## Features

- **17 chained recon modules** covering the full bug bounty workflow
- **Full-screen TUI** built with Bubbletea — live stats, module navigation, per-category runs
- **Automatic scope detection** — apex, strict, single-host, and PaaS modes auto-selected from the target you provide
- **CDN/WAF-aware** — detects Cloudflare, Akamai, Imperva, DataDome, PerimeterX, AWS WAF; separates challenged hosts from clean targets so your tools run against the right surface
- **Origin IP discovery** — finds real backend IPs behind CDNs for direct-connect scanning
- **Comprehensive JS recon** — endpoints, DOM XSS sinks, secrets, source-map reconstruction (recovers original sources), admin routes, cloud assets, tech fingerprinting, page→JS mapping
- **Concurrent 403 bypass** — 15 goroutines testing header tricks and path variants in parallel
- **Resume support** — restart a scan exactly where it left off
- **Interactive HTML report** — attack surface graph, triage section, search, WSL-aware paths
- **Graceful degradation** — missing tools skip with a warning, nothing crashes

---

## Quick Start

```bash
git clone https://github.com/FanzyBear/Tanya.git && cd Tanya

# Install Go, all recon tools, and SecLists (takes a few minutes)
./install.sh --all

# Interactive TUI
./tanya example.com

# Headless — run all 17 modules and exit
./tanya example.com --full
```

---

## Screenshots

> TUI — live module progress and stats bar

```
  ──────────────────────────────────────────────────────────────────────────────
   ◆ TANYA  v6.3  ›  example.com  [apex]                      9/17  ██████░░  52%
     output/example.com_20260615_142301
  ──────────────────────────────────────────────────────────────────────────────

  ◆ RECON ──────────────────────────────────────────────────────────────────────

  ✓  1  Subdomain Enum    ✓  2  HTTP Probe + WAF    ✓  3  Origin Discovery
  ✓  4  Port Scanning     ✓  5  URL Collection      ✓  6  JS Recon

  ◆ ATTACK ─────────────────────────────────────────────────────────────────────

  ✓  7  Dir Bruteforce    ✓  8  Params + CORS       ▶  9  Vuln Scan
    10  Sub Takeover      ✗ 11  403 Bypass             12  XSS Scan

  ──────────────────────────────────────────────────────────────────────────────
  subs:247  live:89  nuclei:12  secrets:3  xss:0  bypass:2  graphql:0  ssl:1
  ──────────────────────────────────────────────────────────────────────────────
  ↑↓/jk nav  ↵ run  tab cat  g/G first/last  F full  R report  D deps  ? help  Q quit
```

Status symbols: `▶` selected · `✓` done · `✗` failed (see `recon.log`) · `·` pending.
Press `?` for a full keybinding overlay. A selected module shows `needs: <module>`
when a prerequisite hasn't run yet.

---

## Modules

| # | Module | What it does | Key tools |
|---|--------|--------------|-----------|
| 1 | **Subdomain Enum** | Active + passive discovery, cert transparency, DNS bruteforce | subfinder, assetfinder, amass, chaos, crt.name, dnsx |
| 2 | **HTTP Probe + WAF** | Live detection, tech stack, WAF fingerprint, edge challenge classification | httpx, nuclei |
| 3 | **Origin Discovery** | CDN vs origin classification, direct-connect verification | cdncheck, dnsx |
| 4 | **Port Scanning** | Top-1000 ports + high-risk flagging (Docker, Redis, Elastic, etcd…) | naabu |
| 5 | **URL Collection** | Crawl + archive; interesting file detection; URL path tree | katana, waybackurls, gau, gospider |
| 6 | **JS Recon** | Endpoints, DOM sinks, secrets, source-map reconstruction (recovers original sources), admin routes, cloud assets, tech, page→JS map | jsluice, subjs, trufflehog, gitleaks |
| 7 | **Dir Bruteforce** | Content discovery against live URLs | ffuf |
| 8 | **Params + CORS** | Parameter classification (SSRF/IDOR/LFI/redirect), CORS deep-check, SSRF probe | arjun, nuclei |
| 9 | **Vuln Scan** | CVEs, exposures, misconfigs; CDN-aware; challenged host slow-pass | nuclei |
| 10 | **Sub Takeover** | Native CNAME + fingerprint detection (works tool-free): CONFIRMED / DANGLING / POTENTIAL, cross-checked with subzy + takeover templates | built-in, subzy, nuclei |
| 11 | **403 Bypass** | Header tricks + path variants, 15 goroutines in parallel | stdlib |
| 12 | **XSS Scan** | Reflected + DOM XSS; dedupes by param signature, caps volume, POC-only output to cut noise | dalfox, gf |
| 13 | **Dorks** | Scoped Google + GitHub dork queries ready to paste | — |
| 14 | **Cloud Buckets** | Bucket permutation + public access check | s3scanner |
| 15 | **Header Audit** | Security headers, host-header injection, CORS | nuclei, stdlib |
| 16 | **GraphQL Recon** | Endpoint discovery, introspection test, batch query check | nuclei, stdlib |
| 17 | **TLS / SSL** | Cert expiry, deprecated protocols, nuclei SSL templates | openssl, nuclei |

### Category shortcuts

| Category | Modules | TUI key | CLI |
|----------|---------|---------|-----|
| RECON | 1–6 | `E` | `--_run-category recon` |
| ATTACK | 7–12 | `A` | `--_run-category attack` |
| INTEL | 13–17 | `I` | `--_run-category intel` |

---

## TUI Keys

| Key | Action |
|-----|--------|
| `↑↓` / `j k` | Navigate modules |
| `Enter` / `Space` | Run selected module |
| `Tab` / `Shift+Tab` | Jump between categories |
| `g` / `G` | First / last module |
| `1`–`9` | Jump to module by number |
| `E` / `A` / `I` | Run full RECON / ATTACK / INTEL category |
| `F` | Run all 17 modules end-to-end |
| `R` | Generate text + HTML report |
| `D` | Check installed tools |
| `C` | Clear done state (re-run selected module) |
| `Q` / `ctrl+c` | Quit |

---

## CLI Flags

```bash
./tanya example.com                   # interactive TUI
./tanya example.com --full            # all 17 modules, headless
./tanya example.com --resume          # continue from last run
./tanya example.com --module nuclei   # run one module
./tanya example.com --passive         # skip active scans
./tanya example.com --single          # no subdomain enumeration
./tanya example.com --strict          # lock to exact FQDN
./tanya example.com --apex            # force full subdomain enum
./tanya --help
```

---

## Scope Modes

Scope is auto-detected from the target you provide.

| Target | Auto mode | Behaviour |
|--------|-----------|-----------|
| `example.com` | `apex` | full subdomain enumeration |
| `www.example.com` | `strict` | locked to exact FQDN, no sub-enum |
| `app.example.com/path` | `strict` | path stripped, locked to subdomain |
| `app.heroku.com` | `single` | PaaS — no sub-enum |
| `203.0.113.10` | `single` | IP — single host only |

PaaS platforms (Heroku, Vercel, Netlify, GitHub Pages, Cloudflare Workers, Fly.io, Render, ~25 others) are auto-detected and forced to single-host mode.

Override with `--strict`, `--single`, or `--apex` when needed.

---

## Output Structure

Everything lands in `output/<target>_<timestamp>/`. Using `--resume` reuses the same directory.

```
output/example.com_20260615_142301/
├── recon.log                              full ANSI-stripped log
├── .state                                 resume bookmarks
├── subdomains/
│   └── subs.txt                           discovered hosts
├── http/
│   ├── live_urls.txt                      live URLs with status + tech
│   ├── clean_urls.txt                     WAF/CDN-free URLs (used by active tools)
│   ├── challenged.txt                     hosts behind edge protection
│   └── interesting.txt                    high-value services (Jenkins, Grafana…)
├── origin/
│   └── confirmed_origins.txt              verified backend IPs
├── ports/
│   ├── ports.txt                          open ports
│   └── high_interest.txt                  high-risk ports
├── urls/
│   ├── urls.txt                           full URL archive
│   ├── site_tree.txt                      URL path tree grouped by host
│   └── interesting_files.txt              .env / .bak / .sql / .log URLs
├── js/
│   ├── potential_secrets.txt              API keys, tokens, credentials
│   ├── endpoints.txt                      API paths extracted from JS
│   ├── sinks.txt                          DOM XSS sinks (innerHTML, eval…)
│   ├── sourcemaps.txt                     exposed .map files (+ recovered count)
│   ├── recovered/                         original sources rebuilt from .map
│   ├── admin_routes.txt                   internal/admin routes in JS
│   ├── cloud_assets.txt                   S3/GCS/Azure URLs in JS
│   ├── technologies.txt                   fingerprinted tech stack
│   ├── page_js_map.json                   which pages load which JS files
│   └── …
├── fuzz/
│   └── findings.txt                       directory bruteforce results
├── params/
│   ├── ssrf_params.txt                    SSRF candidates
│   ├── idor_params.txt                    IDOR candidates
│   ├── lfi_params.txt                     LFI candidates
│   └── redirect_params.txt                open redirect candidates
├── nuclei/
│   ├── findings.txt                       all findings (deduped)
│   ├── cves.txt                           CVE matches
│   └── misconfig.txt                      misconfigurations
├── bypass403/
│   └── bypassed.txt                       confirmed 403 bypasses
├── takeover/
│   ├── takeovers.txt                      CONFIRMED / DANGLING / POTENTIAL
│   └── cnames.txt                         resolved CNAME map (host → target)
├── xss/
│   ├── dalfox_results.txt                 XSS proof-of-concept findings
│   └── dalfox_raw.txt                     unfiltered dalfox output
├── headers/
│   ├── cors_issues.txt                    CORS misconfigurations
│   └── host_injection.txt                 host-header injection hits
├── graphql/
│   ├── endpoints.txt                      GraphQL endpoints
│   └── introspection_enabled.txt          introspection-enabled endpoints
├── ssl/
│   └── issues.txt                         cert expiry + TLS issues
└── report/
    ├── report.txt                         text summary + site tree + file tree
    └── report.html                        interactive HTML report
```

---

## Installation

### Automated

```bash
./install.sh                 # core + recommended tools
./install.sh --optional      # + optional tools
./install.sh --seclists      # + SecLists wordlists
./install.sh --all           # everything
./install.sh --minimal       # Go + build only
```

### Manual build

Requires Go 1.22+.

```bash
go mod tidy
go build -ldflags="-s -w" -o tanya .
./tanya --help
```

### Requirements

| Requirement | Notes |
|-------------|-------|
| Go 1.22+ | Build only — not needed at runtime |
| Linux, macOS, or WSL 2 | Binary targets |
| `python3` | HTML report generation |
| `curl` | Used by install script |

All recon tools are optional — missing tools produce a warning and the relevant module is skipped.

---

## Configuration

`config.env` lives next to the binary and is loaded automatically. All fields are optional.

```bash
# Threading and rate limits
HTTPX_THREADS=100
NAABU_THREADS=200
NAABU_RATE=2000
FFUF_THREADS=100
KATANA_DEPTH=5

# Wordlists
FFUF_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"

# API keys (leave blank to silently skip the feature)
SECURITYTRAILS_API_KEY=""
SHODAN_API_KEY=""
```

---

## HTML Report

Running `R` in the TUI or `./tanya <target> --module report` generates:

- `report.txt` — plain text summary, URL path tree, file tree
- `report.html` — self-contained interactive report (no CDN, works offline)

The HTML report includes:
- Severity-weighted triage card (where to start)
- All findings grouped by type with one-click copy
- Site URL tree showing the target's path structure
- Page → JS file mapping (expand any page to see its scripts)
- Force-directed attack surface graph
- Full-text search across all sections

On WSL, the report path is printed as `\\wsl.localhost\...` so you can open it directly in a Windows browser.

---

## Project Structure

```
Tanya/
├── main.go                    entry point, CLI flags, banner
├── go.mod / go.sum
├── Makefile
├── internal/
│   ├── config/config.go       config struct + config.env loader
│   ├── target/target.go       target parsing, PaaS detection, scope modes
│   ├── state/state.go         thread-safe resume state
│   ├── runner/runner.go       subprocess helpers, file helpers, output
│   ├── modules/modules.go     all 17 modules
│   └── tui/tui.go             Bubbletea TUI
├── tanya_report.py            HTML report generator
├── config.env                 runtime overrides
└── install.sh                 dependency installer
```

---

## Roadmap

- [ ] Headless browser integration for DOM-based XSS testing (hash fragment sinks)
- [ ] Authenticated scanning via cookie or header auth in config
- [ ] Differential scanning — compare two runs and show what changed
- [ ] Nuclei false-positive filtering layer
- [ ] Secret scanning extended to HTML pages and JSON API responses
- [ ] HTTP method fuzzing in parameter discovery

---

## Contributing

Bug reports and pull requests are welcome. A few ground rules:

- Keep modules self-contained — each module should clean up after itself and work when run in isolation via `--module`
- New tools should degrade gracefully when not installed
- The binary must build with `go build ./...` with no warnings

---

## Disclaimer

This tool makes active network requests against remote systems. Running it against targets you do not own or are not authorized to test is illegal and will get you banned from bug bounty programs. Use it only within scope — a bug bounty program you're enrolled in, a signed pentest agreement, or your own infrastructure.
