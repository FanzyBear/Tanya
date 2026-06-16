# Tanya — Bug Bounty Web Recon Pipeline

```
  ████████╗ █████╗ ███╗   ██╗██╗   ██╗  █████╗        _._     _,-'""`-._
     ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝ ██╔══██╗    (,-.`._,'(       |\`-/|
     ██║   ███████║██╔██╗ ██║ ╚████╔╝  ███████║         `-.-' \ )-`( , o o)
     ██║   ██╔══██║██║╚██╗██║  ╚██╔╝   ██╔══██║              `-    \`_`"'-
     ██║   ██║  ██║██║ ╚████║   ██║    ██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═╝  ╚═╝

  Bug Bounty Web Recon Pipeline  v6.2  ·  Go + Bubbletea TUI  ·  authorized targets only
```

A single compiled Go binary that orchestrates a 17-module web recon pipeline. Launch it, get a full-screen Bubbletea TUI with live stats — or pass `--full` for a headless end-to-end run.

> **Authorization.** Only scan assets you own or are explicitly in-scope for. You are responsible for how you use this tool.

---

## Quick start

```bash
git clone https://github.com/FanzyBear/Tanya.git && cd Tanya
./install.sh --all          # install Go + recon tools + SecLists, build binary

./tanya example.com         # full-screen TUI
./tanya example.com --full  # headless, run all 17 modules
```

---

## Interface

Launch without flags to get the full-screen TUI:

```
  ──────────────────────────────────────────────────────────────────────────────
   ◆ TANYA  v6.2  ›  example.com  [apex]                      7/17  ████░░░░  41%
     output/example.com_20260615_142301
  ──────────────────────────────────────────────────────────────────────────────

  ◆ RECON ──────────────────────────────────────────────────────────────────────

  ✓  1  Subdomain Enum    ✓  2  HTTP Probe + WAF    ▶  3  Origin Discovery
  ✓  4  Port Scanning     ✓  5  URL Collection         6  JS Recon

  ◆ ATTACK ─────────────────────────────────────────────────────────────────────

     7  Dir Bruteforce       8  Params + CORS           9  Vuln Scan
    10  Sub Takeover        11  403 Bypass             12  XSS Scan

  ◆ INTEL ──────────────────────────────────────────────────────────────────────

    13  Dorks              14  Cloud Buckets           15  Header Audit
    16  GraphQL Recon      17  TLS / SSL

  ──────────────────────────────────────────────────────────────────────────────
  subs:247  live:89  nuclei:12  secrets:3  xss:0  bypass:2  graphql:0  ssl:1
  ──────────────────────────────────────────────────────────────────────────────
  ↑↓/jk nav  ↵ run  tab cat  g/G first/last  F full  R report  D deps  Q quit
  E RECON  A ATTACK  I INTEL  C clear done  1-9 jump
  ──────────────────────────────────────────────────────────────────────────────
  ✓  nuclei  ·  14 findings  ·  2m12s
  ▶  Vuln Scan  ·  Severity scan + exposures + misconfig across all live targets
```

### TUI keys

| Key | Action |
|-----|--------|
| `↑↓` / `j k` | navigate modules |
| `Enter` / `Space` | run selected module |
| `tab` / `shift+tab` | jump to next / previous category |
| `g` / `G` | jump to first / last module |
| `1`–`9` | jump to module by number |
| `E` | run full **RECON** category (modules 1–6) |
| `A` | run full **ATTACK** category (modules 7–12) |
| `I` | run full **INTEL** category (modules 13–17) |
| `F` | run all 17 modules end-to-end |
| `R` | generate text + HTML report |
| `D` | dependency check |
| `C` | clear done state for selected module (re-run it) |
| `Q` / `ctrl+c` | quit |

After each module finishes, the TUI shows a result line: `✓ nuclei · 14 findings · 2m12s`.

### CLI flags

```bash
./tanya example.com                   # interactive TUI
./tanya example.com --full            # all 17 modules end-to-end
./tanya example.com --resume          # continue last run (log + state preserved)
./tanya example.com --module nuclei   # run a single module
./tanya example.com --passive         # skip noisy active scans
./tanya example.com --single          # force single-host (no subdomain enum)
./tanya example.com --strict          # lock crawler + URLs to exact FQDN only
./tanya example.com --apex            # force apex mode (enum from registrable root)
./tanya --help
```

---

## Modules

| # | Module | What it does | Key tools |
|---|--------|--------------|-----------|
| 1 | **Subdomain Enum** | Active + passive discovery, cert transparency, DNS bruteforce | subfinder · assetfinder · amass · chaos · crt.sh · dnsx |
| 2 | **HTTP Probe + WAF** | Live service detection, tech stack, WAF fingerprint, edge challenge classification (Cloudflare / Akamai / Imperva / DataDome / PerimeterX / AWS WAF) | httpx · nuclei |
| 3 | **Origin Discovery** | CDN vs origin IP classification, direct-connect verification | cdncheck · dnsx |
| 4 | **Port Scanning** | Top-1000 ports + high-risk port flagging (Docker / Redis / Elastic / etcd …) | naabu · nc fallback |
| 5 | **URL Collection** | Crawl + archive (wayback/gau/gospider), interesting file detection | katana · waybackurls · gau · gospider |
| 6 | **JS Recon** | JS download + comprehensive extraction: endpoints, DOM sinks, secrets, tech fingerprinting, admin routes, cloud assets, source maps, subdomains, GraphQL patterns | jsluice · subjs · trufflehog · gitleaks · regexp fallback |
| 7 | **Dir Bruteforce** | Content discovery against live URLs; results aggregated into `fuzz/findings.txt` | ffuf |
| 8 | **Params + CORS** | Param classification (SSRF/IDOR/LFI/redirect), nuclei SSRF probe on candidates | arjun · nuclei |
| 9 | **Vuln Scan** | Severity low→critical + exposures + misconfig; gentle pass on WAF-challenged hosts; CDN-aware (origin IPs included) | nuclei |
| 10 | **Sub Takeover** | CNAME-based detection + nuclei takeover templates | subzy · nuclei |
| 11 | **403 Bypass** | Header tricks + path variants on blocked endpoints — **parallel** (15 goroutines) | stdlib net/http |
| 12 | **XSS Scan** | gf pre-filter → dalfox reflected/DOM XSS | dalfox · gf |
| 13 | **Dorks** | Ready-to-paste Google + GitHub dork queries scoped to the exact target host | — |
| 14 | **Cloud Buckets** | Bucket name permutation (from registrable apex) + public access check; raw output preserved, noise-filtered results separate | s3scanner |
| 15 | **Header Audit** | Security headers, host-header injection, CORS deep-check (null origin + reflected origin) | nuclei · stdlib |
| 16 | **GraphQL Recon** | Endpoint discovery, introspection test, batch query check, nuclei GraphQL templates | stdlib · nuclei |
| 17 | **TLS / SSL** | Certificate expiry, nuclei SSL/TLS templates | openssl · nuclei |

### Category runs

The three categories can be run with a single key in the TUI or via `--_run-category`:

| Category | Modules | TUI key |
|----------|---------|---------|
| **RECON** | Subdomains, HTTP, Origin, Ports, URLs, JS | `E` |
| **ATTACK** | Fuzz, Params, Nuclei, Takeover, 403bypass, XSS | `A` |
| **INTEL** | Dorks, Cloud, Headers, GraphQL, SSL | `I` |

---

## Target formats & scope modes

Scope is **auto-detected** from the target you provide — no flags needed for the common cases:

| Target | Auto scope | Behaviour |
|--------|-----------|-----------|
| `example.com` | `apex` | full subdomain enumeration from `example.com` |
| `www.example.com` | `strict` | **locked to `www.example.com` only** — crawler + URLs filtered to exact FQDN |
| `app.example.com/path` | `strict` | scheme + path stripped; locked to `app.example.com` |
| `app.herokuapp.com` | `single` | PaaS host — no subdomain enum, exact host only |
| `203.0.113.10` | `single` | IP — single-host mode |

PaaS platforms (Heroku, Vercel, Netlify, GitHub Pages, Cloudflare Workers, Fly.io, Render, …) are auto-detected and forced to single-host mode.

The rule: if the host you supply **is** the registrable apex (e.g. `example.com`, `example.co.uk`) → `apex` mode. If it's a subdomain (e.g. `www.example.com`, `api.staging.example.com`) → `strict` mode automatically.

### Override flags

| Flag | Mode | Use when |
|------|------|----------|
| `--strict` | `strict` | force strict even on a bare apex |
| `--single` | `single` | no enum, no URL filtering (just probe the one host) |
| `--apex` | `apex` | force full subdomain enum even on a subdomain target |

---

## Output

Everything lands under `output/<target>_<timestamp>/`. On `--resume`, the previous directory is reused and `recon.log` + `.state` are **appended to**, not overwritten.

The final `report/report.txt` shows a summary, a **crawl map** (URL path tree grouped by host), and an ASCII file tree of everything produced:

```
output/example.com_20260615_142301/
├── recon.log                              full ANSI-stripped log
├── .state                                 resume bookmarks (one module name per line)
├── subdomains/
│   └── subs.txt                           in-scope hosts
├── http/
│   ├── live_urls.txt                      all live URLs (status + tech)
│   ├── clean_urls.txt                     challenge-free URLs (used by nuclei / fuzz / crawl)
│   ├── challenged.txt                     hosts behind Cloudflare / Akamai / etc.
│   └── interesting.txt                    high-value services (Jenkins, Grafana, …)
├── origin/
│   └── confirmed_origins.txt              verified backend IPs (CDN bypassed)
├── ports/
│   ├── ports.txt                          open ports (host:port)
│   └── high_interest.txt                  high-risk ports (Docker, Redis, Elastic …)
├── urls/
│   ├── urls.txt                           full URL archive (katana + wayback + gau + gospider)
│   ├── gospider.txt                       URLs discovered by gospider spider
│   └── interesting_files.txt             .env / .bak / .sql / .js / .log URLs
├── js/
│   ├── js_urls.txt                        JS file URLs collected (katana crawl + subjs)
│   ├── subjs_urls.txt                     additional JS URLs discovered by subjs
│   ├── potential_secrets.txt              secret hits (jsluice / trufflehog / gitleaks / regex)
│   ├── endpoints.txt                      API endpoints extracted from JS (jsluice + regex)
│   ├── sinks.txt                          DOM XSS sink patterns (innerHTML, eval, document.write …)
│   ├── sourcemaps.txt                     source map references (exposed .map files)
│   ├── technologies.txt                   technology fingerprints found in JS
│   ├── admin_routes.txt                   admin / internal route strings in JS
│   ├── cloud_assets.txt                   cloud storage URLs / ARNs found in JS
│   ├── subdomains.txt                     subdomains discovered via JS analysis
│   ├── js_params.txt                      parameter names extracted from JS
│   ├── comments.txt                       inline JS comments with sensitive patterns
│   ├── html_comments.txt                  HTML page comments with sensitive patterns
│   └── graphql.txt                        GraphQL schema / query patterns in JS
├── fuzz/
│   └── findings.txt                       aggregated ffuf discovery results
├── params/
│   ├── parameterized.txt                  URLs with query parameters
│   ├── ssrf_params.txt                    SSRF candidates
│   └── nuclei_ssrf.txt                    nuclei SSRF probe results (if any)
├── nuclei/
│   ├── findings.txt                       all unique vuln findings (deduped)
│   ├── cves.txt                           CVE matches
│   ├── exposures.txt                      exposure findings
│   └── misconfig.txt                      misconfig findings
├── bypass403/
│   └── bypassed.txt                       confirmed 403 bypasses
├── xss/
│   └── dalfox_results.txt                 XSS findings
├── dorks/
│   ├── google_dorks.txt                   ready-to-paste Google dork queries
│   └── github_dorks.txt                   ready-to-paste GitHub dork queries
├── cloud/
│   ├── bucket_names.txt                   generated bucket name permutations
│   ├── s3_raw.txt                         raw s3scanner output (preserved for debug)
│   ├── s3_results.txt                     noise-filtered bucket scan results
│   └── open_buckets.txt                   publicly accessible buckets
├── headers/
│   ├── cors_issues.txt                    CORS misconfigurations
│   └── host_injection.txt                 host-header injection hits
├── graphql/
│   ├── endpoints.txt                      discovered GraphQL endpoints
│   └── introspection_enabled.txt          endpoints with introspection on
├── ssl/
│   └── issues.txt                         cert expiry + deprecated protocols
└── report/
    ├── report.txt                         prioritized WHERE TO START + file tree
    └── report.html                        interactive HTML report (electric terminal theme)
```

---

## Installation

```bash
./install.sh                 # core + recommended  (builds tanya binary)
./install.sh --optional      # + optional tools
./install.sh --seclists      # + SecLists → ~/SecLists
./install.sh --all           # everything
./install.sh --minimal       # core only (Go + build)
```

### Manual build

```bash
# Requires Go 1.22+
go mod tidy
go build -ldflags="-s -w" -o tanya .
./tanya --help
# or: make check   (runs go vet then build)
```

### Manual tool install

```bash
# ProjectDiscovery suite
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Fuzzing / crawling / archive
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/jaeles-project/gospider@latest

# JS analysis
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/lc/subjs@latest

# Bug bounty
go install github.com/hahwul/dalfox/v2@latest
go install github.com/PentestPad/subzy@latest
go install github.com/tomnomnom/gf@latest
go install github.com/gitleaks/gitleaks/v8@latest
go install github.com/sa7mon/s3scanner@latest
```

---

## Configuration

`config.env` sits next to the binary and is loaded at startup. All keys are optional.

```bash
# Threading & rate limits
HTTPX_THREADS=100
NAABU_THREADS=200
NAABU_RATE=2000
FFUF_THREADS=100
KATANA_DEPTH=5

# Nuclei tuning
# NUCLEI_RATE=150
# NUCLEI_CONC=25

# Wordlists
FFUF_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"

# API keys  (blank = feature silently skipped)
SECURITYTRAILS_API_KEY=""
SHODAN_API_KEY=""
```

---

## File structure

```
Tanya/
├── main.go                entry point + CLI flags + banner
├── go.mod / go.sum
├── Makefile               build / vet / install targets
├── internal/
│   ├── config/config.go   Config struct + config.env loader
│   ├── target/target.go   target parsing, PaaS detection, scope modes (apex/single/strict)
│   ├── state/state.go     thread-safe .state file for resume + MarkUndone
│   ├── runner/runner.go   exec helpers, file helpers, ANSI output
│   ├── modules/modules.go all 17 modules as methods on *Ctx + RunCategory
│   └── tui/tui.go         Bubbletea model + lipgloss view
├── tanya_report.py        interactive HTML report generator (python3, electric theme)
├── config.env             optional overrides (auto-created by install.sh)
└── install.sh             dependency installer
```

---

## Requirements

- Go 1.22+ (to build)
- Linux, macOS, or WSL 2 (binary targets)
- `curl` and `jq` — all other recon tools degrade gracefully when absent
- `python3` — for HTML report generation (`tanya_report.py`)

---

## Disclaimer

This tool automates active reconnaissance against remote systems. Running it against targets you do not own or are not authorized to test may be illegal in your jurisdiction. Use it only within the scope of a sanctioned engagement — a bug bounty program, a signed pentest agreement, or your own infrastructure. The authors assume no liability for misuse.
