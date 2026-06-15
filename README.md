# Tanya — Bug Bounty Web Recon Pipeline

```
 ████████╗ █████╗ ███╗   ██╗██╗   ██╗  █████╗
    ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝ ██╔══██╗
    ██║   ███████║██╔██╗ ██║ ╚████╔╝  ███████║
    ██║   ██╔══██║██║╚██╗██║  ╚██╔╝   ██╔══██║
    ██║   ██║  ██║██║ ╚████║   ██║    ██║  ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═╝  ╚═╝

  Bug Bounty Web Recon Pipeline  v6.2  ·  web-focused · authorized targets only
```

A multi-file Bash pipeline built for bug bounty web recon. Point it at a target, run `--full`, and get a prioritized report — critical findings first, manual candidates last.

> **Authorization.** Only scan assets you own or are explicitly in-scope for. You are responsible for how you use this tool.

---

## Quick start

```bash
git clone https://github.com/FanzyBear/Tanya.git && cd Tanya
./install.sh --all               # install everything + SecLists

# Python TUI  (arrow-key menu, live stats, rich output)
python3 tanya_ui.py example.com

# Bash CLI
./tanya.sh example.com           # interactive number menu
./tanya.sh example.com --full    # run all 17 modules end-to-end
```

---

## Two interfaces

### Python TUI  `tanya_ui.py`  *(recommended)*

Arrow-key menu, live stats sidebar, color-coded output panels.

```
pip install rich          # one-time
python3 tanya_ui.py <target>
python3 tanya_ui.py <target> --full
python3 tanya_ui.py <target> --module nuclei
python3 tanya_ui.py <target> --passive
python3 tanya_ui.py <target> --resume
```

Requires Linux / macOS / WSL (curses). Falls back to a number menu on environments without curses.

### Bash CLI  `tanya.sh`

```
./tanya.sh <target> [options]
```

| Flag | Description |
|------|-------------|
| `--full` | Run all 17 modules end-to-end |
| `--resume` | Continue the most recent run for this target |
| `--module <name>` | Run a single module |
| `--single` | Force single-host mode (skip subdomain enum) |
| `--apex` | Force apex mode (always run subdomain enum) |
| `--passive` | Skip active/noisy scans (ports, fuzz, nuclei, crawl, bypass, xss) |
| `--help` | Show help |

---

## Modules

| # | Module | What it does | Key tools |
|---|--------|--------------|-----------|
| 1 | **Subdomain Enum** | Active + passive discovery, cert transparency | subfinder · assetfinder · amass · chaos · puredns · crt.sh · dnsx |
| 2 | **HTTP Probe + WAF** | Live service detection, tech stack, WAF fingerprint, edge challenge classification | httpx · nuclei waf |
| 3 | **Origin Discovery** | CDN vs origin IP, historical A records, title-match verification | cdncheck · dnsx · SecurityTrails · Shodan |
| 4 | **Port Scanning** | CDN-aware scan, high-risk port flagging, web-service probe | naabu · httpx · nc |
| 5 | **URL Collection** | Crawl + archive, interesting files, sensitive path probe | katana · hakrawler · waybackurls · gau |
| 6 | **JavaScript Recon** | Secret scanning, API endpoint extraction | trufflehog · gitleaks · Python regex |
| 7 | **Dir Bruteforce** | Content discovery against live URLs | ffuf |
| 8 | **Params + CORS** | Param classification, SSRF/IDOR/LFI/redirect candidates, CORS, HTTP methods | arjun · gf · curl |
| 9 | **Vuln Scan** | Web-only nuclei (never raw IPs), CVEs, misconfigs, exposures | nuclei |
| 10 | **Subdomain Takeover** | CNAME-based detection + nuclei takeover templates | subzy · nuclei |
| 11 | **403/401 Bypass** | Header tricks + path variants on blocked endpoints | curl |
| 12 | **XSS Scan** | gf pre-filter → dalfox | dalfox · gf |
| 13 | **Dorks** | Ready-to-paste Google + GitHub dork lists | — |
| 14 | **Cloud Buckets** | Name permutation + public bucket check | s3scanner |
| 15 | **Header Audit** | Security headers (HSTS, CSP, X-Frame-Options…), host-header injection probe, CORS deep-check, CRLF injection | nuclei · curl |
| 16 | **GraphQL Recon** | Endpoint discovery (15 common paths), introspection test, batch query check, nuclei GraphQL templates | curl · nuclei |
| 17 | **TLS / SSL** | Certificate expiry, deprecated protocols (TLS 1.0/1.1), nuclei SSL/TLS templates | openssl · nuclei |

Reports (modules 18–19) generate a prioritized text report and an interactive HTML report.

---

## Target formats

| Target | Mode |
|--------|------|
| `example.com` | apex — subdomain enum ON |
| `https://app.example.com/path` | URL — scheme/path stripped, apex mode |
| `app.herokuapp.com` | PaaS host — auto single-host (no subdomain enum) |
| `203.0.113.10` | IP — single-host mode |

PaaS platforms (Heroku, Vercel, Netlify, GitHub Pages, Cloudflare Workers, Fly.io, Render, …) are auto-detected.

---

## Web-focused design

1. **HTTP probe first** — `httpx` confirms every live HTTP/HTTPS URL before anything else runs.
2. **CDN detection** — `cdncheck` classifies IPs. If all IPs are shared CDN (GitHub Pages, Cloudflare, Fastly…), port scanning is skipped entirely — scanning shared CDN IPs returns results for all their tenants, not just your target.
3. **Port scan → web probe** — After `naabu` finds open ports, `httpx` re-probes web-looking ports. Only confirmed HTTP/HTTPS URLs reach nuclei.
4. **Origin IP → web probe** — When a real backend IP is found (CDN bypassed), `httpx` probes it before nuclei sees it. Nuclei never receives a raw IP.
5. **Edge challenge quarantine** — Cloudflare / Akamai / DataDome / PerimeterX challenged hosts are quarantined. Nuclei, ffuf, and crawlers only target clean URLs.

---

## Output

Everything lands under `output/<target>_<timestamp>/`:

```
output/example.com_20260615_142301/
├── recon.log                   full log (ANSI-stripped)
├── .state                      resume bookmarks
│
├── subdomains/
│   ├── subs.txt                in-scope hosts (normalized, deduplicated)
│   └── resolved_ips.txt        dnsx-confirmed IPs
│
├── http/
│   ├── live_urls.txt           all live HTTP/HTTPS URLs
│   ├── clean_urls.txt          challenge-free (used by nuclei / fuzz / crawl)
│   ├── challenged.txt          hosts behind Cloudflare / Akamai / etc.
│   ├── interesting.txt         Jenkins · Grafana · Swagger · GraphQL …
│   └── waf.txt                 WAF fingerprints
│
├── origin/
│   ├── cdn_ips.txt             IPs flagged as edge/CDN
│   ├── origin_candidates.txt   non-CDN IPs (unverified)
│   └── confirmed_origins.txt   verified backend IPs (title-match)
│
├── ports/
│   ├── ports.txt               open ports (host:port)
│   ├── high_interest.txt       Docker · Redis · Mongo · Elasticsearch · K8s
│   └── web_urls.txt            HTTP/HTTPS URLs from port scan (httpx-probed)
│
├── urls/
│   ├── urls.txt                deduplicated URL archive
│   ├── interesting_files.txt   .env · .sql · .bak · .log · .zip …
│   └── sensitive_paths.txt     robots.txt · .env · swagger · admin …
│
├── js/
│   ├── endpoints.txt           extracted API paths from JS files
│   └── potential_secrets.txt   secret hits (trufflehog / gitleaks / regex)
│
├── params/
│   ├── parameterized.txt       URLs with query parameters
│   ├── ssrf_params.txt         SSRF-likely parameter names
│   ├── redirect_params.txt     open-redirect parameter names
│   ├── idor_params.txt         IDOR-likely (id, user_id …)
│   ├── lfi_params.txt          LFI-likely (file, path, page …)
│   ├── cors_vuln.txt           CORS misconfigurations (reflected Origin)
│   └── methods_vuln.txt        dangerous HTTP methods (PUT / DELETE / TRACE)
│
├── nuclei/
│   ├── findings.txt            all unique findings (web URLs only)
│   ├── cves.txt                CVE matches
│   ├── exposures.txt           .git / .env / backup / directory listing
│   └── misconfig.txt           security-header / CORS / default-credential
│
├── takeover/
│   ├── takeovers.txt           subzy vulnerable candidates
│   └── nuclei_takeover.txt     nuclei takeover template hits
│
├── bypass403/
│   └── bypassed.txt            confirmed bypasses with technique
│
├── xss/
│   └── dalfox_results.txt      dalfox confirmed XSS
│
├── fuzz/                       ffuf JSON results per URL
├── dorks/                      google_dorks.txt · github_dorks.txt
├── cloud/                      bucket_names.txt · open_buckets.txt
│
├── headers/
│   ├── nuclei_headers.txt      security-header nuclei hits
│   ├── host_injection.txt      host-header reflection candidates
│   └── cors_issues.txt         CORS null-origin / reflection issues
│
├── graphql/
│   ├── endpoints.txt           discovered GraphQL endpoints
│   ├── introspection_enabled.txt  endpoints with introspection on
│   ├── batch_allowed.txt       endpoints accepting batch queries
│   └── nuclei_graphql.txt      nuclei GraphQL findings
│
├── ssl/
│   ├── https_hosts.txt         HTTPS hosts checked
│   ├── issues.txt              expiry warnings · deprecated protocols
│   ├── cert_info.txt           raw certificate metadata
│   └── nuclei_ssl.txt          nuclei SSL/TLS findings
│
└── report/
    ├── report.txt              prioritized WHERE TO START text report
    └── report.html             interactive filterable HTML report
```

### WHERE TO START legend

```
[!!!]  critical     critical nuclei · public buckets · subdomain takeover
[!! ]  high         high nuclei · CVEs · secrets · XSS · 403 bypass · CORS
[!  ]  notable      confirmed origin IPs · interesting services · high-risk ports
[ ? ]  candidate    SSRF · IDOR · LFI · open redirect · interesting files
```

---

## Installation

```bash
./install.sh                 # core + recommended
./install.sh --optional      # + optional tools
./install.sh --seclists      # + SecLists → ~/SecLists
./install.sh --all           # everything
./install.sh --minimal       # core only (curl jq python3 rich)
```

The installer also runs `pip install rich` for the Python TUI.

### Manual install (key tools)

```bash
# ProjectDiscovery suite
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

# Fuzzing / crawling
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hakluke/hakrawler@latest

# Bug bounty
go install github.com/hahwul/dalfox/v2@latest
go install github.com/PentestPad/subzy@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/gitleaks/gitleaks/v8@latest

# gf patterns
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/Gf-Patterns 2>/dev/null || true
cp ~/.gf/Gf-Patterns/*.json ~/.gf/ 2>/dev/null || true
```

---

## Configuration

`config.env` sits next to `tanya.sh` and is sourced at startup. All keys are optional — `install.sh` writes a starter file automatically.

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
SECURITYTRAILS_API_KEY=""   # historical IP lookup in origin module
SHODAN_API_KEY=""           # Shodan DNS records in origin module
```

---

## File structure

```
Tanya/
├── tanya.sh           main orchestrator  (bash, v6.1)
├── tanya_ui.py        Python TUI  (arrow-key menu, rich output)
├── tanya_report.py    interactive HTML report generator
├── lib/
│   ├── ui.sh          terminal UI — banner, spinner, progress bar, box
│   └── utils.sh       helpers — file ops, CDN detection, target parsing, state
├── config.env         optional overrides  (threads, rate limits, API keys)
└── install.sh         dependency installer  (core / recommended / optional)
```

---

## Requirements

- Bash 4.3+
- Linux, macOS, or WSL 2
- `curl` and `jq` — all other tools degrade gracefully

---

## WSL support

Under WSL 2, Tanya translates output paths to `\\wsl.localhost\…` UNC paths and prints a `file://` URL so the HTML report opens directly in a Windows browser.

---

## Disclaimer

This tool automates active reconnaissance against remote systems. Running it against targets you do not own or are not authorized to test may be illegal in your jurisdiction. Use it only within the scope of a sanctioned engagement — a bug bounty program, a signed pentest agreement, or your own infrastructure. The authors assume no liability for misuse.
