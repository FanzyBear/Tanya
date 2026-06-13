# Tanyaaaa~ — Web Recon Pipeline

A single-file Bash pipeline that orchestrates the common open-source web-recon
tools (subdomain enumeration → HTTP probing → origin discovery → port scanning →
URL/JS collection → fuzzing → vuln scanning → cloud checks) and rolls everything
up into a prioritized, human-readable report. Output is plain `txt`/`jsonl` on
disk — no database, no daemon, nothing to clean up.

> ⚠️ **Authorization.** Only scan assets you own or are explicitly authorized
> (in scope) to test. You are responsible for how you use this tool.

---

## Highlights

- **One target, one command.** Point it at a domain, URL, or IP and it figures
  out the right mode (apex vs. single host) on its own.
- **Resumable.** State is tracked per run, so `--resume` continues where an
  interrupted scan left off instead of redoing finished modules.
- **Prioritized report.** A `WHERE TO START` triage block ranks findings by
  signal (critical vulns and public buckets first, candidates to test last) and
  points at the exact file for each.
- **No clutter.** Empty output files are pruned automatically — the run
  directory only ever contains files that actually have findings.
- **Readable TUI.** Auto-width, color-aware boxes for the run config and the
  completion summary; the interactive menu marks modules you've already run with
  a ✓.
- **Degrades gracefully.** Missing optional tools are skipped, not fatal. Only
  `curl` and `jq` are hard requirements.

---

## Quick start

```bash
git https://github.com/FanzyBear/Tanya.git && cd tanya
./install.sh            # installs deps (see Installation below)
./tanya.sh example.com --full
```

No arguments launches an interactive menu:

```bash
./tanya.sh example.com
```

---

## Usage

```
./tanya.sh <target> [options]
```

### Targets

| Target                         | Behavior                              |
| ------------------------------ | ------------------------------------- |
| `example.com`                  | apex domain — subdomain enum **on**   |
| `https://app.example.com/path` | URL — scheme/path stripped            |
| `app.herokuapp.com`            | PaaS host — auto single-host mode     |
| `203.0.113.10`                 | IP — single-host mode                 |

PaaS hosts (Heroku, Vercel, Netlify, Pages, Workers, S3/CloudFront, etc.) are
detected automatically and treated as single apps rather than enumerable apexes.

### Options

| Flag               | Description                                                        |
| ------------------ | ----------------------------------------------------------------- |
| `--full`           | Run every module end-to-end                                       |
| `--resume`         | Continue the most recent run for this target                      |
| `--module <name>`  | Run a single module                                               |
| `--single`         | Force single-host mode (skip subdomain enum)                      |
| `--apex`           | Force apex mode (do subdomain enum)                               |
| `--passive`        | Quiet mode: skip noisy active scans (ports, fuzz, nuclei, crawl, origin verification) |
| `--help`           | Show help                                                         |

### Examples

```bash
./tanya.sh example.com                          # interactive menu
./tanya.sh example.com --full                   # full pipeline
./tanya.sh https://juice-shop.herokuapp.com/    # auto single-host
./tanya.sh app.example.com --apex --full        # force enum on the apex
./tanya.sh example.com --single --full          # one host, no enum
./tanya.sh example.com --resume                 # continue last run
./tanya.sh example.com --module nuclei          # just run nuclei
./tanya.sh example.com --full --passive         # recon without active scans
```

---

## Modules

Run any of these individually with `--module <name>`:

| Module       | What it does                                                       |
| ------------ | ----------------------------------------------------------------- |
| `subdomains` | Subdomain enumeration (subfinder / assetfinder / amass) or seed   |
| `http`       | Live-host probing + WAF detection (httpx)                         |
| `origin`     | Origin-IP discovery behind CDNs (DNS history, Shodan/SecurityTrails, cdncheck) |
| `ports`      | Port scanning (naabu) + high-interest service flagging            |
| `urls`       | URL collection (katana crawl, waybackurls, gau)                   |
| `js`         | JavaScript recon — endpoints + secret hunting (trufflehog/gitleaks) |
| `fuzz`       | Directory/content brute-force (ffuf)                              |
| `params`    | Parameter discovery (arjun) + interesting-param tagging           |
| `nuclei`     | Templated vulnerability scanning (nuclei)                         |
| `dorks`      | Google / GitHub dork suggestions                                  |
| `cloud`      | Cloud bucket recon (s3scanner)                                    |
| `report`     | Generate the prioritized report from existing output             |

---

## Output

Everything lands under `output/<target>_<timestamp>/`:

```
output/example.com_20260613-185300/
├── recon.log                 # full run log
├── .state                    # resume bookkeeping
├── subdomains/               # subs.txt …
├── http/                     # live_urls.txt, interesting.txt, waf.txt …
├── origin/                   # origins.txt, confirmed_origins.txt …
├── ports/                    # ports.txt, high_interest.txt …
├── urls/                     # urls.txt …
├── js/                       # endpoints.txt, potential_secrets.txt …
├── params/                   # parameterized.txt, redirect_params.txt …
├── nuclei/                   # findings.txt, cves.txt …
├── cloud/                    # open_buckets.txt …
├── fuzz/                     # ffuf results …
├── dorks/                    # generated dork queries …
└── report/report.txt         # the report (also printed to the terminal)
```

Empty files are pruned automatically, so anything you see has content. The
report's `WHERE TO START` section is the recommended entry point:

```
[!!!] critical / act now      e.g. critical nuclei findings, public buckets
[!! ] high                    high findings, CVEs, leaked secrets
[!  ] notable                 confirmed origin IPs, exposed services, risky ports
[ ? ] candidate to test       SSRF / IDOR / LFI / open-redirect candidates
```

---

## Installation

The bundled `install.sh` handles dependencies. Run it from the repo directory:

```bash
./install.sh             # core + recommended tools
./install.sh --optional  # also install optional tools (arjun, s3scanner, etc.)
./install.sh --seclists  # also clone SecLists wordlists into ~/SecLists
./install.sh --all       # everything above
```

See the script header for what each flag installs and the package managers it
supports. If you'd rather install by hand, the dependency tiers are:

- **Core (required):** `curl`, `jq`
- **Recommended:** `subfinder`, `httpx`, `naabu`, `nuclei`, `katana`, `ffuf`
- **Optional:** `assetfinder`, `amass`, `waybackurls`, `gau`, `arjun`,
  `trufflehog`, `gitleaks`, `s3scanner`, plus `host`/`nslookup`/`nc`/`python3`
  from your base system. `dnsx` and `cdncheck` further improve origin discovery.

Most of the recommended/optional tools are Go binaries installable via
`go install`; ProjectDiscovery ships them under `github.com/projectdiscovery/...`.

---

## Configuration

Drop a `config.env` next to `tanya.sh` to override defaults (it's sourced at
startup). All keys are optional:

```bash
# config.env
HTTPX_THREADS=50
NAABU_THREADS=100
NAABU_RATE=1000
KATANA_DEPTH=3
FFUF_THREADS=40
FFUF_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"
CURL_UA="Mozilla/5.0 (recon; +tanya.sh)"

# Optional API keys — enable richer origin discovery; left blank = skipped
SECURITYTRAILS_API_KEY=""
SHODAN_API_KEY=""
```

`install.sh` writes a starter `config.env` for you if one doesn't already exist.

---

## Requirements

- Bash 4+ (`box`/menu use arrays and `%b` printf)
- A Unix-like environment (Linux / macOS / WSL)
- `curl` and `jq` at minimum; everything else degrades gracefully

---

## Disclaimer

This tool automates reconnaissance that touches remote systems. Running it
against hosts you don't own or aren't authorized to test may be illegal. Use it
only within the scope of a sanctioned engagement (bug bounty, pentest with a
signed agreement, your own infrastructure). The authors assume no liability for
misuse.