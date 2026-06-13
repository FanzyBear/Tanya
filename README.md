# tanyaa — Web Recon Pipeline

A modular, resumable web reconnaissance pipeline that chains together the best open-source recon tools into a single script. Run everything at once or pick individual modules. Results land in clean, organized text files — no database required.

```
  ████████╗ █████╗ ███╗   ██╗██╗   ██╗ █████╗  █████╗
     ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗
     ██║   ███████║██╔██╗ ██║ ╚████╔╝ ███████║███████║
     ██║   ██╔══██║██║╚██╗██║  ╚██╔╝  ██╔══██║██╔══██║
     ██║   ██║  ██║██║ ╚████║   ██║   ██║  ██║██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
         Web Recon Pipeline v4.0 (txt-only)
```

---

## Features

- **11 recon modules** covering the full passive-to-active attack surface
- **Resume support** — interrupted runs pick up where they left off
- **Interactive menu** or fully automated `--full` pipeline
- **Telegram notifications** for long-running scans
- **No database** — all output is plain `.txt` and `.json`

---

## Modules

| # | Module | Tools |
|---|--------|-------|
| 1 | Subdomain Enumeration | subfinder, assetfinder, amass, crt.sh |
| 2 | HTTP Probing | httpx |
| 3 | Port Scanning | naabu (nc fallback) |
| 4 | Screenshots | gowitness (eyewitness fallback) |
| 5 | URL Collection | katana, waybackurls, gau |
| 6 | JavaScript Recon | curl + grep (endpoints, secrets) |
| 7 | Directory Bruteforce | ffuf + SecLists |
| 8 | Parameter Discovery | arjun + passive URL classification |
| 9 | Vulnerability Scanning | nuclei (CVEs, exposures, misconfigs) |
| 10 | Google Dorks | Generated dork list (manual) |
| 11 | Cloud Bucket Recon | s3scanner |

---

## Installation

```bash
git clone https://github.com/fanzybear/tanya.git
cd tanya
chmod +x install.sh tanyaa.sh
./install.sh
```

`install.sh` installs all Go tools, pip tools, and system packages, pulls nuclei templates, and optionally clones SecLists.

**Requirements:** Go 1.21+, Python 3, pip3, git

---

## Usage

```bash
# Interactive menu
./tanyaa.sh example.com

# Full automated pipeline
./tanyaa.sh example.com --full

# Resume an interrupted run
./tanyaa.sh example.com --resume

# Single module
./tanyaa.sh example.com --module nuclei
```

Available module names: `subdomains` `http` `ports` `screenshots` `urls` `js` `fuzz` `params` `nuclei` `dorks` `cloud` `report`

---

## Configuration

Copy or create `config.env` in the same directory as the script:

```bash
# config.env

# Telegram notifications (optional)
TELEGRAM_TOKEN=""
TELEGRAM_CHAT_ID=""

# Tool tuning
HTTPX_THREADS=50
NAABU_THREADS=100

# Wordlist for ffuf (module 7)
FFUF_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"
```

---

## Output Structure

Each run creates a timestamped folder under `./output/`:

```
output/example.com_20250601_120000/
├── subdomains/
│   ├── subs.txt              # merged, deduplicated subdomains
│   ├── subfinder.txt
│   ├── amass.txt
│   └── crtsh.txt
├── http/
│   ├── alive.txt             # full httpx output
│   ├── live_urls.txt
│   ├── status_200.txt
│   ├── status_401_403.txt
│   └── interesting.txt       # high-value services (jenkins, kibana, etc.)
├── ports/
│   ├── ports.txt
│   └── high_interest.txt     # flagged ports (redis, docker, elastic, etc.)
├── screenshots/              # gowitness/eyewitness output
├── urls/
│   ├── urls.txt              # merged from katana + wayback + gau
│   └── interesting_files.txt # .env, .sql, .bak, .log, etc.
├── js/
│   ├── js_urls.txt
│   ├── files/                # downloaded JS files
│   ├── endpoints.txt
│   └── potential_secrets.txt # API keys, tokens, DSNs
├── fuzz/                     # ffuf JSON results per target
├── params/
│   ├── parameterized.txt
│   ├── ssrf_params.txt
│   ├── redirect_params.txt
│   ├── idor_params.txt
│   └── lfi_params.txt
├── nuclei/
│   ├── nuclei.txt
│   ├── nuclei_cves.txt
│   ├── nuclei_exposures.txt
│   └── nuclei_misconfig.txt
├── dorks/
│   ├── dorks.txt             # Google dorks (manual browser use)
│   └── github_dorks.txt
├── cloud/
│   ├── bucket_names.txt
│   ├── s3_results.txt
│   └── open_buckets.txt
├── report/
│   └── report.txt            # summary of all findings
├── recon.log
└── .state                    # resume checkpoint
```

---

## Disclaimer

This tool is for authorized security testing and bug bounty research only. Only run against targets you have explicit permission to test. The author is not responsible for misuse.

---

## License

MIT