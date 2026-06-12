# recon-pipeline

A modular, menu-driven web recon pipeline for bug bounty and penetration testing.

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

## Features

- **Interactive menu** — pick modules individually or run the full pipeline
- **8 recon modules** — subdomains, HTTP, ports, JS mining, params, dorks, cloud, screenshots
- **Graceful fallbacks** — works with whatever tools you have installed; warns on missing ones
- **Telegram alerts** — optional notifications after each phase
- **Timestamped output** — every run gets its own folder, nothing overwrites

## Quick Start

```bash
git clone https://github.com/yourname/recon-pipeline
cd recon-pipeline
chmod +x recon.sh install.sh

# Install dependencies
./install.sh

# Run interactively
./recon.sh example.com

# Run full pipeline
./recon.sh example.com --full

# Run a single module
./recon.sh example.com --module subdomains
./recon.sh example.com --module js
```

## Modules

| # | Module | Tools Used | What It Does |
|---|--------|-----------|--------------|
| 1 | `subdomains` | subfinder, amass, crt.sh, dnsx | Passive + active subdomain enum |
| 2 | `http` | httpx | Probe live services, detect tech |
| 3 | `ports` | naabu | Scan non-standard ports |
| 4 | `js` | gau, katana | Download JS, extract endpoints & secrets |
| 5 | `params` | gau, waybackurls | Mine historical URLs, filter juicy params |
| 6 | `dorks` | *(manual)* | Generate Google dorks list |
| 7 | `cloud` | s3scanner | Enumerate S3/cloud bucket permutations |
| 8 | `screenshots` | gowitness, eyewitness | Screenshot all live HTTP services |

## Output Structure

```
output/
└── example.com_20260611_143022/
    ├── subdomains/
    │   ├── subfinder.txt
    │   ├── amass.txt
    │   ├── crtsh.txt
    │   ├── all_subs.txt
    │   └── live_subs.txt       ← resolved live hosts
    ├── http/
    │   ├── httpx_results.txt
    │   ├── live_urls.txt
    │   └── interesting.txt     ← Jenkins, Grafana, admin panels
    ├── ports/
    │   ├── open_ports.txt
    │   └── high_interest.txt   ← Redis, MongoDB, Elasticsearch, Docker
    ├── js/
    │   ├── js_urls.txt
    │   ├── files/              ← downloaded JS files
    │   ├── endpoints.txt
    │   └── potential_secrets.txt
    ├── params/
    │   ├── all_urls.txt
    │   ├── parameterized.txt
    │   └── juicy_params.txt    ← SSRF/redirect/IDOR candidates
    ├── dorks/
    │   └── dorks.txt
    ├── cloud/
    │   ├── bucket_names.txt
    │   └── open_buckets.txt
    └── screenshots/
```

## Configuration

Copy `config.env` and fill in optional values:

```bash
# Telegram alerts
TELEGRAM_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"

# GitHub dorking (future module)
GITHUB_TOKEN="your_github_token"
```

## Dependencies

Installed automatically by `install.sh` (requires Go + Python3):

**Go tools:** subfinder, dnsx, httpx, naabu, katana, gau, waybackurls, gowitness, notify  
**Python tools:** s3scanner  
**Optional:** amass (via apt), eyewitness

## Usage

```
./recon.sh <domain>                     Interactive menu
./recon.sh <domain> --full              Run full pipeline
./recon.sh <domain> --module <name>     Run specific module
./recon.sh --help
```

## Legal

Only use against targets you have explicit permission to test.  
Always stay within program scope.  
Report responsibly.
