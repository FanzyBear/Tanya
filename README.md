# recon-pipeline v2.0

A modular, menu-driven web recon pipeline with asset correlation, scoring, and structured output.

## Quick Start

```bash
git clone https://github.com/yourname/recon-pipeline
cd recon-pipeline
chmod +x recon.sh install.sh

./install.sh              # install Go + pip tools
./recon.sh example.com    # interactive menu
```

## Usage

```
./recon.sh <domain>                       Interactive menu
./recon.sh <domain> --full                Full pipeline
./recon.sh <domain> --resume              Resume interrupted run
./recon.sh <domain> --module <name>       Single module
```

## Modules

| # | Module | Key Tools | What It Does |
|---|--------|-----------|--------------|
| 1 | `subdomains` | subfinder, amass, crt.sh, dnsx | Passive + active enum, normalisation, wildcard filtering |
| 2 | `http` | httpx | Probe services, classify by status, flag interesting tech |
| 3 | `ports` | naabu | Port scan, service scoring, flag Redis/Elastic/Docker |
| 4 | `js` | gau, katana | Parallel JS download, endpoint extraction, secret detection |
| 5 | `params` | gau, waybackurls | Historical URL mining, classify SSRF/redirect/IDOR/LFI |
| 6 | `dorks` | *(manual)* | Generate Google + GitHub dork lists |
| 7 | `cloud` | s3scanner | S3/GCS/Azure bucket permutation scan |
| 8 | `screenshots` | gowitness | Screenshot all live services |
| 9 | `correlate` | Python/SQLite | Cross-link all findings, score, generate report |

## What's New in v2.0

### Correctness fixes
- **No more `set -e` + `|| true` conflict** — strict error model, intentional suppression only
- **Input validation** — FQDN regex check, wildcard rejection, DNS sanity check on startup
- **Subdomain normalisation** — lowercase, strip `*.`, FQDN regex validation, dedup
- **Wildcard DNS detection** — random label probe; wildcard IPs filtered from live results
- **HTTP response classification** — grouped by 200/301/403/401; title-based dedup
- **JS secret detection with context** — beautify-lite preprocessing, context window, skip placeholders
- **Parameter vulnerability classification** — SSRF / redirect / IDOR / LFI per URL
- **Retry with exponential backoff** — crt.sh, gau, waybackurls retried on failure
- **Parallel JS downloads** — 20 concurrent workers via xargs

### Architecture upgrades
- **SQLite asset graph** — every subdomain, port, service, JS finding, and parameter stored and queryable
- **Cross-module correlation** — links subdomain → port → HTTP service → JS endpoint → parameter
- **Prioritised scoring** — every finding scored 1–10; top findings surfaced automatically
- **Markdown report** — auto-generated with summary, top attack surfaces, SSRF/redirect lists
- **Resume capability** — `--resume` skips already-completed modules
- **Full run log** — everything tee'd to `recon.log`

## Output Structure

```
output/
└── example.com_20260611_143022/
    ├── recon.log
    ├── recon.db                    ← SQLite asset graph
    ├── .state                      ← completed modules (resume)
    ├── subdomains/
    │   ├── all_subs.txt            ← normalised + validated
    │   ├── live_subs.txt           ← wildcard-filtered
    │   └── host_ip_pairs.txt
    ├── http/
    │   ├── httpx_raw.jsonl
    │   ├── live_urls.txt
    │   ├── status_200.txt
    │   ├── status_401_403.txt
    │   └── interesting.txt
    ├── ports/
    │   ├── open_ports.txt
    │   └── high_interest.txt       ← score ≥8
    ├── js/
    │   ├── endpoints.txt
    │   └── potential_secrets.txt   ← kind + value + context
    ├── params/
    │   ├── ssrf_params.txt
    │   ├── redirect_params.txt
    │   ├── idor_params.txt
    │   └── lfi_params.txt
    ├── dorks/
    │   ├── dorks.txt
    │   └── github_dorks.txt
    ├── cloud/
    │   └── open_buckets.txt
    ├── screenshots/
    └── report/
        ├── report.md               ← prioritised markdown report
        └── asset_graph.json        ← full correlation graph
```

## Querying the Asset Graph

```bash
# Top findings by score
sqlite3 output/example.com_*/recon.db \
  "SELECT score, category, title, detail FROM findings ORDER BY score DESC LIMIT 20"

# SSRF parameter candidates
sqlite3 output/example.com_*/recon.db \
  "SELECT url FROM parameters WHERE kind='ssrf'"

# Hosts with Grafana service AND port 3000 open
sqlite3 output/example.com_*/recon.db \
  "SELECT DISTINCT o.host FROM open_ports o
   JOIN http_services h ON h.subdomain=o.host
   WHERE o.port=3000 AND h.tech LIKE '%Grafana%'"
```

## Scoring Reference

| Finding | Score |
|---------|-------|
| Open S3 bucket | 10 |
| Docker daemon (:2375) | 10 |
| Redis (:6379) | 10 |
| Kubernetes kubelet (:10250) | 10 |
| SSRF parameter | 9 |
| Elasticsearch (:9200) | 9 |
| MongoDB (:27017) | 9 |
| Open redirect parameter | 8 |
| LFI parameter | 8 |
| JS secret found | 8 |
| Admin panel | 7 |
| IDOR parameter | 7 |

## Configuration

```bash
# config.env
TELEGRAM_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"
HTTPX_THREADS=50
NAABU_THREADS=100
```

## Legal

Only test targets you have explicit written permission to test. Stay in scope. Report responsibly.
