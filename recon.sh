#!/usr/bin/env bash
# ============================================================
#  tanyaa.sh — Web Recon Pipeline v3.0
#  Usage: ./tanyaa.sh <domain> [--full | --module <name> | --resume]
# ============================================================

# ── Error model: strict but intentional ─────────────────────
# set -e is NOT used globally. Each external tool call is
# explicitly checked. This avoids the || true anti-pattern
# while keeping shell safety (nounset + pipefail stay on).
set -uo pipefail

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Paths ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_BASE="$SCRIPT_DIR/output"
CONFIG_FILE="$SCRIPT_DIR/config.env"
DB_FILE=""          # set per-run
OUT_DIR=""          # set per-run
DOMAIN=""           # set by validate_target
STATE_FILE=""       # set per-run (resume support)

# ── Config defaults ──────────────────────────────────────────
TELEGRAM_TOKEN=""
TELEGRAM_CHAT_ID=""
GITHUB_TOKEN=""
HTTPX_THREADS=50
NAABU_THREADS=100

[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

# ── Scoring weights ──────────────────────────────────────────
declare -A SCORE_WEIGHTS=(
  [open_redirect_param]=9
  [ssrf_param]=9
  [js_secret]=8
  [admin_panel]=7
  [graphql]=7
  [swagger]=6
  [port_redis]=10
  [port_elastic]=9
  [port_mongo]=9
  [port_docker]=10
  [port_jenkins]=8
  [status_200_login]=8
  [status_403]=3
  [open_bucket]=10
)

# ── Logging ──────────────────────────────────────────────────
LOG_FILE=""

_log() { echo -e "$*" | tee -a "${LOG_FILE:-/dev/null}"; }

banner() {
cat << 'EOF'
  ████████╗ █████╗ ███╗   ██╗██╗   ██╗ █████╗  █████╗
     ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗
     ██║   ███████║██╔██╗ ██║ ╚████╔╝ ███████║███████║   _._     _,-'""`-._
     ██║   ██╔══██║██║╚██╗██║  ╚██╔╝  ██╔══██║██╔══██║  (,-.`._,'(       |\`-/|
     ██║   ██║  ██║██║ ╚████║   ██║   ██║  ██║██║  ██║      `-.-' \ )-`( , o o)
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝            `-    \`_`"'-   
         Web Recon Pipeline v3.0
EOF
}

info()    { _log "${CYAN}[*]${RESET} $*"; }
ok()      { _log "${GREEN}[+]${RESET} $*"; }
warn()    { _log "${YELLOW}[!]${RESET} $*"; }
err()     { _log "${RED}[✗]${RESET} $*"; }
section() { _log "\n${BOLD}${YELLOW}━━━ $* ━━━${RESET}"; }
die()     { err "$*"; exit 1; }
scored()  { _log "${MAGENTA}[★]${RESET} $*"; }

# ── Tool helpers ─────────────────────────────────────────────
has()    { command -v "$1" &>/dev/null; }
need()   { has "$1" || die "'$1' not found — run ./install.sh"; }
count()  { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo "0"; }

# Run tool, log result, never abort pipeline on failure
run_tool() {
  local label="$1"; shift
  if "$@" 2>>"${LOG_FILE:-/dev/null}"; then
    return 0
  else
    warn "$label exited non-zero (check $LOG_FILE)"
    return 1
  fi
}

# Retry wrapper: retry N times with backoff
retry() {
  local attempts="${1}"; shift
  local delay=2
  local n=0
  until "$@" 2>>"${LOG_FILE:-/dev/null}"; do
    n=$(( n + 1 ))
    [ "$n" -ge "$attempts" ] && { warn "Failed after $attempts attempts: $*"; return 1; }
    warn "Attempt $n failed, retrying in ${delay}s…"
    sleep "$delay"
    delay=$(( delay * 2 ))
  done
}

# ── Telegram notify ──────────────────────────────────────────
notify() {
  local msg="$1"
  [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]] && return 0
  curl -s --max-time 10 -X POST \
    "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" \
    -d "text=${msg}" \
    -d "parse_mode=Markdown" > /dev/null 2>&1 || warn "Telegram notify failed"
}

# ── SQLite asset graph ────────────────────────────────────────
db_init() {
  python3 - "$DB_FILE" "$DOMAIN" "$TIMESTAMP" << 'PYEOF'
import sys, sqlite3
db_path, domain, ts = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect(db_path)
db.executescript("""
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- One row per ./recon.sh invocation; enables dedup across --resume runs
CREATE TABLE IF NOT EXISTS runs (
    id      INTEGER PRIMARY KEY,
    domain  TEXT NOT NULL,
    ts      TEXT NOT NULL,
    created TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subdomains (
    id       INTEGER PRIMARY KEY,
    run_id   INTEGER NOT NULL REFERENCES runs(id),
    host     TEXT NOT NULL,
    ip       TEXT,
    cname    TEXT,
    source   TEXT,           -- 'subfinder' | 'amass' | 'crtsh' | 'enum'
    wildcard INTEGER DEFAULT 0,
    created  TEXT DEFAULT (datetime('now')),
    UNIQUE(run_id, host)
);

CREATE TABLE IF NOT EXISTS http_services (
    id          INTEGER PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES runs(id),
    subdomain   TEXT NOT NULL,
    url         TEXT NOT NULL,
    status      INTEGER,
    title       TEXT,
    tech        TEXT,
    content_len INTEGER,
    redirects   TEXT,
    created     TEXT DEFAULT (datetime('now')),
    UNIQUE(run_id, url)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id      INTEGER PRIMARY KEY,
    run_id  INTEGER NOT NULL REFERENCES runs(id),
    host    TEXT NOT NULL,
    port    INTEGER NOT NULL,
    service TEXT,
    score   INTEGER DEFAULT 0,
    UNIQUE(run_id, host, port)
);

CREATE TABLE IF NOT EXISTS js_findings (
    id      INTEGER PRIMARY KEY,
    run_id  INTEGER NOT NULL REFERENCES runs(id),
    url     TEXT NOT NULL,
    kind    TEXT NOT NULL,   -- 'endpoint' | 'secret'
    value   TEXT NOT NULL,
    context TEXT,
    score   INTEGER DEFAULT 0,
    UNIQUE(run_id, kind, value)
);

CREATE TABLE IF NOT EXISTS parameters (
    id      INTEGER PRIMARY KEY,
    run_id  INTEGER NOT NULL REFERENCES runs(id),
    url     TEXT NOT NULL,
    host    TEXT,            -- parsed hostname for cross-module joins
    params  TEXT,
    kind    TEXT,            -- 'ssrf' | 'redirect' | 'idor' | 'lfi' | 'generic'
    score   INTEGER DEFAULT 0,
    UNIQUE(run_id, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY,
    run_id   INTEGER NOT NULL REFERENCES runs(id),
    source   TEXT,           -- module that emitted this: 'http' | 'port' | 'js' | 'param' | 'cloud'
    category TEXT NOT NULL,
    title    TEXT NOT NULL,
    detail   TEXT,
    score    INTEGER DEFAULT 0,
    created  TEXT DEFAULT (datetime('now')),
    UNIQUE(run_id, category, title, detail)
);

-- Indexes that matter for correlation queries
CREATE INDEX IF NOT EXISTS idx_sub_host   ON subdomains(host);
CREATE INDEX IF NOT EXISTS idx_http_sub   ON http_services(subdomain);
CREATE INDEX IF NOT EXISTS idx_port_host  ON open_ports(host);
CREATE INDEX IF NOT EXISTS idx_param_host ON parameters(host);
CREATE INDEX IF NOT EXISTS idx_find_score ON findings(score DESC);
""")

# Upsert the run record and store its id in a meta table
db.execute("INSERT OR IGNORE INTO runs (domain, ts) VALUES (?, ?)", (domain, ts))
db.commit()
run_id = db.execute("SELECT id FROM runs WHERE domain=? AND ts=?", (domain, ts)).fetchone()[0]

# Store run_id in a tiny meta table so shell wrappers can read it
db.execute("CREATE TABLE IF NOT EXISTS _meta (key TEXT PRIMARY KEY, value TEXT)")
db.execute("INSERT OR REPLACE INTO _meta VALUES ('run_id', ?)", (str(run_id),))
db.commit()
db.close()
print(f"DB initialised (run_id={run_id})")
PYEOF
}

# Helper: read current run_id from DB
get_run_id() {
  python3 -c "
import sqlite3, sys
db = sqlite3.connect('$DB_FILE')
row = db.execute(\"SELECT value FROM _meta WHERE key='run_id'\").fetchone()
print(row[0] if row else '1')
db.close()
"
}

db_query() {
  local sql="$1"
  python3 - "$DB_FILE" << PYEOF
import sqlite3
db = sqlite3.connect("$DB_FILE")
rows = db.execute("""$sql""").fetchall()
for r in rows:
    print("\t".join(str(c) for c in r))
db.close()
PYEOF
}

# Insert finding with score (run_id-aware, deduped per run)
db_finding() {
  local source="$1" category="$2" title="$3" detail="$4" score="$5"
  python3 - "$DB_FILE" "$source" "$category" "$title" "$detail" "$score" << 'PYEOF'
import sys, sqlite3
db_path, source, category, title, detail, score = sys.argv[1:7]
db = sqlite3.connect(db_path)
run_id = db.execute("SELECT value FROM _meta WHERE key='run_id'").fetchone()[0]
rid = db.execute("SELECT value FROM _meta WHERE key='run_id'").fetchone()[0]
db.execute(
    "INSERT OR IGNORE INTO findings (run_id,source,category,title,detail,score) VALUES (?,?,?,?,?,?)",
    (int(rid), source, category, title, detail, int(score))
)
db.commit()
db.close()
PYEOF
}

# ── Resume state ──────────────────────────────────────────────
state_mark_done() { echo "$1" >> "$STATE_FILE"; }
state_is_done()   { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }

# ── Input validation ─────────────────────────────────────────
validate_target() {
  local raw="$1"
  # Strip scheme and path
  raw="${raw#http://}"; raw="${raw#https://}"; raw="${raw%%/*}"
  raw="${raw,,}"  # lowercase

  # Basic FQDN regex
  if ! echo "$raw" | grep -qE '^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'; then
    die "Invalid domain: '$raw'. Provide a valid FQDN (e.g. example.com)"
  fi

  # Check for wildcard
  if echo "$raw" | grep -q '^\*'; then
    die "Wildcard domains not supported as input. Provide the root domain."
  fi

  # DNS sanity — does the domain even resolve?
  info "Validating domain resolves…"
  if ! host "$raw" >/dev/null 2>&1 && ! nslookup "$raw" >/dev/null 2>&1; then
    warn "Domain '$raw' did not resolve. Continuing anyway (may be correct for some targets)."
  else
    ok "Domain resolves: $raw"
  fi

  DOMAIN="$raw"
}

# ── Subdomain normalisation ───────────────────────────────────
normalise_subs() {
  local infile="$1" outfile="$2"
  python3 - "$infile" "$outfile" "$DOMAIN" << 'PYEOF'
import sys, re

infile, outfile, apex = sys.argv[1], sys.argv[2], sys.argv[3]
fqdn_re = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')
seen = set()

try:
    lines = open(infile).read().splitlines()
except FileNotFoundError:
    open(outfile, 'w').close()
    sys.exit(0)

with open(outfile, 'w') as out:
    for line in lines:
        # Strip leading *. or .
        sub = line.strip().lower().lstrip('*.').strip('.')
        if not sub:
            continue
        # Must end with the apex domain
        if not (sub == apex or sub.endswith('.' + apex)):
            continue
        # Must match FQDN regex
        if not fqdn_re.match(sub):
            continue
        if sub not in seen:
            seen.add(sub)
            out.write(sub + '\n')

print(f"Normalised: {len(seen)} valid subdomains")
PYEOF
}

# ── Wildcard DNS detection ────────────────────────────────────
detect_wildcard() {
  local domain="$1"
  # Generate random label unlikely to exist
  local rand
  rand="recon-wc-$(head /dev/urandom | tr -dc a-z0-9 | head -c 12).${domain}"
  if host "$rand" >/dev/null 2>&1; then
    warn "⚠  Wildcard DNS detected on $domain — results will be filtered"
    WILDCARD_IP=$(host "$rand" 2>/dev/null | grep "has address" | awk '{print $NF}' | head -1)
    warn "   Wildcard resolves to: ${WILDCARD_IP:-unknown}"
    # Persist for HTTP layer filter (Fix 3)
    echo "${WILDCARD_IP:-}" > "$OUT_DIR/subdomains/.wildcard_ip"
    echo "${WILDCARD_IP:-}"
    return 0
  fi
  echo ""
  return 0
}

# ── MODULE 1: Subdomain Enumeration ──────────────────────────
run_subdomains() {
  state_is_done "subdomains" && { info "Subdomains: already done (resume)"; return 0; }
  section "SUBDOMAIN ENUMERATION"
  local dir="$OUT_DIR/subdomains"
  mkdir -p "$dir"

  # Wildcard detection first
  info "Checking for wildcard DNS…"
  local wc_ip
  wc_ip=$(detect_wildcard "$DOMAIN")

  # ── Passive sources ──
  if has subfinder; then
    info "subfinder…"
    run_tool "subfinder" subfinder -d "$DOMAIN" -all -recursive -silent \
      -o "$dir/raw_subfinder.txt" || true
  fi

  if has amass; then
    info "amass (passive, 90s timeout)…"
    run_tool "amass" timeout 90 amass enum -passive -d "$DOMAIN" \
      -o "$dir/raw_amass.txt" || true
  fi

  info "crt.sh (with retry)…"
  retry 3 bash -c \
    "curl -sf --max-time 30 'https://crt.sh/?q=%.${DOMAIN}&output=json' \
     | python3 -c \"import sys,json; [print(e.get('name_value','')) for e in json.load(sys.stdin)]\" \
     > '$dir/raw_crtsh.txt'"  || warn "crt.sh failed after retries"

  # ── Merge raw outputs ──
  cat "$dir"/raw_*.txt 2>/dev/null > "$dir/raw_merged.txt" || true

  # ── Normalise ──
  normalise_subs "$dir/raw_merged.txt" "$dir/all_subs.txt"
  local total
  total=$(count "$dir/all_subs.txt")
  ok "Unique valid subdomains before resolution: $total"

  # ── DNS resolution ──
  if has dnsx; then
    info "Resolving with dnsx…"
    run_tool "dnsx" dnsx -silent -resp -l "$dir/all_subs.txt" \
      -o "$dir/resolved.txt" || true

    # Extract host and IP pairs
    awk '{print $1, $2}' "$dir/resolved.txt" 2>/dev/null | tr -d '[]' > "$dir/host_ip_pairs.txt" || true
    awk '{print $1}' "$dir/host_ip_pairs.txt" | sort -u > "$dir/live_subs.txt"
  else
    warn "dnsx not found — copying all subs as live (unresolved)"
    cp "$dir/all_subs.txt" "$dir/live_subs.txt"
    touch "$dir/host_ip_pairs.txt"
  fi

  # ── Wildcard filtering ──
  if [[ -n "$wc_ip" && -f "$dir/host_ip_pairs.txt" ]]; then
    info "Filtering wildcard IPs ($wc_ip)…"
    local before after
    before=$(count "$dir/live_subs.txt")
    grep -v "$wc_ip" "$dir/host_ip_pairs.txt" | awk '{print $1}' \
      | sort -u > "$dir/live_subs_filtered.txt" 2>/dev/null || true
    mv "$dir/live_subs_filtered.txt" "$dir/live_subs.txt"
    after=$(count "$dir/live_subs.txt")
    warn "Wildcard filter: $before → $after (removed $(( before - after )) false positives)"
  fi

  # ── Persist to DB ──
  python3 - "$DB_FILE" "$dir/host_ip_pairs.txt" "$DOMAIN" << 'PYEOF'
import sys, sqlite3
db_path, pairs_file, apex = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect(db_path)
run_id = db.execute("SELECT value FROM _meta WHERE key='run_id'").fetchone()[0]
try:
    lines = open(pairs_file).read().splitlines()
except FileNotFoundError:
    sys.exit(0)
for line in lines:
    parts = line.split()
    host = parts[0] if parts else ''
    ip   = parts[1] if len(parts) > 1 else None
    if host:
        db.execute(
            "INSERT OR IGNORE INTO subdomains (run_id, host, ip, source) VALUES (?,?,?,?)",
            (int(run_id), host, ip, 'enum')
        )
db.commit()
db.close()
PYEOF

  local live
  live=$(count "$dir/live_subs.txt")
  ok "Live subdomains: $live"
  notify "📡 Subdomains: $total found, $live live — $DOMAIN"
  state_mark_done "subdomains"
}

# ── MODULE 2: HTTP Probing ────────────────────────────────────
run_http_probe() {
  state_is_done "http" && { info "HTTP: already done (resume)"; return 0; }
  section "HTTP PROBING"
  local dir="$OUT_DIR/http"
  local subs="$OUT_DIR/subdomains/live_subs.txt"
  mkdir -p "$dir"

  [ -f "$subs" ] || { warn "No live subs — run subdomains first"; return 0; }
  need httpx

  # Fix 3: re-apply wildcard IP filter at HTTP layer in case subdomains module was skipped/resumed
  # Read wildcard IP from the subdomains wildcard detection artefact if present
  local wc_ip_file="$OUT_DIR/subdomains/.wildcard_ip"
  if [[ -f "$wc_ip_file" ]]; then
    local wc_ip
    wc_ip=$(cat "$wc_ip_file")
    if [[ -n "$wc_ip" ]]; then
      info "Re-applying wildcard filter (${wc_ip}) before HTTP probing…"
      local subs_clean="$dir/live_subs_wc_filtered.txt"
      # Filter by re-resolving isn't free, so we filter the input list against the known wildcard IP
      # using the host_ip_pairs file produced by dnsx
      local pairs="$OUT_DIR/subdomains/host_ip_pairs.txt"
      if [[ -f "$pairs" ]]; then
        grep -v "$wc_ip" "$pairs" | awk '{print $1}' | sort -u > "$subs_clean" || true
        subs="$subs_clean"
        ok "Wildcard-clean input: $(wc -l < "$subs_clean") hosts"
      fi
    fi
  fi

  info "Probing with httpx (threads: $HTTPX_THREADS)…"
  # Fix 6: retry httpx up to 2 times on transient failure
  retry 2 httpx \
    -l "$subs" \
    -title -tech-detect -status-code -content-length \
    -follow-redirects -location \
    -threads "$HTTPX_THREADS" \
    -silent \
    -json \
    -o "$dir/httpx_raw.jsonl" || warn "httpx failed after retries — partial results may be available"

  # Parse JSONL → text summary + classified lists
  python3 - "$dir/httpx_raw.jsonl" "$dir" "$DB_FILE" << 'PYEOF'
import sys, json, sqlite3, os

raw_file, out_dir, db_path = sys.argv[1], sys.argv[2], sys.argv[3]

os.makedirs(out_dir, exist_ok=True)
db = sqlite3.connect(db_path)
run_id = db.execute("SELECT value FROM _meta WHERE key='run_id'").fetchone()[0]

buckets   = {200: [], 301: [], 302: [], 403: [], 401: [], 500: [], 'other': []}
tech_map  = {}
titles    = set()

HIGH_VALUE = {'jenkins','grafana','kibana','elasticsearch','phpmyadmin',
              'admin','dashboard','swagger','graphql','rabbitmq','consul',
              'prometheus','airflow','jupyter','panel','portainer'}

try:
    lines = open(raw_file).read().splitlines()
except FileNotFoundError:
    print("No httpx output"); sys.exit(0)

interesting = []

for line in lines:
    if not line.strip():
        continue
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue

    url    = r.get('url', '')
    status = r.get('status-code', 0)
    title  = r.get('title', '')
    tech   = ','.join(r.get('tech', []) or [])
    clen   = r.get('content-length', 0)
    loc    = r.get('location', '')
    host   = r.get('input', url)

    # Dedupe by title (response similarity proxy)
    if title and title in titles:
        continue
    titles.add(title)

    # Bucket by status
    key = status if status in buckets else 'other'
    buckets[key].append(url)

    # DB insert
    db.execute(
        "INSERT OR IGNORE INTO http_services "
        "(run_id, subdomain, url, status, title, tech, content_len, redirects) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (int(run_id), host, url, status, title, tech, clen, loc)
    )

    # Flag interesting tech / title
    combined = (title + ' ' + tech).lower()
    for kw in HIGH_VALUE:
        if kw in combined:
            interesting.append((url, status, title, tech))
            score = 7
            db.execute(
                "INSERT OR IGNORE INTO findings (run_id,source,category,title,detail,score) VALUES (?,?,?,?,?,?)",
                (int(run_id), 'http', 'http', f"Interesting service: {kw}", url, score)
            )
            break

db.commit()
db.close()

# Write classified files
all_urls = []
with open(f'{out_dir}/status_200.txt', 'w') as f:
    for u in buckets[200]: f.write(u+'\n')
with open(f'{out_dir}/status_401_403.txt', 'w') as f:
    for u in buckets[401]+buckets[403]: f.write(u+'\n')
with open(f'{out_dir}/status_redirect.txt', 'w') as f:
    for u in buckets[301]+buckets[302]: f.write(u+'\n')

all_urls = buckets[200]+buckets[301]+buckets[302]+buckets[403]+buckets[401]+buckets[500]+buckets['other']
with open(f'{out_dir}/live_urls.txt', 'w') as f:
    for u in sorted(set(all_urls)): f.write(u+'\n')

with open(f'{out_dir}/interesting.txt', 'w') as f:
    for url, status, title, tech in interesting:
        f.write(f"{status}\t{url}\t{title}\t{tech}\n")

print(f"200:{len(buckets[200])}  403/401:{len(buckets[401])+len(buckets[403])}  "
      f"redirects:{len(buckets[301])+len(buckets[302])}  interesting:{len(interesting)}")
PYEOF

  ok "HTTP complete — $(count "$dir/live_urls.txt") live URLs"
  [ "$(count "$dir/interesting.txt")" -gt 0 ] && \
    warn "$(count "$dir/interesting.txt") high-value services (see http/interesting.txt)"

  notify "🌐 HTTP: $(count "$dir/live_urls.txt") services — $DOMAIN"
  state_mark_done "http"
}

# ── MODULE 3: Port Scanning ───────────────────────────────────
run_ports() {
  state_is_done "ports" && { info "Ports: already done (resume)"; return 0; }
  section "PORT SCANNING"
  local dir="$OUT_DIR/ports"
  local subs="$OUT_DIR/subdomains/live_subs.txt"
  mkdir -p "$dir"

  [ -f "$subs" ] || { warn "No live subs — run subdomains first"; return 0; }

  # Base ports + expand based on tech fingerprinting hints
  local BASE_PORTS="21,22,23,25,80,443,2375,2376,3000,3306,4848,5000,5432,5900,6379,7001,8080,8443,8888,9000,9090,9200,9300,10250,27017,28017"

  if has naabu; then
    info "naabu port scan…"
    # Fix 6: retry naabu up to 2 times on transient failure
    retry 2 naabu \
      -l "$subs" \
      -p "$BASE_PORTS" \
      -rate 1000 \
      -silent \
      -json \
      -o "$dir/naabu_raw.jsonl" || warn "naabu failed after retries — partial results may be available"

    # Parse + score
    python3 - "$dir/naabu_raw.jsonl" "$dir" "$DB_FILE" << 'PYEOF'
import sys, json, sqlite3

raw, out_dir, db_path = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect(db_path)
run_id = db.execute("SELECT value FROM _meta WHERE key='run_id'").fetchone()[0]

# Fix 5: context-aware scoring — private IPs get -2 (still dangerous but not public-critical)
import ipaddress as _ipmod

HIGH_INTEREST = {
    2375:  ('Docker daemon EXPOSED',        10),
    10250: ('Kubernetes kubelet',           10),
    6379:  ('Redis (no auth?)',             10),
    2376:  ('Docker TLS daemon',             8),
    9200:  ('Elasticsearch',                 9),
    9300:  ('Elasticsearch transport',       8),
    27017: ('MongoDB (no auth?)',            9),
    28017: ('MongoDB HTTP interface',        9),
    4848:  ('GlassFish admin',               8),
    5900:  ('VNC',                           8),
    7001:  ('WebLogic',                      8),
    3000:  ('Dev server / Grafana',          7),
    8888:  ('Jupyter / unauth web UI',       7),
    9090:  ('Prometheus / Cockpit',          7),
    4444:  ('Metasploit / reverse shell?',   9),
}

def _is_private(host):
    """Return True if host resolves to an RFC-1918/loopback address."""
    try:
        addr = _ipmod.ip_address(host)
        return addr.is_private or addr.is_loopback
    except ValueError:
        pass
    import socket
    try:
        ip = socket.gethostbyname(host)
        addr = _ipmod.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except Exception:
        return False

try:
    lines = open(raw).read().splitlines()
except FileNotFoundError:
    print("No naabu output"); sys.exit(0)

hi_findings = []
all_ports   = []

for line in lines:
    if not line.strip():
        continue
    try:
        r = json.loads(line)
    except Exception:
        continue
    host = r.get('host', '') or r.get('ip', '')
    port = int(r.get('port', 0))
    if not host or not port:
        continue
    all_ports.append(f"{host}:{port}")
    desc, base_score = HIGH_INTEREST.get(port, ('', 0))

    # Context adjustment: private IPs are lower risk than public exposure
    if base_score > 0 and _is_private(host):
        adj_score = max(base_score - 2, 1)
        desc = desc + ' [private IP]' 
    else:
        adj_score = base_score

    db.execute(
        "INSERT OR IGNORE INTO open_ports (run_id,host,port,service,score) VALUES (?,?,?,?,?)",
        (int(run_id), host, port, desc, adj_score)
    )
    if adj_score >= 8:
        hi_findings.append((host, port, desc, adj_score))
        db.execute(
            "INSERT OR IGNORE INTO findings (run_id,source,category,title,detail,score) VALUES (?,?,?,?,?,?)",
            (int(run_id), 'port', 'port', f"High-risk port {port}: {desc}", f"{host}:{port}", adj_score)
        )

db.commit()
db.close()

with open(f'{out_dir}/open_ports.txt', 'w') as f:
    f.write('\n'.join(all_ports) + '\n')

with open(f'{out_dir}/high_interest.txt', 'w') as f:
    for h,p,d,s in hi_findings:
        f.write(f"[score={s}] {h}:{p}  {d}\n")

print(f"Open ports: {len(all_ports)} | High-interest: {len(hi_findings)}")
PYEOF

  else
    warn "naabu not found — basic nc fallback (slow)"
    while IFS= read -r host; do
      for port in 80 443 8080 8443 3000 6379 9200 27017 2375 10250; do
        if nc -z -w 2 "$host" "$port" 2>/dev/null; then
          echo "${host}:${port}" >> "$dir/open_ports.txt"
        fi
      done
    done < "$subs"
    ok "Open ports: $(count "$dir/open_ports.txt")"
  fi

  [ "$(count "$dir/high_interest.txt")" -gt 0 ] && \
    warn "High-risk ports detected — see ports/high_interest.txt"

  notify "🔍 Ports: $(count "$dir/open_ports.txt") open — $DOMAIN"
  state_mark_done "ports"
}

# ── MODULE 4: JS Mining ───────────────────────────────────────
run_js() {
  state_is_done "js" && { info "JS: already done (resume)"; return 0; }
  section "JAVASCRIPT MINING"
  local dir="$OUT_DIR/js"
  mkdir -p "$dir/files"

  # Collect JS URLs
  touch "$dir/js_urls_raw.txt"

  if has gau; then
    info "gau…"
    retry 2 bash -c \
      "gau '$DOMAIN' --threads 5 --blacklist png,jpg,gif,svg,css,woff,ttf,ico,mp4 \
       >> '$dir/js_urls_raw.txt'" || warn "gau failed"
  fi

  if has katana; then
    info "katana crawl…"
    run_tool "katana" katana \
      -u "https://$DOMAIN" -jc -d 3 -silent \
      -o "$dir/katana_out.txt" || true
    cat "$dir/katana_out.txt" >> "$dir/js_urls_raw.txt" 2>/dev/null || true
  fi

  # Filter + dedup JS URLs
  grep -iE '\.js(\?.*)?$' "$dir/js_urls_raw.txt" | sort -u > "$dir/js_urls.txt" || true

  local js_count
  js_count=$(count "$dir/js_urls.txt")

  if [[ "$js_count" -eq 0 ]]; then
    warn "No JS URLs collected — skipping JS mining"
    state_mark_done "js"
    return 0
  fi

  info "Downloading $js_count JS files (parallel, 20 workers)…"
  # Parallel download with xargs
  cat "$dir/js_urls.txt" | xargs -P 20 -I{} bash -c '
    fn=$(echo "{}" | md5sum | cut -d" " -f1)
    out="'"$dir/files"'/${fn}.js"
    [ -f "$out" ] && exit 0   # cache hit
    curl -sk --max-time 15 "{}" -o "$out" 2>/dev/null || true
  '

  info "Extracting endpoints and secrets from JS…"
  python3 - "$dir/files" "$dir" "$DB_FILE" "$DOMAIN" << 'PYEOF'
import os, re, sys, sqlite3, base64, json

files_dir, out_dir, db_path, domain = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
db = sqlite3.connect(db_path)
run_id = db.execute("SELECT value FROM _meta WHERE key='run_id'").fetchone()[0]

SECRET_PATTERNS = [
    (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{20,})', 'AWS Key'),
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']', 'API Key'),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']', 'Secret Key'),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', 'Password'),
    (r'(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["\']([A-Za-z0-9\-_.]{20,})["\']', 'Token'),
    (r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+', 'JWT'),
    (r'(?i)mongodb(\+srv)?://[^\s"\']+', 'MongoDB URI'),
    (r'(?i)postgres://[^\s"\']+', 'Postgres URI'),
    (r'(?i)redis://[^\s"\']+', 'Redis URI'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
]

ENDPOINT_PATTERNS = [
    r'["\'`](/api/[^\s"\'`]+)',
    r'["\'`](/v\d+/[^\s"\'`]+)',
    r'["\'`](https?://[^\s"\'`]{10,})',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'url\s*[=:]\s*["\']([^"\']{5,})["\']',
]

endpoints = set()
secrets   = []

for fname in os.listdir(files_dir):
    if not fname.endswith('.js'):
        continue
    fpath = os.path.join(files_dir, fname)
    try:
        content = open(fpath, 'r', errors='ignore').read()
    except:
        continue

    # Skip likely non-JS (binary/empty)
    if len(content) < 50:
        continue

    # Beautify minimal: replace ; and { with newlines for better regex hits
    content_clean = re.sub(r'[;{}]', '\n', content)

    # Endpoints
    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, content_clean):
            ep = m.group(1).strip()
            if len(ep) > 3 and not ep.startswith('//'):
                endpoints.add(ep)

    # Secrets
    for pat, kind in SECRET_PATTERNS:
        for m in re.finditer(pat, content_clean):
            val = m.group(0)
            # Skip obvious placeholder values
            if re.search(r'(example|placeholder|xxxx|your[_-]?key|insert)', val, re.I):
                continue
            context = content_clean[max(0,m.start()-40):m.end()+40].replace('\n',' ')
            secrets.append((kind, val, context))
            db.execute(
                "INSERT OR IGNORE INTO js_findings (run_id,url,kind,value,context,score) VALUES (?,?,?,?,?,?)",
                (int(run_id), fname, 'secret', f"{kind}: {val[:80]}", context[:200], 8)
            )
            db.execute(
                "INSERT OR IGNORE INTO findings (run_id,source,category,title,detail,score) VALUES (?,?,?,?,?,?)",
                (int(run_id), 'js', 'js', f"Potential {kind} in JS", val[:120], 8)
            )

# Normalise + filter endpoints (Fix 4: origin filter + API grouping)
from urllib.parse import urlparse as _urlparse, urlencode, parse_qsl

JUNK_EXTENSIONS = re.compile(r'\.(png|jpg|gif|svg|ico|woff|ttf|css|mp4|pdf)$', re.I)
JUNK_PREFIXES   = re.compile(r'^(//|data:|javascript:|mailto:)', re.I)

norm_eps   = set()  # all cleaned
api_groups = {}     # /api/v1/... → set of full paths

for ep in endpoints:
    ep = ep.rstrip('/')
    if not ep or len(ep) < 4:
        continue
    if JUNK_EXTENSIONS.search(ep.split('?')[0]):
        continue
    if JUNK_PREFIXES.match(ep):
        continue

    # For absolute URLs: only keep same-apex-domain endpoints
    if ep.startswith('http'):
        try:
            parsed = _urlparse(ep)
            host = parsed.hostname or ''
            # Keep if it ends with apex domain
            if not (host == domain or host.endswith('.' + domain)):
                continue
            # Normalise: strip default ports, sort query params
            path = parsed.path.rstrip('/')
            qs   = urlencode(sorted(parse_qsl(parsed.query)))
            ep   = f"{parsed.scheme}://{host}{path}" + (f"?{qs}" if qs else '')
        except Exception:
            continue
    else:
        # Relative path: normalise query
        if '?' in ep:
            path, qs_raw = ep.split('?', 1)
            qs = urlencode(sorted(parse_qsl(qs_raw)))
            ep = path + (f"?{qs}" if qs else '')

    if ep in norm_eps:
        continue
    norm_eps.add(ep)

    # API grouping: cluster by /api/vN/ or /api/ prefix
    path_only = ep.split('?')[0]
    api_m = re.match(r'(/(?:api|graphql|rest|v\d+)/[^/]+)', path_only)
    if api_m:
        group = api_m.group(1)
        api_groups.setdefault(group, set()).add(ep)

    db.execute(
        "INSERT OR IGNORE INTO js_findings (run_id,url,kind,value,score) VALUES (?,?,?,?,?)",
        (int(run_id), 'extracted', 'endpoint', ep, 3)
    )

db.commit()
db.close()

with open(f'{out_dir}/endpoints.txt', 'w') as f:
    f.write('\n'.join(sorted(norm_eps)) + '\n')

# Write API group summary
with open(f'{out_dir}/api_groups.txt', 'w') as f:
    for grp, eps in sorted(api_groups.items(), key=lambda x: -len(x[1])):
        f.write(f"[{len(eps)}] {grp}\n")
        for e in sorted(eps)[:5]:
            f.write(f"    {e}\n")

with open(f'{out_dir}/potential_secrets.txt', 'w') as f:
    for kind, val, ctx in secrets:
        f.write(f"[{kind}] {val[:120]}\n  ctx: {ctx[:100]}\n\n")

print(f"Endpoints: {len(norm_eps)}  API groups: {len(api_groups)}  Potential secrets: {len(secrets)}")
PYEOF

  local eps secs
  eps=$(count "$dir/endpoints.txt")
  secs=$(python3 -c "
import re
try:
    c = len([l for l in open('$dir/potential_secrets.txt') if l.startswith('[')])
    print(c)
except: print(0)
")
  ok "JS: $js_count files | $eps endpoints | $secs potential secrets"
  notify "📄 JS: $secs secrets, $eps endpoints — $DOMAIN"
  state_mark_done "js"
}

# ── MODULE 5: Parameter Discovery ────────────────────────────
run_params() {
  state_is_done "params" && { info "Params: already done (resume)"; return 0; }
  section "PARAMETER DISCOVERY"
  local dir="$OUT_DIR/params"
  mkdir -p "$dir"

  touch "$dir/all_urls_raw.txt"

  if has gau; then
    info "gau historical URLs…"
    retry 2 bash -c \
      "gau '$DOMAIN' --threads 5 \
       --blacklist png,jpg,gif,svg,css,woff,ttf,ico,mp4,mp3,zip \
       >> '$dir/all_urls_raw.txt'" || warn "gau failed"
  fi

  if has waybackurls; then
    info "waybackurls…"
    retry 2 bash -c \
      "waybackurls '$DOMAIN' >> '$dir/all_urls_raw.txt'" || warn "waybackurls failed"
  fi

  if [[ "$(count "$dir/all_urls_raw.txt")" -eq 0 ]]; then
    warn "No URL archive tools available (gau/waybackurls)"; state_mark_done "params"; return 0
  fi

  sort -u "$dir/all_urls_raw.txt" > "$dir/all_urls.txt"

  python3 - "$dir/all_urls.txt" "$dir" "$DB_FILE" << 'PYEOF'
import sys, re, sqlite3
from urllib.parse import urlparse, parse_qs

urls_file, out_dir, db_path = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect(db_path)
run_id = db.execute("SELECT value FROM _meta WHERE key='run_id'").fetchone()[0]

# Parameter → vulnerability class mapping
SSRF_PARAMS    = {'url','webhook','redirect_url','callback','fetch','load',
                  'src','dest','uri','endpoint','proxy','return_url','next',
                  'return','continue','checkout_url','service','host','target'}
REDIRECT_PARAMS = {'redirect','redir','r','destination','dest','forward',
                   'location','goto','out','view','loginto','image_url','open'}
IDOR_PARAMS    = {'id','user_id','uid','account_id','profile_id','order_id',
                  'invoice_id','ticket_id','customer_id','member_id'}
LFI_PARAMS     = {'file','path','filename','page','template','doc','folder',
                  'root','include','require','view','content','pg','style'}

param_urls = {'ssrf': [], 'redirect': [], 'idor': [], 'lfi': [], 'generic': []}

try:
    lines = open(urls_file).read().splitlines()
except FileNotFoundError:
    sys.exit(0)

all_parameterized = []
seen = set()

for url in lines:
    url = url.strip()
    if '?' not in url or url in seen:
        continue
    seen.add(url)
    all_parameterized.append(url)

    try:
        parsed = urlparse(url)
        params = set(parse_qs(parsed.query).keys())
        hostname = parsed.hostname or ''  # Fix 4: store parsed host for SQL joins
    except Exception:
        continue

    kind = 'generic'
    score = 4

    if params & SSRF_PARAMS:
        kind = 'ssrf'; score = 9
    elif params & REDIRECT_PARAMS:
        kind = 'redirect'; score = 8
    elif params & IDOR_PARAMS:
        kind = 'idor'; score = 7
    elif params & LFI_PARAMS:
        kind = 'lfi'; score = 8

    param_urls[kind].append(url)

    db.execute(
        "INSERT OR IGNORE INTO parameters (run_id, url, host, params, kind, score) VALUES (?,?,?,?,?,?)",
        (run_id, url, hostname.lower(), ','.join(params), kind, score)
    )

    if score >= 7:
        db.execute(
            "INSERT OR IGNORE INTO findings (run_id, source, category, title, detail, score) VALUES (?,?,?,?,?,?)",
            (run_id, 'param', f"{kind.upper()}", f"{kind.upper()} candidate parameter", url[:200], score)
        )

db.commit()
db.close()

with open(f'{out_dir}/parameterized.txt', 'w') as f:
    f.write('\n'.join(all_parameterized)+'\n')

# Write per-class files
for kind, urls in param_urls.items():
    with open(f'{out_dir}/{kind}_params.txt', 'w') as f:
        f.write('\n'.join(urls)+'\n')

total_juicy = sum(len(v) for k,v in param_urls.items() if k != 'generic')
print(f"Total parameterised: {len(all_parameterized)} | "
      f"SSRF:{len(param_urls['ssrf'])} Redirect:{len(param_urls['redirect'])} "
      f"IDOR:{len(param_urls['idor'])} LFI:{len(param_urls['lfi'])} "
      f"Juicy total: {total_juicy}")
PYEOF

  ok "Parameterized URLs: $(count "$dir/parameterized.txt")"
  for kind in ssrf redirect idor lfi; do
    local n
    n=$(count "$dir/${kind}_params.txt")
    [ "$n" -gt 0 ] && warn "${kind^^} candidates: $n → $dir/${kind}_params.txt"
  done

  notify "🔗 Params done — $DOMAIN"
  state_mark_done "params"
}

# ── MODULE 6: Google Dorks ────────────────────────────────────
run_dorks() {
  state_is_done "dorks" && { info "Dorks: already done (resume)"; return 0; }
  section "GOOGLE DORKS"
  local dir="$OUT_DIR/dorks"
  mkdir -p "$dir"

  cat > "$dir/dorks.txt" << EOF
site:${DOMAIN} ext:log
site:${DOMAIN} ext:env
site:${DOMAIN} ext:xml inurl:config
site:${DOMAIN} filetype:sql
site:${DOMAIN} filetype:bak
site:${DOMAIN} inurl:admin
site:${DOMAIN} inurl:login
site:${DOMAIN} inurl:dashboard
site:${DOMAIN} inurl:swagger
site:${DOMAIN} inurl:graphql
site:${DOMAIN} "api_key"
site:${DOMAIN} intitle:"index of"
site:${DOMAIN} inurl:/.git/
site:${DOMAIN} "SQL syntax"
site:${DOMAIN} "stack trace"
site:${DOMAIN} inurl:api/v1
site:${DOMAIN} inurl:.env
site:${DOMAIN} inurl:config.json
site:${DOMAIN} inurl:phpinfo.php
site:${DOMAIN} intext:"internal server error"
EOF

  info "Generated $(count "$dir/dorks.txt") dorks → $dir/dorks.txt"

  # GitHub dorks (manual — requires browser/token)
  cat > "$dir/github_dorks.txt" << EOF
org:${DOMAIN%%.*} "api_key"
org:${DOMAIN%%.*} filename:.env
org:${DOMAIN%%.*} "aws_access_key_id"
org:${DOMAIN%%.*} "DB_PASSWORD"
org:${DOMAIN%%.*} "mongodb+srv"
"${DOMAIN}" password
"${DOMAIN}" "BEGIN RSA PRIVATE KEY"
"${DOMAIN}" internal api
EOF

  info "GitHub dorks → $dir/github_dorks.txt (manual browser use)"
  state_mark_done "dorks"
}

# ── MODULE 7: Cloud Buckets ───────────────────────────────────
run_cloud() {
  state_is_done "cloud" && { info "Cloud: already done (resume)"; return 0; }
  section "CLOUD BUCKET RECON"
  local dir="$OUT_DIR/cloud"
  mkdir -p "$dir"

  local company
  company=$(echo "$DOMAIN" | cut -d'.' -f1)

  python3 - "$company" > "$dir/bucket_names.txt" << 'PYEOF'
import sys
company = sys.argv[1]
suffixes = ["dev","prod","staging","backup","data","assets","files",
            "internal","logs","temp","test","media","uploads","static",
            "public","private","infra","cdn","storage","config","secrets"]
prefixes = ["","aws-","s3-","cdn-","app-","cloud-"]
names = set()
for p in prefixes:
    for s in suffixes:
        names.add(f"{p}{company}-{s}")
        names.add(f"{p}{s}-{company}")
        names.add(f"{p}{company}{s}")
    names.add(f"{p}{company}")
for n in sorted(names):
    print(n)
PYEOF

  ok "Generated $(count "$dir/bucket_names.txt") bucket permutations"

  if has s3scanner; then
    info "Scanning with s3scanner…"
    run_tool "s3scanner" s3scanner scan \
      --bucket-file "$dir/bucket_names.txt" \
      --out-file "$dir/s3_results.txt" || true
    grep -iE "open|public|listable" "$dir/s3_results.txt" \
      > "$dir/open_buckets.txt" 2>/dev/null || true
    local open_n
    open_n=$(count "$dir/open_buckets.txt")
    ok "Open/misconfigured buckets: $open_n"
    if [ "$open_n" -gt 0 ]; then
      db_finding "cloud" "cloud" "Open S3 bucket found" \
        "$(head -1 "$dir/open_buckets.txt")" "10"
      notify "🪣 OPEN BUCKET: $open_n found — $DOMAIN"
    fi
  else
    warn "s3scanner not found (pip install s3scanner)"
    info "Bucket names saved — check manually: aws s3 ls s3://BUCKET"
  fi

  state_mark_done "cloud"
}

# ── MODULE 8: Screenshots ─────────────────────────────────────
run_screenshots() {
  state_is_done "screenshots" && { info "Screenshots: already done (resume)"; return 0; }
  section "SCREENSHOTS"
  local urls="$OUT_DIR/http/live_urls.txt"
  local dir="$OUT_DIR/screenshots"
  mkdir -p "$dir"

  [ -f "$urls" ] || { warn "No live URLs — run http first"; state_mark_done "screenshots"; return 0; }

  if has gowitness; then
    info "gowitness (8 threads)…"
    run_tool "gowitness" gowitness file -f "$urls" \
      --delay 2 --threads 8 \
      --screenshot-path "$dir/" || true
    ok "Screenshots → $dir/"
  elif has eyewitness; then
    run_tool "eyewitness" eyewitness --web -f "$urls" \
      --timeout 10 --threads 8 -d "$dir/" || true
    ok "Screenshots → $dir/"
  else
    warn "No screenshot tool found (gowitness/eyewitness)"
  fi

  state_mark_done "screenshots"
}

# ── MODULE 9: Asset Correlation + Scoring ────────────────────
run_correlate() {
  section "ASSET CORRELATION & SCORING"
  local dir="$OUT_DIR/report"
  mkdir -p "$dir"

  python3 - "$DB_FILE" "$dir" "$DOMAIN" << 'PYEOF'
import sys, sqlite3, json
from datetime import datetime

db_path, out_dir, domain = sys.argv[1], sys.argv[2], sys.argv[3]
db = sqlite3.connect(db_path)

# ── Build asset graph (JSON) ──────────────────────────────────
graph = {}
run_id = db.execute("SELECT value FROM _meta WHERE key='run_id'").fetchone()[0]
subdomains = db.execute("SELECT host, ip FROM subdomains WHERE run_id=?", (run_id,)).fetchall()
for host, ip in subdomains:
    entry = {'ip': ip, 'ports': [], 'http': [], 'js_endpoints': [], 'parameters': []}

    # Linked ports
    ports = db.execute("SELECT port, service, score FROM open_ports WHERE run_id=? AND host=?", (run_id, host)).fetchall()
    entry['ports'] = [{'port': p, 'service': s, 'score': sc} for p,s,sc in ports]

    # Linked HTTP services
    http = db.execute("SELECT url, status, title, tech FROM http_services WHERE run_id=? AND subdomain=?", (run_id, host)).fetchall()
    entry['http'] = [{'url': u, 'status': st, 'title': t, 'tech': tc} for u,st,t,tc in http]

    graph[host] = entry

# Link JS endpoints and params by parsed hostname match (Fix 2: no more naive string-in)
from urllib.parse import urlparse as _up

def _host(raw):
    """Return lowercase hostname from an absolute or relative URL, or '' if unparseable."""
    try:
        h = _up(raw).hostname or ''
        return h.lower()
    except Exception:
        return ''

js_eps = db.execute("SELECT value FROM js_findings WHERE run_id=? AND kind='endpoint'", (run_id,)).fetchall()
params = db.execute("SELECT url, kind, score FROM parameters WHERE run_id=? AND score >= 7", (run_id,)).fetchall()

# Build lookup sets for O(1) membership tests
_ep_by_host = {}
for (ep,) in js_eps:
    h = _host(ep)
    if h:
        _ep_by_host.setdefault(h, []).append(ep)
    # Also keep relative endpoints as-is (they'll link to the graph host that owns them)
    # relative paths have no hostname; skip for now — they appear in the JS section

_param_by_host = {}
for (u, k, s) in params:
    h = _host(u)
    if h:
        _param_by_host.setdefault(h, []).append({'url': u, 'kind': k, 'score': s})

for host in graph:
    graph[host]['js_endpoints'] = _ep_by_host.get(host, [])
    graph[host]['parameters']   = _param_by_host.get(host, [])

with open(f'{out_dir}/asset_graph.json', 'w') as f:
    json.dump(graph, f, indent=2)

# ── Top findings by score ─────────────────────────────────────
findings = db.execute(
    "SELECT category, title, detail, score FROM findings WHERE run_id=? ORDER BY score DESC LIMIT 30", (run_id,)
).fetchall()

# ── Markdown report ───────────────────────────────────────────
lines = [
    f"# Recon Report: {domain}",
    f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n",
    "## Summary",
]

stats = {
    'Live subdomains':  db.execute("SELECT COUNT(*) FROM subdomains WHERE run_id=?", (run_id,)).fetchone()[0],
    'HTTP services':    db.execute("SELECT COUNT(*) FROM http_services WHERE run_id=?", (run_id,)).fetchone()[0],
    'Open ports':       db.execute("SELECT COUNT(*) FROM open_ports WHERE run_id=?", (run_id,)).fetchone()[0],
    'JS endpoints':     db.execute("SELECT COUNT(*) FROM js_findings WHERE run_id=? AND kind='endpoint'", (run_id,)).fetchone()[0],
    'Potential secrets':db.execute("SELECT COUNT(*) FROM js_findings WHERE run_id=? AND kind='secret'", (run_id,)).fetchone()[0],
    'Parameterized URLs':db.execute("SELECT COUNT(*) FROM parameters WHERE run_id=?", (run_id,)).fetchone()[0],
    'SSRF candidates':  db.execute("SELECT COUNT(*) FROM parameters WHERE run_id=? AND kind='ssrf'", (run_id,)).fetchone()[0],
    'Redirect candidates':db.execute("SELECT COUNT(*) FROM parameters WHERE run_id=? AND kind='redirect'", (run_id,)).fetchone()[0],
    'Total findings':   db.execute("SELECT COUNT(*) FROM findings WHERE run_id=?", (run_id,)).fetchone()[0],
}
for k, v in stats.items():
    lines.append(f"- **{k}**: {v}")

lines += ["", "## Top Attack Surfaces (by score)", ""]
lines.append("| Score | Category | Title | Detail |")
lines.append("|-------|----------|-------|--------|")
for cat, title, detail, score in findings:
    d = (detail or '')[:80].replace('|','\\|')
    lines.append(f"| **{score}** | {cat} | {title} | `{d}` |")

lines += ["", "## Correlation Highlights", ""]

# Subdomains with both interesting ports AND HTTP services
cursor = db.execute(
    """SELECT DISTINCT o.host, o.port, o.service, h.url, h.title
       FROM open_ports o
       JOIN http_services h ON h.subdomain = o.host AND h.run_id = o.run_id
       WHERE o.run_id=? AND o.score >= 8
       LIMIT 20""",
    (run_id,)
)
corr = cursor.fetchall()
if corr:
    lines.append("### High-value hosts (interesting port + HTTP service)")
    for host, port, svc, url, title in corr:
        lines.append(f"- `{host}:{port}` ({svc}) → [{title or url}]({url})")
else:
    lines.append("*No correlated high-value hosts found.*")

lines += ["", "## SSRF / Redirect Candidates", ""]
ssrf = db.execute("SELECT url FROM parameters WHERE run_id=? AND kind='ssrf' LIMIT 20", (run_id,)).fetchall()
redir = db.execute("SELECT url FROM parameters WHERE run_id=? AND kind='redirect' LIMIT 20", (run_id,)).fetchall()
if ssrf:
    lines.append("**SSRF:**")
    for (u,) in ssrf: lines.append(f"- `{u[:120]}`")
if redir:
    lines.append("\n**Open Redirect:**")
    for (u,) in redir: lines.append(f"- `{u[:120]}`")

report_md = '\n'.join(lines)
with open(f'{out_dir}/report.md', 'w') as f:
    f.write(report_md)

print(report_md)
PYEOF

  ok "Asset graph → $dir/asset_graph.json"
  ok "Report     → $dir/report.md"
}

# ── Full Pipeline ─────────────────────────────────────────────
run_full() {
  section "FULL PIPELINE"
  notify "🚀 Recon started: \`$DOMAIN\`"
  local start=$SECONDS

  run_subdomains
  run_http_probe
  run_ports
  run_js
  run_params
  run_dorks
  run_cloud
  run_correlate

  local elapsed=$(( SECONDS - start ))
  ok "Pipeline complete in ${elapsed}s → $OUT_DIR"
  notify "✅ Recon done for $DOMAIN (${elapsed}s) — check report/"
}

# ── Interactive Menu ──────────────────────────────────────────
interactive_menu() {
  while true; do
    echo ""
    echo -e "  ${BOLD}Target:${RESET} ${GREEN}$DOMAIN${RESET}   ${BOLD}Output:${RESET} ${CYAN}$OUT_DIR${RESET}"
    echo ""
    echo -e "  ${BOLD}[1]${RESET}  Subdomain Enumeration"
    echo -e "  ${BOLD}[2]${RESET}  HTTP Probing"
    echo -e "  ${BOLD}[3]${RESET}  Port Scanning"
    echo -e "  ${BOLD}[4]${RESET}  JavaScript Mining"
    echo -e "  ${BOLD}[5]${RESET}  Parameter Discovery"
    echo -e "  ${BOLD}[6]${RESET}  Google Dorks"
    echo -e "  ${BOLD}[7]${RESET}  Cloud Bucket Recon"
    echo -e "  ${BOLD}[8]${RESET}  Screenshots"
    echo -e "  ${BOLD}[9]${RESET}  Asset Correlation + Report"
    echo -e "  ${BOLD}[F]${RESET}  🚀 Run Full Pipeline"
    echo -e "  ${BOLD}[Q]${RESET}  Quit"
    echo ""
    read -rp "$(echo -e "${BOLD}  > ${RESET}")" choice

    case "${choice^^}" in
      1) run_subdomains ;;
      2) run_http_probe ;;
      3) run_ports ;;
      4) run_js ;;
      5) run_params ;;
      6) run_dorks ;;
      7) run_cloud ;;
      8) run_screenshots ;;
      9) run_correlate ;;
      F) run_full ;;
      Q) ok "Done. Results in $OUT_DIR"; exit 0 ;;
      *) warn "Invalid choice" ;;
    esac
  done
}

# ── Usage ─────────────────────────────────────────────────────
usage() {
  echo -e "
${BOLD}Usage:${RESET}
  ./tanyaa.sh <domain>                       Interactive menu
  ./tanyaa.sh <domain> --full                Full pipeline
  ./tanyaa.sh <domain> --resume              Resume interrupted run
  ./tanyaa.sh <domain> --module <name>       Single module
  ./tanyaa.sh <domain> --query <sql|alias>   Query the SQLite DB
    aliases: findings  ssrf  ports  secrets

${BOLD}Modules:${RESET}
  subdomains  http  ports  js  params  dorks  cloud  screenshots  correlate

${BOLD}Examples:${RESET}
  ./recon.sh example.com
  ./recon.sh example.com --full
  ./recon.sh example.com --resume
  ./recon.sh example.com --module js
"
  exit 0
}

# ── Entry Point ───────────────────────────────────────────────
main() {
  banner

  [ $# -eq 0 ] && usage

  validate_target "$1"
  shift

  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  OUT_DIR="$OUTPUT_BASE/${DOMAIN}_${TIMESTAMP}"

  # Resume: find latest run dir
  if [[ "${1:-}" == "--resume" ]]; then
    local latest
    latest=$(ls -td "$OUTPUT_BASE/${DOMAIN}_"* 2>/dev/null | head -1 || true)
    if [[ -n "$latest" ]]; then
      OUT_DIR="$latest"
      info "Resuming run: $OUT_DIR"
    else
      warn "No previous run found — starting fresh"
    fi
    shift
  fi

  mkdir -p "$OUT_DIR"
  LOG_FILE="$OUT_DIR/recon.log"
  STATE_FILE="$OUT_DIR/.state"
  DB_FILE="$OUT_DIR/recon.db"

  touch "$STATE_FILE" "$LOG_FILE"
  db_init

  info "Target : $DOMAIN"
  info "Output : $OUT_DIR"
  info "DB     : $DB_FILE"
  info "Log    : $LOG_FILE"

  case "${1:-}" in
    --full)     run_full ;;
    --module)
      [[ -z "${2:-}" ]] && die "Specify a module name"
      case "$2" in
        subdomains)  run_subdomains ;;
        http)        run_http_probe ;;
        ports)       run_ports ;;
        js)          run_js ;;
        params)      run_params ;;
        dorks)       run_dorks ;;
        cloud)       run_cloud ;;
        screenshots) run_screenshots ;;
        correlate)   run_correlate ;;
        *)           die "Unknown module: $2" ;;
      esac
      ;;
    --query)
      # Quick DB query shortcut: ./recon.sh <domain> --query "SELECT ..."
      # or built-in named queries: findings | ssrf | ports | secrets
      [[ -z "${2:-}" ]] && die "Provide a SQL query or alias (findings|ssrf|ports|secrets)"
      case "$2" in
        findings) db_query "SELECT score,source,category,title,detail FROM findings ORDER BY score DESC LIMIT 30" ;;
        ssrf)     db_query "SELECT url FROM parameters WHERE kind='ssrf'" ;;
        ports)    db_query "SELECT host,port,service,score FROM open_ports WHERE score>=8 ORDER BY score DESC" ;;
        secrets)  db_query "SELECT kind,value,context FROM js_findings WHERE kind='secret'" ;;
        *)        db_query "$2" ;;
      esac
      ;;
    --help|-h)  usage ;;
    "")         interactive_menu ;;
    *)          die "Unknown option: $1 — use --help" ;;
  esac
}

main "$@"