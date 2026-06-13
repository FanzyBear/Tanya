#!/usr/bin/env bash
# ============================================================
#  tanya.sh — Web Recon Pipeline v5.0 (txt/jsonl, no DB)
#
#  Usage:
#    ./tanya.sh <target> [options]
#
#  Examples:
#    ./tanya.sh example.com
#    ./tanya.sh https://juice-shop.herokuapp.com/#/ --full
#    ./tanya.sh 203.0.113.10 --full
#    ./tanya.sh app.example.com --apex --full      # force subdomain enum on example.com
#    ./tanya.sh example.com --single --full         # treat as one host, skip enum
#    ./tanya.sh example.com --resume
#    ./tanya.sh example.com --module nuclei
#
#  AUTHORIZATION: Only scan assets you own or are explicitly
#  authorized (in scope) to test. You are responsible for use.
# ============================================================

set -uo pipefail

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Paths / globals ──────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_BASE="$SCRIPT_DIR/output"
CONFIG_FILE="$SCRIPT_DIR/config.env"
OUT_DIR=""
DOMAIN=""           # the registrable scope (apex) used for enumeration
TARGET_HOST=""      # the exact host the user pointed at (always seeded)
TARGET_SCHEME=""    # http/https if a URL was given
SCOPE_MODE="apex"   # "apex" (enumerate subdomains) | "single" (one host)
STATE_FILE=""
LOG_FILE=""

# ── Config defaults (override in config.env) ─────────────────
HTTPX_THREADS=50
NAABU_THREADS=100
NAABU_RATE=1000
KATANA_DEPTH=3
FFUF_THREADS=40
FFUF_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"
CURL_UA="Mozilla/5.0 (recon; +tanya.sh)"

# Hosts on these providers are single apps, not enumerable apexes.
PAAS_SUFFIXES=(
  herokuapp.com vercel.app netlify.app netlify.com pages.dev github.io
  web.app firebaseapp.com azurewebsites.net onrender.com fly.dev
  workers.dev surge.sh glitch.me repl.co replit.dev ngrok.io
  ngrok-free.app trycloudflare.com appspot.com elasticbeanstalk.com
  cloudfront.net amazonaws.com render.com pythonanywhere.com
)

[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

# ── Logging ──────────────────────────────────────────────────
_log()    { echo -e "$*" | tee -a "${LOG_FILE:-/dev/null}"; }
info()    { _log "${CYAN}[*]${RESET} $*"; }
ok()      { _log "${GREEN}[+]${RESET} $*"; }
warn()    { _log "${YELLOW}[!]${RESET} $*"; }
err()     { _log "${RED}[x]${RESET} $*"; }
section() { _log "\n${BOLD}${YELLOW}=== $* ===${RESET}"; }
die()     { err "$*"; exit 1; }

banner() {
cat << 'EOF'

  ████████╗ █████╗ ███╗   ██╗██╗   ██╗ █████╗
     ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝██╔══██╗      _._     _,-'""`-._
     ██║   ███████║██╔██╗ ██║ ╚████╔╝ ███████║     (,-.`._,'(       |\`-/|
     ██║   ██╔══██║██║╚██╗██║  ╚██╔╝  ██╔══██║          `-.-' \ )-`( , o o)
     ██║   ██║  ██║██║ ╚████║   ██║   ██║  ██║               `-    \`_`"'-
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
            Web Recon Pipeline v5.0

EOF
}

# ── Helpers ──────────────────────────────────────────────────
has()   { command -v "$1" >/dev/null 2>&1; }
need()  { has "$1" || die "'$1' not found — install it first"; }

# Robust line count (handles files with no trailing newline)
count() { if [ -f "$1" ]; then awk 'END{print NR+0}' "$1" 2>/dev/null; else echo 0; fi; }

# Non-empty file?
nonempty() { [ -s "$1" ]; }

run_tool() {
  local label="$1"; shift
  if "$@" 2>>"${LOG_FILE:-/dev/null}"; then
    return 0
  else
    warn "$label exited non-zero (see log)"
    return 1
  fi
}

retry() {
  local attempts="$1"; shift
  local delay=2 n=0
  until "$@" 2>>"${LOG_FILE:-/dev/null}"; do
    n=$(( n + 1 ))
    [ "$n" -ge "$attempts" ] && { warn "Failed after $attempts attempts"; return 1; }
    warn "Attempt $n failed, retrying in ${delay}s…"
    sleep "$delay"
    delay=$(( delay * 2 ))
  done
}

# normalize a stream of hostnames: strip scheme/path/port, lowercase, drop wildcards & junk
normalize_hosts() {
  sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s/:[0-9]+$//; s/^\*\.//' \
    | tr '[:upper:]' '[:lower:]' \
    | grep -E '^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$' \
    | sort -u
}

# ── Resume state ─────────────────────────────────────────────
state_mark_done() { echo "$1" >> "$STATE_FILE"; }
state_is_done()   { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }

# ── Target parsing & scope detection ─────────────────────────
is_ip() { echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; }

is_paas_host() {
  local h="$1" suf
  for suf in "${PAAS_SUFFIXES[@]}"; do
    [[ "$h" == *".$suf" || "$h" == "$suf" ]] && return 0
  done
  return 1
}

parse_target() {
  local raw="$1"

  # capture scheme if present
  if [[ "$raw" =~ ^([a-zA-Z]+):// ]]; then
    TARGET_SCHEME="${BASH_REMATCH[1],,}"
  fi
  raw="${raw#http://}"; raw="${raw#https://}"
  raw="${raw%%/*}"          # drop path / fragment
  raw="${raw%%\?*}"         # drop query
  raw="${raw%%:*}"          # drop :port
  raw="${raw,,}"

  [ -n "$raw" ] || die "Empty target"

  if is_ip "$raw"; then
    TARGET_HOST="$raw"
    DOMAIN="$raw"
    SCOPE_MODE="single"
    info "Target is an IP — single-host mode"
  elif echo "$raw" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'; then
    TARGET_HOST="$raw"
    if is_paas_host "$raw"; then
      DOMAIN="$raw"
      SCOPE_MODE="single"
      info "Target sits on a PaaS provider — single-host mode (no subdomain enum)"
    else
      DOMAIN="$raw"
      SCOPE_MODE="apex"
    fi
  else
    die "Invalid target: '$1'. Provide a domain, URL, or IP (e.g. example.com)"
  fi

  # resolve check (best-effort, never fatal)
  if has host && host "$TARGET_HOST" >/dev/null 2>&1; then
    ok "Resolves: $TARGET_HOST"
  elif has nslookup && nslookup "$TARGET_HOST" >/dev/null 2>&1; then
    ok "Resolves: $TARGET_HOST"
  else
    warn "Could not confirm DNS resolution for $TARGET_HOST — continuing anyway"
  fi
}

# ── Dependency preflight ─────────────────────────────────────
check_deps() {
  section "DEPENDENCY CHECK"
  local core=(curl jq)                      # pipeline relies on these
  local recommended=(subfinder httpx naabu nuclei katana ffuf)
  local optional=(assetfinder amass waybackurls gau gowitness eyewitness \
                  arjun trufflehog gitleaks s3scanner host nslookup nc)
  local missing_core=()

  printf "  ${BOLD}%-14s %s${RESET}\n" "TOOL" "STATUS"
  for t in "${core[@]}"; do
    if has "$t"; then printf "  %-14s ${GREEN}ok${RESET}\n" "$t"
    else printf "  %-14s ${RED}MISSING (required)${RESET}\n" "$t"; missing_core+=("$t"); fi
  done
  for t in "${recommended[@]}"; do
    if has "$t"; then printf "  %-14s ${GREEN}ok${RESET}\n" "$t"
    else printf "  %-14s ${YELLOW}missing${RESET}\n" "$t"; fi
  done
  for t in "${optional[@]}"; do
    has "$t" && printf "  %-14s ${GREEN}ok${RESET}\n" "$t" \
             || printf "  %-14s ${MAGENTA}skip${RESET}\n" "$t"
  done

  if [ "${#missing_core[@]}" -gt 0 ]; then
    warn "Install required tools: ${missing_core[*]}"
    warn "  jq:   sudo apt install jq      curl: sudo apt install curl"
    die  "Cannot continue without core tools."
  fi
  echo ""
}

# ── MODULE 1: Subdomain Enumeration / Seed ───────────────────
run_subdomains() {
  state_is_done "subdomains" && { info "Subdomains: done (resume)"; return 0; }
  section "SUBDOMAIN ENUMERATION"
  local dir="$OUT_DIR/subdomains"
  mkdir -p "$dir"
  local raw="$dir/raw.txt"
  : > "$raw"

  # Always seed the exact target host — THIS is what was missing before.
  echo "$TARGET_HOST" >> "$raw"

  if [ "$SCOPE_MODE" = "single" ]; then
    info "Single-host mode — skipping enumeration, seeding target only"
  else
    if has subfinder; then
      info "subfinder…"
      run_tool subfinder subfinder -d "$DOMAIN" -all -recursive -silent \
        -o "$dir/subfinder.txt" || true
      [ -f "$dir/subfinder.txt" ] && cat "$dir/subfinder.txt" >> "$raw"
    fi
    if has assetfinder; then
      info "assetfinder…"
      assetfinder --subs-only "$DOMAIN" > "$dir/assetfinder.txt" 2>>"$LOG_FILE" || true
      cat "$dir/assetfinder.txt" >> "$raw" 2>/dev/null || true
    fi
    if has amass; then
      info "amass (passive, 120s cap)…"
      timeout 120 amass enum -passive -d "$DOMAIN" -o "$dir/amass.txt" \
        >>"$LOG_FILE" 2>&1 || true
      cat "$dir/amass.txt" >> "$raw" 2>/dev/null || true
    fi
    info "crt.sh…"
    retry 3 bash -c \
      "curl -sf --max-time 30 'https://crt.sh/?q=%25.${DOMAIN}&output=json' \
       | jq -r '.[].name_value' 2>/dev/null \
       | sed 's/\*\.//g' | tr ',' '\n' >> '$raw'" \
      || warn "crt.sh failed (rate-limited or down)"
  fi

  # Normalize + scope filter. In apex mode keep only in-scope hosts;
  # in single mode keep only the exact host (and its sub-hosts if any).
  local esc="${DOMAIN//./\\.}"
  normalize_hosts < "$raw" \
    | grep -E "(^|\.)${esc}\$" \
    | sort -u > "$dir/subs.txt"

  # Guarantee the seed survived the filter (covers odd PaaS names).
  grep -qxF "$TARGET_HOST" "$dir/subs.txt" 2>/dev/null \
    || echo "$TARGET_HOST" >> "$dir/subs.txt"
  sort -u -o "$dir/subs.txt" "$dir/subs.txt"

  ok "In-scope hosts: $(count "$dir/subs.txt") → $dir/subs.txt"
  state_mark_done "subdomains"
}

# ── MODULE 2: HTTP Probing + WAF (jsonl-based, version-robust) ─
run_http_probe() {
  state_is_done "http" && { info "HTTP: done (resume)"; return 0; }
  section "HTTP PROBING"
  local dir="$OUT_DIR/http"
  local subs="$OUT_DIR/subdomains/subs.txt"
  mkdir -p "$dir"

  nonempty "$subs" || { warn "No hosts to probe — run subdomains first"; return 0; }
  need httpx; need jq

  info "httpx on $(count "$subs") host(s), threads=$HTTPX_THREADS…"
  retry 2 httpx \
    -l "$subs" \
    -json \
    -title -tech-detect -status-code -content-length -web-server \
    -follow-redirects \
    -threads "$HTTPX_THREADS" \
    -silent \
    -o "$dir/alive.jsonl" || warn "httpx had issues — using whatever it produced"

  if ! nonempty "$dir/alive.jsonl"; then
    warn "No live HTTP services found."
    state_mark_done "http"
    return 0
  fi

  # Robust parsing via jq (works across httpx versions)
  jq -r '.url' "$dir/alive.jsonl" | sort -u > "$dir/live_urls.txt"
  jq -r 'select(.status_code==200)         | .url' "$dir/alive.jsonl" | sort -u > "$dir/status_200.txt"
  jq -r 'select(.status_code==401 or .status_code==403) | .url' "$dir/alive.jsonl" | sort -u > "$dir/status_401_403.txt"
  jq -r 'select(.status_code>=300 and .status_code<400) | .url' "$dir/alive.jsonl" | sort -u > "$dir/status_redirect.txt"

  # Human-readable summary line per host
  jq -r '"\(.url)\t[\(.status_code // "?")]\t\(.title // "")\t\((.tech // []) | join(","))"' \
    "$dir/alive.jsonl" | sort -u > "$dir/alive.txt"

  # Flag high-value services by URL or title
  grep -iE '(jenkins|grafana|kibana|elastic|phpmyadmin|adminer|/admin|dashboard|swagger|graphql|prometheus|jupyter|portainer|gitlab|sonar|kong|consul|vault|rabbitmq|airflow)' \
    "$dir/alive.txt" > "$dir/interesting.txt" 2>/dev/null || true

  ok "Live URLs: $(count "$dir/live_urls.txt") → $dir/alive.txt"
  [ "$(count "$dir/interesting.txt")" -gt 0 ] && \
    warn "$(count "$dir/interesting.txt") high-value service(s) → $dir/interesting.txt"

  # WAF detection via nuclei
  if has nuclei && nonempty "$dir/live_urls.txt"; then
    info "WAF detection (nuclei waf templates)…"
    nuclei -l "$dir/live_urls.txt" -tags waf -silent \
      -o "$dir/waf.txt" 2>>"$LOG_FILE" || true
    local n; n=$(count "$dir/waf.txt")
    [ "$n" -gt 0 ] && warn "$n WAF fingerprint(s) → $dir/waf.txt" || ok "No WAF detected"
  else
    warn "nuclei unavailable — skipping WAF detection"
  fi

  state_mark_done "http"
}

# ── MODULE 3: Port Scanning ──────────────────────────────────
run_ports() {
  state_is_done "ports" && { info "Ports: done (resume)"; return 0; }
  section "PORT SCANNING"
  local dir="$OUT_DIR/ports"
  local subs="$OUT_DIR/subdomains/subs.txt"
  mkdir -p "$dir"
  nonempty "$subs" || { warn "No hosts — run subdomains first"; return 0; }

  if has naabu; then
    info "naabu top-1000 ports…"
    retry 2 naabu -list "$subs" -top-ports 1000 -rate "$NAABU_RATE" \
      -c "$NAABU_THREADS" -silent -o "$dir/ports.txt" \
      || warn "naabu had issues — partial results possible"
  else
    warn "naabu not found — nc fallback (slow, top ports only)"
    : > "$dir/ports.txt"
    while IFS= read -r host; do
      for p in 80 443 8080 8443 3000 5000 6379 9200 27017 2375 10250 9000; do
        nc -z -w 2 "$host" "$p" 2>/dev/null && echo "${host}:${p}" >> "$dir/ports.txt"
      done
    done < "$subs"
  fi

  grep -E ':(2375|2376|6379|9200|9300|27017|28017|10250|4848|5900|7001|8888|9090|2379|5601)$' \
    "$dir/ports.txt" > "$dir/high_interest.txt" 2>/dev/null || true

  ok "Open ports: $(count "$dir/ports.txt") → $dir/ports.txt"
  [ "$(count "$dir/high_interest.txt")" -gt 0 ] && \
    warn "High-risk ports → $dir/high_interest.txt"
  state_mark_done "ports"
}

# ── MODULE 4: Screenshots ────────────────────────────────────
run_screenshots() {
  state_is_done "screenshots" && { info "Screenshots: done (resume)"; return 0; }
  section "SCREENSHOTS"
  local urls="$OUT_DIR/http/live_urls.txt"
  local dir="$OUT_DIR/screenshots"
  mkdir -p "$dir"
  nonempty "$urls" || { warn "No live URLs — run http first"; state_mark_done "screenshots"; return 0; }

  if has gowitness; then
    info "gowitness…"
    run_tool gowitness gowitness scan file -f "$urls" \
      --delay 2 --threads 8 --screenshot-path "$dir/" || true
    ok "Screenshots → $dir/"
  elif has eyewitness; then
    run_tool eyewitness eyewitness --web -f "$urls" \
      --timeout 10 --threads 8 -d "$dir/" || true
    ok "Screenshots → $dir/"
  else
    warn "No screenshot tool (gowitness/eyewitness)"
  fi
  state_mark_done "screenshots"
}

# ── MODULE 5: URL Collection ─────────────────────────────────
run_urls() {
  state_is_done "urls" && { info "URLs: done (resume)"; return 0; }
  section "URL COLLECTION"
  local dir="$OUT_DIR/urls"
  local alive="$OUT_DIR/http/live_urls.txt"
  mkdir -p "$dir"
  touch "$dir/katana.txt" "$dir/wayback.txt" "$dir/gau.txt"

  if has katana && nonempty "$alive"; then
    info "katana crawl (depth $KATANA_DEPTH)…"
    run_tool katana katana -list "$alive" -jc -d "$KATANA_DEPTH" -silent \
      -o "$dir/katana.txt" || true
  fi
  if has waybackurls; then
    info "waybackurls…"
    waybackurls "$TARGET_HOST" > "$dir/wayback.txt" 2>>"$LOG_FILE" || warn "waybackurls failed"
  fi
  if has gau; then
    info "gau…"
    gau --threads 20 --subs \
      --blacklist png,jpg,gif,svg,css,woff,ttf,ico,mp4 \
      "$TARGET_HOST" > "$dir/gau.txt" 2>>"$LOG_FILE" || warn "gau failed"
  fi

  cat "$dir/katana.txt" "$dir/wayback.txt" "$dir/gau.txt" 2>/dev/null \
    | sort -u > "$dir/urls.txt"
  ok "Total URLs: $(count "$dir/urls.txt") → $dir/urls.txt"

  grep -iE '\.(js|json|env|bak|zip|sql|txt|log|xml|config|ya?ml)(\?.*)?$' \
    "$dir/urls.txt" > "$dir/interesting_files.txt" 2>/dev/null || true
  [ "$(count "$dir/interesting_files.txt")" -gt 0 ] && \
    warn "$(count "$dir/interesting_files.txt") interesting file URLs → $dir/interesting_files.txt"
  state_mark_done "urls"
}

# ── MODULE 6: JavaScript Recon ───────────────────────────────
run_js() {
  state_is_done "js" && { info "JS: done (resume)"; return 0; }
  section "JAVASCRIPT RECON"
  local dir="$OUT_DIR/js"
  local urls_file="$OUT_DIR/urls/urls.txt"
  mkdir -p "$dir/files"
  nonempty "$urls_file" || { warn "No URLs — run urls first"; state_mark_done "js"; return 0; }

  grep -iE '\.js(\?.*)?$' "$urls_file" | sort -u > "$dir/js_urls.txt" || true
  local js_count; js_count=$(count "$dir/js_urls.txt")
  if [ "$js_count" -eq 0 ]; then
    warn "No JS URLs found — skipping"; state_mark_done "js"; return 0
  fi

  info "Downloading $js_count JS files…"
  export CURL_UA dir
  cat "$dir/js_urls.txt" | xargs -P 20 -I{} bash -c '
    u="$1"
    fn=$(printf "%s" "$u" | md5sum | cut -d" " -f1)
    out="'"$dir"'/files/${fn}.js"
    [ -f "$out" ] && exit 0
    curl -sk -A "$CURL_UA" --max-time 15 "$u" -o "$out" 2>/dev/null || true
  ' _ {}

  info "Extracting endpoints…"
  cat "$dir/files"/*.js 2>/dev/null \
    | grep -Eo '(https?://[^"'"'"' \t<>{}()]{8,}|/api/[^"'"'"' \t<>{}()]{2,}|/v[0-9]+/[^"'"'"' \t<>{}()]{2,})' \
    | grep -vE '\.(png|jpg|gif|svg|ico|woff2?|ttf|css|mp4|eot)(\?|$)' \
    | sort -u > "$dir/endpoints.txt" || true

  info "Scanning for secrets…"
  if has trufflehog; then
    info "  → trufflehog…"
    trufflehog filesystem "$dir/files/" --json --no-update \
      2>>"$LOG_FILE" | grep -v '^$' > "$dir/trufflehog_raw.json" || true
    if nonempty "$dir/trufflehog_raw.json"; then
      python3 - "$dir/trufflehog_raw.json" "$dir/potential_secrets.txt" <<'PYEOF'
import json, sys
out = []
for line in open(sys.argv[1]):
    line = line.strip()
    if not line: continue
    try:
        o = json.loads(line)
        det = o.get("DetectorName", "unknown")
        val = (o.get("RawV2") or o.get("Raw") or "")[:120]
        loc = ""
        src = o.get("SourceMetadata", {}).get("Data", {})
        for v in src.values():
            if v: loc = str(v); break
        tag = "[VERIFIED]" if o.get("Verified") else "[unverified]"
        out.append(f"{tag} [{det}] {val}  ({loc})")
    except Exception:
        pass
open(sys.argv[2], "w").write("\n".join(dict.fromkeys(out)))
PYEOF
    fi
  elif has gitleaks; then
    info "  → gitleaks…"
    gitleaks detect --source "$dir/files/" --report-format json \
      --report-path "$dir/gitleaks_raw.json" --no-git --redact \
      2>>"$LOG_FILE" || true
    if nonempty "$dir/gitleaks_raw.json"; then
      python3 - "$dir/gitleaks_raw.json" "$dir/potential_secrets.txt" <<'PYEOF'
import json, sys
try: findings = json.load(open(sys.argv[1]))
except Exception: findings = []
out = []
for it in findings:
    rule = it.get("RuleID", "unknown")
    sec  = (it.get("Secret") or it.get("Match") or "")[:120]
    out.append(f"[{rule}] {sec}  ({it.get('File','')}:{it.get('StartLine','')})")
open(sys.argv[2], "w").write("\n".join(dict.fromkeys(out)))
PYEOF
    fi
  else
    warn "  no trufflehog/gitleaks — python regex fallback"
    python3 - "$dir/files" "$dir/potential_secrets.txt" <<'PYEOF'
import os, re, sys
root, outpath = sys.argv[1], sys.argv[2]
patterns = {
  "aws_key":  r"AKIA[0-9A-Z]{16}",
  "jwt":      r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
  "generic":  r"(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]",
  "mongo":    r"mongodb(?:\+srv)?://[^\s'\"<>]{8,}",
  "password": r"password\s*[:=]\s*['\"][^\s'\"]{8,}['\"]",
}
noise = re.compile(r"(example|placeholder|xxxx+|your[_-]?key|insert[_-]?here|dummy|sample|test123|changeme|redacted|undefined|null|<[^>]+>|\$\{)", re.I)
seen = []
for dp,_,fs in os.walk(root):
    for f in fs:
        try: txt = open(os.path.join(dp,f),"r",errors="ignore").read()
        except Exception: continue
        for name,pat in patterns.items():
            for m in re.findall(pat, txt):
                s = (m if isinstance(m,str) else m[0])
                if noise.search(s): continue
                line = f"[{name}] {s[:120]}"
                if line not in seen: seen.append(line)
open(outpath,"w").write("\n".join(seen))
PYEOF
  fi

  local sn; sn=$(count "$dir/potential_secrets.txt")
  ok "JS: $js_count files | $(count "$dir/endpoints.txt") endpoints | $sn secret hit(s)"
  [ "$sn" -gt 0 ] && warn "Potential secrets → $dir/potential_secrets.txt  (verify manually; many are false positives)"
  state_mark_done "js"
}

# ── MODULE 7: Directory Bruteforce ───────────────────────────
run_fuzz() {
  state_is_done "fuzz" && { info "Fuzz: done (resume)"; return 0; }
  section "DIRECTORY BRUTEFORCE"
  local dir="$OUT_DIR/fuzz"
  local urls="$OUT_DIR/http/live_urls.txt"
  mkdir -p "$dir"
  nonempty "$urls" || { warn "No live URLs — run http first"; state_mark_done "fuzz"; return 0; }
  need ffuf

  if [ ! -f "$FFUF_WORDLIST" ]; then
    warn "Wordlist missing: $FFUF_WORDLIST — set FFUF_WORDLIST in config.env"
    state_mark_done "fuzz"; return 0
  fi

  info "ffuf against $(count "$urls") target(s)…"
  while IFS= read -r url; do
    local safe; safe=$(echo "$url" | sed 's|[:/?#]|_|g')
    ffuf -u "${url}/FUZZ" -w "$FFUF_WORDLIST" -ac -t "$FFUF_THREADS" -s \
      -o "$dir/${safe}.json" -of json 2>>"$LOG_FILE" || true
  done < "$urls"
  ok "ffuf complete → $dir/"
  state_mark_done "fuzz"
}

# ── MODULE 8: Parameter Discovery ────────────────────────────
run_params() {
  state_is_done "params" && { info "Params: done (resume)"; return 0; }
  section "PARAMETER DISCOVERY"
  local dir="$OUT_DIR/params"
  local urls_file="$OUT_DIR/urls/urls.txt"
  local alive="$OUT_DIR/http/live_urls.txt"
  mkdir -p "$dir"

  if has arjun && nonempty "$alive"; then
    info "arjun…"
    run_tool arjun arjun -i "$alive" -oT "$dir/arjun.txt" --rate-limit 10 || true
    ok "arjun → $dir/arjun.txt"
  else
    warn "arjun unavailable — skipping active param discovery"
  fi

  if nonempty "$urls_file"; then
    info "Classifying params from URL archive…"
    grep '?' "$urls_file" | sort -u > "$dir/parameterized.txt" || true
    grep -iE '[?&](url|webhook|redirect_url|callback|fetch|load|src|dest|uri|endpoint|proxy|return_url|next|return|continue|service|host|target)=' \
      "$dir/parameterized.txt" > "$dir/ssrf_params.txt" 2>/dev/null || true
    grep -iE '[?&](redirect|redir|r|destination|dest|forward|location|goto|out|view|loginto|image_url|open)=' \
      "$dir/parameterized.txt" > "$dir/redirect_params.txt" 2>/dev/null || true
    grep -iE '[?&](id|user_id|uid|account_id|profile_id|order_id|invoice_id|ticket_id|customer_id|member_id)=' \
      "$dir/parameterized.txt" > "$dir/idor_params.txt" 2>/dev/null || true
    grep -iE '[?&](file|path|filename|page|template|doc|folder|root|include|require|view|content|pg|style)=' \
      "$dir/parameterized.txt" > "$dir/lfi_params.txt" 2>/dev/null || true

    ok "Parameterized URLs: $(count "$dir/parameterized.txt")"
    for kind in ssrf redirect idor lfi; do
      local n; n=$(count "$dir/${kind}_params.txt")
      [ "$n" -gt 0 ] && warn "${kind^^} candidates: $n → $dir/${kind}_params.txt"
    done
  fi
  state_mark_done "params"
}

# ── MODULE 9: Vulnerability Scanning ─────────────────────────
run_nuclei() {
  state_is_done "nuclei" && { info "Nuclei: done (resume)"; return 0; }
  section "VULNERABILITY SCANNING"
  local dir="$OUT_DIR/nuclei"
  local alive="$OUT_DIR/http/live_urls.txt"
  mkdir -p "$dir"
  nonempty "$alive" || { warn "No live URLs — run http first"; state_mark_done "nuclei"; return 0; }
  need nuclei

  info "nuclei full scan (low→critical)…"
  run_tool nuclei nuclei -l "$alive" -severity low,medium,high,critical -silent -o "$dir/nuclei.txt" || true
  info "nuclei — CVEs…"
  run_tool nuclei nuclei -l "$alive" -tags cves -silent -o "$dir/nuclei_cves.txt" || true
  info "nuclei — exposures…"
  run_tool nuclei nuclei -l "$alive" -tags exposures -silent -o "$dir/nuclei_exposures.txt" || true
  info "nuclei — misconfig…"
  run_tool nuclei nuclei -l "$alive" -tags misconfig -silent -o "$dir/nuclei_misconfig.txt" || true

  local total; total=$(cat "$dir"/nuclei*.txt 2>/dev/null | sort -u | awk 'END{print NR+0}')
  ok "Nuclei findings (unique): $total → $dir/"
  [ "$total" -gt 0 ] && warn "Review $dir/"
  state_mark_done "nuclei"
}

# ── MODULE 10: Google / GitHub Dorks ─────────────────────────
run_dorks() {
  state_is_done "dorks" && { info "Dorks: done (resume)"; return 0; }
  section "DORKS"
  local dir="$OUT_DIR/dorks"
  mkdir -p "$dir"
  local org="${DOMAIN%%.*}"

  cat > "$dir/google_dorks.txt" <<EOF
site:${TARGET_HOST} ext:log
site:${TARGET_HOST} ext:env
site:${TARGET_HOST} ext:xml inurl:config
site:${TARGET_HOST} filetype:sql
site:${TARGET_HOST} filetype:bak
site:${TARGET_HOST} inurl:admin
site:${TARGET_HOST} inurl:login
site:${TARGET_HOST} inurl:dashboard
site:${TARGET_HOST} inurl:swagger
site:${TARGET_HOST} inurl:graphql
site:${TARGET_HOST} "api_key"
site:${TARGET_HOST} intitle:"index of"
site:${TARGET_HOST} inurl:/.git/
site:${TARGET_HOST} "SQL syntax"
site:${TARGET_HOST} "stack trace"
site:${TARGET_HOST} inurl:api/v1
site:${TARGET_HOST} inurl:.env
site:${TARGET_HOST} inurl:config.json
site:${TARGET_HOST} inurl:phpinfo.php
site:${TARGET_HOST} intext:"internal server error"
EOF

  cat > "$dir/github_dorks.txt" <<EOF
org:${org} "api_key"
org:${org} filename:.env
org:${org} "aws_access_key_id"
org:${org} "DB_PASSWORD"
org:${org} "mongodb+srv"
"${TARGET_HOST}" password
"${TARGET_HOST}" "BEGIN RSA PRIVATE KEY"
"${TARGET_HOST}" internal api
EOF

  info "Google dorks → $dir/google_dorks.txt"
  info "GitHub dorks → $dir/github_dorks.txt (use manually in a browser)"
  state_mark_done "dorks"
}

# ── MODULE 11: Cloud Buckets ─────────────────────────────────
run_cloud() {
  state_is_done "cloud" && { info "Cloud: done (resume)"; return 0; }
  section "CLOUD BUCKET RECON"
  local dir="$OUT_DIR/cloud"
  mkdir -p "$dir"
  local company="${DOMAIN%%.*}"
  local suffixes=(dev prod staging backup data assets files internal logs temp
                  test media uploads static public private infra cdn storage config secrets)

  : > "$dir/bucket_names.txt"
  { for s in "${suffixes[@]}"; do
      echo "${company}-${s}"; echo "${s}-${company}"; echo "${company}${s}"
    done; echo "$company"; } | sort -u >> "$dir/bucket_names.txt"
  ok "Generated $(count "$dir/bucket_names.txt") bucket permutations"

  if has s3scanner; then
    info "s3scanner…"
    run_tool s3scanner s3scanner scan --bucket-file "$dir/bucket_names.txt" \
      --out-file "$dir/s3_results.txt" || true
    grep -iE '(open|public|listable)' "$dir/s3_results.txt" \
      > "$dir/open_buckets.txt" 2>/dev/null || true
    local n; n=$(count "$dir/open_buckets.txt")
    ok "Open/misconfigured buckets: $n"
    [ "$n" -gt 0 ] && warn "→ $dir/open_buckets.txt"
  else
    warn "s3scanner not found (pip install s3scanner) — names saved for manual check"
  fi
  state_mark_done "cloud"
}

# ── Report ───────────────────────────────────────────────────
run_report() {
  section "GENERATING REPORT"
  local dir="$OUT_DIR/report"
  mkdir -p "$dir"
  local report="$dir/report.txt"
  {
    echo "========================================"
    echo "  RECON REPORT: $TARGET_HOST"
    echo "  scope mode : $SCOPE_MODE"
    echo "  generated  : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================"
    echo ""
    echo "-- SUMMARY -----------------------------"
    printf "  %-22s %s\n" "In-scope hosts:"  "$(count "$OUT_DIR/subdomains/subs.txt")"
    printf "  %-22s %s\n" "Live URLs:"        "$(count "$OUT_DIR/http/live_urls.txt")"
    printf "  %-22s %s\n" "WAF detections:"   "$(count "$OUT_DIR/http/waf.txt")"
    printf "  %-22s %s\n" "Open ports:"       "$(count "$OUT_DIR/ports/ports.txt")"
    printf "  %-22s %s\n" "Total URLs:"       "$(count "$OUT_DIR/urls/urls.txt")"
    printf "  %-22s %s\n" "JS endpoints:"     "$(count "$OUT_DIR/js/endpoints.txt")"
    printf "  %-22s %s\n" "Secret hits:"      "$(count "$OUT_DIR/js/potential_secrets.txt")"
    printf "  %-22s %s\n" "Param URLs:"       "$(count "$OUT_DIR/params/parameterized.txt")"
    printf "  %-22s %s\n" "SSRF candidates:"  "$(count "$OUT_DIR/params/ssrf_params.txt")"
    printf "  %-22s %s\n" "Redirect cands:"   "$(count "$OUT_DIR/params/redirect_params.txt")"
    printf "  %-22s %s\n" "Nuclei findings:"  "$(cat "$OUT_DIR/nuclei"/nuclei*.txt 2>/dev/null | sort -u | awk 'END{print NR+0}')"
    echo ""

    _block() { [ "$(count "$2")" -gt 0 ] && { echo "-- $1"; head -"${3:-50}" "$2"; echo ""; }; }
    _block "WAF DETECTIONS"            "$OUT_DIR/http/waf.txt"
    _block "HIGH-RISK PORTS"           "$OUT_DIR/ports/high_interest.txt"
    _block "INTERESTING SERVICES"      "$OUT_DIR/http/interesting.txt"
    _block "SSRF CANDIDATES (top 20)"  "$OUT_DIR/params/ssrf_params.txt" 20
    _block "REDIRECT CANDIDATES (20)"  "$OUT_DIR/params/redirect_params.txt" 20
    _block "POTENTIAL SECRETS (20)"    "$OUT_DIR/js/potential_secrets.txt" 20

    echo "-- OUTPUT FILES ------------------------"
    find "$OUT_DIR" -type f \( -name '*.txt' -o -name '*.jsonl' -o -name '*.json' \) \
      | sort | sed "s|$OUT_DIR/||"
    echo ""
    echo "========================================"
  } | tee "$report"
  ok "Report → $report"
}

# ── Full pipeline ────────────────────────────────────────────
run_full() {
  section "FULL PIPELINE"
  local start=$SECONDS
  run_subdomains
  run_http_probe
  run_ports
  run_screenshots
  run_urls
  run_js
  run_fuzz
  run_params
  run_nuclei
  run_dorks
  run_cloud
  run_report
  ok "Pipeline complete in $(( SECONDS - start ))s → $OUT_DIR"
}

# ── Interactive menu ─────────────────────────────────────────
interactive_menu() {
  while true; do
    echo ""
    echo -e "  ${BOLD}Target:${RESET} ${GREEN}$TARGET_HOST${RESET}  ${BOLD}Mode:${RESET} ${MAGENTA}$SCOPE_MODE${RESET}"
    echo -e "  ${BOLD}Output:${RESET} ${CYAN}$OUT_DIR${RESET}"
    echo ""
    echo -e "  ${BOLD}[1]${RESET}  Subdomains / Seed     ${BOLD}[7]${RESET}  Directory Bruteforce"
    echo -e "  ${BOLD}[2]${RESET}  HTTP Probe + WAF      ${BOLD}[8]${RESET}  Parameter Discovery"
    echo -e "  ${BOLD}[3]${RESET}  Port Scanning         ${BOLD}[9]${RESET}  Vuln Scanning (nuclei)"
    echo -e "  ${BOLD}[4]${RESET}  Screenshots           ${BOLD}[10]${RESET} Dorks"
    echo -e "  ${BOLD}[5]${RESET}  URL Collection        ${BOLD}[11]${RESET} Cloud Buckets"
    echo -e "  ${BOLD}[6]${RESET}  JavaScript Recon      ${BOLD}[R]${RESET}  Report"
    echo -e "  ${BOLD}[F]${RESET}  Run Full Pipeline     ${BOLD}[Q]${RESET}  Quit"
    echo ""
    read -rp "$(echo -e "${BOLD}  > ${RESET}")" choice
    case "${choice^^}" in
      1) run_subdomains ;; 2) run_http_probe ;; 3) run_ports ;;
      4) run_screenshots ;; 5) run_urls ;; 6) run_js ;;
      7) run_fuzz ;; 8) run_params ;; 9) run_nuclei ;;
      10) run_dorks ;; 11) run_cloud ;; R) run_report ;;
      F) run_full ;; Q) ok "Results in $OUT_DIR"; exit 0 ;;
      *) warn "Invalid choice" ;;
    esac
  done
}

usage() {
  cat <<EOF

$(echo -e "${BOLD}Usage:${RESET}")
  ./tanya.sh <target> [options]

$(echo -e "${BOLD}Targets:${RESET}")
  example.com                         apex domain (subdomain enum ON)
  https://app.example.com/path        URL (scheme/path stripped)
  juice-shop.herokuapp.com            PaaS host (auto single-host mode)
  203.0.113.10                        IP (single-host mode)

$(echo -e "${BOLD}Options:${RESET}")
  --full              Run every module end-to-end
  --resume            Continue the most recent run for this target
  --module <name>     Run one module
  --single            Force single-host mode (skip subdomain enum)
  --apex              Force apex mode (do subdomain enum)
  --help              This help

$(echo -e "${BOLD}Modules:${RESET}")
  subdomains http ports screenshots urls js fuzz params nuclei dorks cloud report

EOF
  exit 0
}

# ── Entry point ──────────────────────────────────────────────
main() {
  banner
  [ $# -eq 0 ] && usage
  [[ "$1" == "--help" || "$1" == "-h" ]] && usage

  parse_target "$1"; shift

  # scope overrides
  local args=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --single) SCOPE_MODE="single" ;;
      --apex)   SCOPE_MODE="apex" ;;
      *) args+=("$1") ;;
    esac
    shift
  done
  set -- "${args[@]:-}"

  mkdir -p "$OUTPUT_BASE"
  local TS; TS=$(date +%Y%m%d_%H%M%S)
  OUT_DIR="$OUTPUT_BASE/${TARGET_HOST}_${TS}"

  if [[ "${1:-}" == "--resume" ]]; then
    local latest
    latest=$(ls -td "$OUTPUT_BASE/${TARGET_HOST}_"* 2>/dev/null | head -1 || true)
    if [ -n "$latest" ]; then OUT_DIR="$latest"; info "Resuming: $OUT_DIR"
    else warn "No previous run — starting fresh"; fi
    shift
  fi

  mkdir -p "$OUT_DIR"
  LOG_FILE="$OUT_DIR/recon.log"
  STATE_FILE="$OUT_DIR/.state"
  touch "$STATE_FILE" "$LOG_FILE"

  check_deps
  info "Target : $TARGET_HOST"
  info "Scope  : $DOMAIN  (mode: $SCOPE_MODE)"
  info "Output : $OUT_DIR"

  case "${1:-}" in
    --full) run_full ;;
    --module)
      [ -z "${2:-}" ] && die "Specify a module name"
      case "$2" in
        subdomains) run_subdomains ;; http) run_http_probe ;; ports) run_ports ;;
        screenshots) run_screenshots ;; urls) run_urls ;; js) run_js ;;
        fuzz) run_fuzz ;; params) run_params ;; nuclei) run_nuclei ;;
        dorks) run_dorks ;; cloud) run_cloud ;; report) run_report ;;
        *) die "Unknown module: $2" ;;
      esac ;;
    "") interactive_menu ;;
    *) die "Unknown option: $1 — use --help" ;;
  esac
}

main "$@"