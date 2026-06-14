#!/usr/bin/env bash
# ============================================================
#  tanya.sh — Web Recon Pipeline v5.5 (txt/jsonl, no DB)
#
#  v5.5 changes:
#    · WSL-aware: report + completion box now print Windows-accessible
#      paths (\\wsl.localhost\...) and a clickable file:// URL so you can
#      open the HTML report straight from a Windows browser/Explorer.
#    · edge anti-bot / challenge detection (Cloudflare "Just a moment",
#      Akamai, Imperva/Incapsula, DataDome, PerimeterX, AWS WAF, generic
#      CAPTCHA gates). Challenged hosts are split out so they don't poison
#      the main nuclei/fuzz/crawl passes; clean hosts are scanned normally.
#    · nuclei is now CDN-aware: it scans the directly-reachable ("clean")
#      URLs + any CONFIRMED ORIGIN IPs (real backend, edge bypassed), with a
#      realistic browser UA and polite rate limits so it trips fewer WAFs.
#      Challenged hosts get a separate slow best-effort pass.
#    · clean log file: ANSI colour codes are stripped from recon.log.
#    · hardier modules: missing recommended tools now skip gracefully
#      instead of killing the whole run; LC_ALL=C for stable sort/grep.
#
#  v5.4 changes:
#    · empty output files are pruned automatically (no more 0-byte clutter)
#    · report now has a prioritized "WHERE TO START" triage + module status
#    · proper enclosed UI boxes (auto-width, ANSI-aware) for run/summary
#    · interactive menu shows checkmarks for already-completed modules
#    · fixed a grep -c double-count bug in the nuclei severity tally
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
export LC_ALL=C LANG=C    # deterministic sort/grep, ASCII-safe (domains are ASCII)

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BLUE='\033[0;34m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

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

# Realistic browser UA — used for edge-challenge detection and the gentle
# nuclei pass over challenged hosts (helps a few checks land where a recon UA
# would be blocked outright). Not an evasion tool; just looks like a browser.
BROWSER_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# nuclei tuning — keep it polite so we don't trip rate limits / get banned.
NUCLEI_RATE=150       # max requests/sec (-rl)
NUCLEI_CONC=25        # template concurrency (-c)
NUCLEI_RETRIES=1
NUCLEI_TIMEOUT=10
CHALLENGE_THREADS=15  # parallelism for edge-challenge detection

# Optional API keys for origin discovery (set in config.env). Left blank = skipped.
SECURITYTRAILS_API_KEY="${SECURITYTRAILS_API_KEY:-}"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"

# Quiet mode — when true, noisy active modules are skipped (set via --passive).
PASSIVE=false

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
# Render colour to the terminal, but write a clean (ANSI-stripped) copy to the
# log file so recon.log stays grep-friendly and email-safe.
_log() {
  local rendered; rendered=$(echo -e "$*")
  printf '%s\n' "$rendered"
  if [ -n "${LOG_FILE:-}" ]; then
    printf '%s\n' "$rendered" | sed -E $'s/\x1b\\[[0-9;]*m//g' >> "$LOG_FILE"
  fi
}
info()    { _log "${DIM}  ·${RESET} $*"; }
ok()      { _log "  ${GREEN}✓${RESET} $*"; }
warn()    { _log "  ${YELLOW}!${RESET} $*"; }
err()     { _log "  ${RED}✗${RESET} $*"; }
section() {
  if [ "${STEP_TOTAL:-0}" -gt 0 ]; then
    STEP_N=$(( STEP_N + 1 ))
    _log "\n${BOLD}${BLUE}[${STEP_N}/${STEP_TOTAL}]${RESET} ${BOLD}${CYAN}$*${RESET}"
  else
    _log "\n${BOLD}${CYAN}▆▆▆${RESET} ${BOLD}$*${RESET}"
  fi
}
die()     { err "$*"; exit 1; }

# Pipeline progress state (set by run_full)
STEP_N=0; STEP_TOTAL=0

banner() {
  _log ""
  _log "${CYAN}  ████████╗ █████╗ ███╗   ██╗██╗   ██╗ █████╗${RESET}"
  _log "${CYAN}     ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝██╔══██╗${RESET}    ${DIM}_._     _,-'\"\"\`-._${RESET}"
  _log "${CYAN}     ██║   ███████║██╔██╗ ██║ ╚████╔╝ ███████║${RESET}   ${DIM}(,-.\`._,'(       |\\\`-/|${RESET}"
  _log "${CYAN}     ██║   ██╔══██║██║╚██╗██║  ╚██╔╝  ██╔══██║${RESET}        ${DIM}\`-.-' \\ )-\`( , o o)${RESET}"
  _log "${CYAN}     ██║   ██║  ██║██║ ╚████║   ██║   ██║  ██║${RESET}             ${DIM}\`-    \\\`_\`\"'-${RESET}"
  _log "${CYAN}     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝${RESET}"
  _log "        ${BOLD}Web Recon Pipeline${RESET} ${GREEN}v5.5${RESET}  ${DIM}— authorized targets only${RESET}"
  _log ""
}

# ── Helpers ──────────────────────────────────────────────────
has()   { command -v "$1" >/dev/null 2>&1; }
need()  { has "$1" || die "'$1' not found — install it first"; }

# Robust line count (handles files with no trailing newline)
count() { if [ -f "$1" ]; then awk 'END{print NR+0}' "$1" 2>/dev/null; else echo 0; fi; }

# Non-empty file?
nonempty() { [ -s "$1" ]; }

# Best URL list for active scanning: prefer the edge-"clean" list produced by
# classify_challenges (hosts NOT sitting behind an active anti-bot challenge),
# falling back to the full live list when classification didn't run or found
# nothing to drop. Echoes a path; empty string if neither exists.
scan_url_list() {
  local clean="$OUT_DIR/http/clean_urls.txt"
  local live="$OUT_DIR/http/live_urls.txt"
  if nonempty "$clean"; then printf '%s' "$clean"
  elif nonempty "$live"; then printf '%s' "$live"
  else printf ''; fi
}

# ── WSL awareness ────────────────────────────────────────────
# When running under WSL, Linux paths like /home/you/... aren't directly
# usable from a Windows browser/Explorer. These helpers translate to the
# Windows form (\\wsl.localhost\Distro\...) and a file:// URL.
is_wsl() {
  [ -n "${WSL_DISTRO_NAME:-}" ] && return 0
  grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null
}
# Linux path -> Windows path (best effort; echoes input back if it can't).
win_path() {
  if has wslpath; then wslpath -w "$1" 2>/dev/null || printf '%s' "$1"
  else printf '%s' "$1"; fi
}
# Linux path -> file:// URL openable from a Windows browser.
win_file_url() {
  local w; w=$(win_path "$1"); w=${w//\\//}     # backslashes -> forward slashes
  if [[ "$w" == //* ]]; then printf 'file://%s' "${w#//}"   # UNC: \\wsl.localhost\..
  else printf 'file:///%s' "$w"; fi                          # drive: C:\..
}

# Visible length of a string, ignoring our literal \033[...m color codes.
# (Color vars hold the *text* "\033[..m"; echo -e renders them, so we strip
#  that literal pattern to measure how wide the line will actually print.)
_vlen() {
  local s
  s=$(printf '%s' "$1" | sed -E 's/\\033\[[0-9;]*m//g')
  printf '%s' "${#s}"
}

# Draw a fully-enclosed, auto-width box around a title + body lines.
# Usage: box "<COLOR>" "TITLE" "line1" "line2" ...
# Width adapts to the widest visible line; ANSI color codes don't break it.
box() {
  local color="$1"; shift
  local title="$1"; shift
  local lines=("$@") l vl maxw=0
  vl=$(_vlen "$title"); (( vl > maxw )) && maxw=$vl
  for l in "${lines[@]}"; do vl=$(_vlen "$l"); (( vl > maxw )) && maxw=$vl; done
  local innerw=$(( maxw + 4 ))                 # 2-space pad on each side
  local bar; bar=$(printf '═%.0s' $(seq 1 "$innerw"))
  local thin; thin=$(printf '─%.0s' $(seq 1 "$innerw"))
  _log "${color}╔${bar}╗${RESET}"
  vl=$(_vlen "$title")
  _log "$(printf "${color}║${RESET}  %b%*s${color}║${RESET}" "$title" "$(( innerw - 2 - vl ))" "")"
  if [ "${#lines[@]}" -gt 0 ]; then
    _log "${color}╟${thin}╢${RESET}"
    for l in "${lines[@]}"; do
      vl=$(_vlen "$l"); local rpad=$(( innerw - 2 - vl )); (( rpad < 0 )) && rpad=0
      _log "$(printf "${color}║${RESET}  %b%*s${color}║${RESET}" "$l" "$rpad" "")"
    done
  fi
  _log "${color}╚${bar}╝${RESET}"
}

# Delete zero-byte output files (and now-empty dirs) so the run dir only
# contains files that actually have findings. Protects the log + state file.
prune_empty() {
  local root="${1:-$OUT_DIR}"
  [ -d "$root" ] || return 0
  find "$root" -type f -empty ! -name 'recon.log' ! -name '.state' -delete 2>/dev/null || true
  find "$root" -mindepth 1 -type d -empty -delete 2>/dev/null || true
}

# Status glyph for the interactive menu: ✓ if a module already ran this run.
_mk() { state_is_done "$1" 2>/dev/null && printf "${GREEN}✓${RESET}" || printf "${DIM}·${RESET}"; }

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

# Harvest hostnames from ANY tool output. We EXTRACT FQDNs from each line
# rather than requiring the whole line to be a clean host — this is what lets
# us recover names from verbose formats (e.g. amass graph lines like
# "www.example.com (FQDN) --> a_record --> 1.2.3.4"). IPs/ASNs/netblocks are
# naturally excluded because the regex requires a trailing alpha TLD.
normalize_hosts() {
  tr '[:upper:]' '[:lower:]' \
    | sed -E 's#https?://##g' \
    | grep -oE '([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,}' \
    | sed -E 's/^\*\.//; s/\.$//' \
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
  local optional=(assetfinder amass waybackurls gau \
                  arjun trufflehog gitleaks s3scanner \
                  dnsx dig cdncheck host nslookup nc)
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
  has httpx || { warn "httpx not installed — cannot probe HTTP, skipping"; state_mark_done "http"; return 0; }
  need jq

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

  # Split live hosts into clean vs edge-challenged (Cloudflare/Akamai/etc.)
  classify_challenges

  state_mark_done "http"
}

# ── Edge anti-bot / challenge detection ──────────────────────
# Detects challenge interstitials served by a CDN/WAF EDGE — Cloudflare
# "Just a moment…", Akamai, Imperva/Incapsula, DataDome, PerimeterX, AWS WAF,
# and generic CAPTCHA gates. This is *detection + routing*, NOT a bypass: hosts
# behind an active challenge are flagged so the operator knows that scanning the
# edge is noisy/useless and that the real target is the ORIGIN (run_origin) or
# authenticated/manual testing. Downstream modules (nuclei/fuzz/crawl) then use
# the "clean" list so they don't waste requests or trip rate limits.
classify_challenges() {
  local dir="$OUT_DIR/http"
  local live="$dir/live_urls.txt"
  nonempty "$live" || return 0
  has curl || { warn "curl missing — skipping challenge detection"; cp "$live" "$dir/clean_urls.txt" 2>/dev/null; return 0; }

  info "Edge challenge / anti-bot detection on $(count "$live") URL(s)…"
  local detail="$dir/challenge_detail.txt"; : > "$detail"

  export BROWSER_UA
  # one bounded request per URL; capture status + headers + a small body slice,
  # then signature-match. Parallel + short timeouts keep this fast.
  cat "$live" | xargs -P "$CHALLENGE_THREADS" -I{} bash -c '
    url="$1"
    td=$(mktemp -d) || exit 0
    code=$(curl -sk -A "$BROWSER_UA" --compressed --max-time 8 \
                -o "$td/b" -D "$td/h" -w "%{http_code}" "$url" 2>/dev/null) || code=000
    blob=$(cat "$td/h" 2>/dev/null; head -c 60000 "$td/b" 2>/dev/null)
    rm -rf "$td"
    low=$(printf "%s" "$blob" | tr "[:upper:]" "[:lower:]")
    vendor="na"; verdict="clean"
    if printf "%s" "$low" | grep -qE "cf-mitigated: ?challenge|just a moment|challenge-platform|cdn-cgi/challenge|challenges\.cloudflare\.com|__cf_chl|cf_chl_|enable javascript and cookies to continue"; then
      vendor="cloudflare"; verdict="challenge"
    elif printf "%s" "$low" | grep -qE "x-iinfo|incap_ses|incapsula|_incapsula_|imperva"; then
      vendor="imperva"; verdict="challenge"
    elif printf "%s" "$low" | grep -qE "x-datadome|datadome"; then
      vendor="datadome"; verdict="challenge"
    elif printf "%s" "$low" | grep -qE "px-captcha|_pxhd|perimeterx|human challenge"; then
      vendor="perimeterx"; verdict="challenge"
    elif printf "%s" "$low" | grep -qE "awswafintegration|token\.awswaf|aws-waf-token"; then
      vendor="awswaf"; verdict="challenge"
    elif printf "%s" "$low" | grep -qE "akamaighost" && printf "%s" "$low" | grep -qE "access denied|reference #[0-9a-f]"; then
      vendor="akamai"; verdict="challenge"
    elif [ "$code" = "403" ] || [ "$code" = "429" ] || [ "$code" = "503" ]; then
      if printf "%s" "$low" | grep -qE "captcha|are you (a )?human|verify you are (a )?human|attention required|bot detection|access denied"; then
        vendor="generic"; verdict="challenge"
      fi
    fi
    printf "%s\t%s\t%s\t%s\n" "$url" "$code" "$verdict" "$vendor"
  ' _ {} >> "$detail" 2>/dev/null || true

  awk -F"\t" '$3=="challenge"{print $1}' "$detail" 2>/dev/null | sort -u > "$dir/challenged.txt"
  if nonempty "$dir/challenged.txt"; then
    grep -vxFf "$dir/challenged.txt" "$live" | sort -u > "$dir/clean_urls.txt"
  else
    cp "$live" "$dir/clean_urls.txt"
  fi

  local ch; ch=$(count "$dir/challenged.txt")
  if [ "$ch" -gt 0 ]; then
    local vlist
    vlist=$(awk -F"\t" '$3=="challenge"{print $4}' "$detail" 2>/dev/null \
            | sort | uniq -c | sort -rn | awk '{printf "%s(%s) ", $2,$1}')
    warn "$ch host(s) behind an active edge challenge → $dir/challenged.txt"
    warn "  vendors: ${vlist:-n/a}"
    warn "  edge scanning these is noisy/blocked — prefer the ORIGIN (origin module) or authenticated/manual testing."
    ok   "Directly-scannable (clean) URLs: $(count "$dir/clean_urls.txt") → $dir/clean_urls.txt"
  else
    ok "No edge challenges detected — all $(count "$dir/clean_urls.txt") live URL(s) directly scannable"
  fi
}

# ── MODULE 2b: Origin Discovery (CDN/WAF bypass) ─────────────
# Goal: when the target hides behind a CDN (Cloudflare/Akamai/etc.), find the
# real backend IP so later scanning hits the origin instead of the edge.
# Method (all standard, mostly key-free):
#   1. Resolve every in-scope host (+ MX hosts) to IPs.
#   2. Pull historical/passive IPs (SecurityTrails, Shodan) if API keys are set.
#   3. Classify each IP as CDN-edge vs non-CDN. Non-CDN IPs are origin candidates.
#   4. Verify candidates: request the site directly on the candidate IP using the
#      real Host/SNI (curl --resolve) and compare the response to the live baseline.
run_origin() {
  state_is_done "origin" && { info "Origin: done (resume)"; return 0; }
  section "ORIGIN DISCOVERY (CDN BYPASS)"
  local dir="$OUT_DIR/origin"
  local subs="$OUT_DIR/subdomains/subs.txt"
  mkdir -p "$dir"
  nonempty "$subs" || { warn "No hosts — run subdomains first"; state_mark_done "origin"; return 0; }
  need curl; need jq; need python3

  local all="$dir/all_ips.txt"; : > "$all"

  # 1. Resolve in-scope hosts → IPs (dnsx if present, else getent)
  info "Resolving $(count "$subs") host(s) to IPs…"
  if has dnsx; then
    dnsx -l "$subs" -a -resp-only -silent 2>>"$LOG_FILE" | sort -u >> "$all" || true
  else
    while IFS= read -r h; do
      getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}'
    done < "$subs" | sort -u >> "$all"
  fi

  # 2. MX hosts often run on the origin / same hosting — resolve them too
  info "Checking MX records…"
  local mx_hosts
  if has dig; then
    mx_hosts=$(dig +short MX "$DOMAIN" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//')
  elif has host; then
    mx_hosts=$(host -t MX "$DOMAIN" 2>/dev/null | awk '/mail is handled/{print $NF}' | sed 's/\.$//')
  fi
  if [ -n "${mx_hosts:-}" ]; then
    echo "$mx_hosts" > "$dir/mx_hosts.txt"
    while IFS= read -r mh; do
      [ -z "$mh" ] && continue
      getent ahostsv4 "$mh" 2>/dev/null | awk '{print $1}'
    done <<< "$mx_hosts" >> "$all"
  fi

  # 3. Optional passive history sources (need API keys; silently skip if absent)
  if [ -n "$SECURITYTRAILS_API_KEY" ]; then
    info "SecurityTrails historical A records…"
    curl -s --max-time 30 \
      "https://api.securitytrails.com/v1/history/${DOMAIN}/dns/a?apikey=${SECURITYTRAILS_API_KEY}" \
      2>>"$LOG_FILE" \
      | jq -r '.records[]?.values[]?.ip' 2>/dev/null >> "$all" || warn "SecurityTrails query failed"
  fi
  if [ -n "$SHODAN_API_KEY" ]; then
    info "Shodan DNS records…"
    curl -s --max-time 30 \
      "https://api.shodan.io/dns/domain/${DOMAIN}?key=${SHODAN_API_KEY}" \
      2>>"$LOG_FILE" \
      | jq -r '.data[]? | select(.type=="A") | .value' 2>/dev/null >> "$all" || warn "Shodan query failed"
  fi

  sort -u -o "$all" "$all"
  local ip_total; ip_total=$(count "$all")
  if [ "$ip_total" -eq 0 ]; then
    warn "No IPs resolved — skipping origin discovery"
    state_mark_done "origin"; return 0
  fi
  ok "Collected $ip_total unique IP(s) → $all"

  # 4. Classify CDN vs non-CDN. cdncheck (ProjectDiscovery) is most accurate;
  #    otherwise a built-in IP-in-CIDR test against major CDN ranges.
  info "Classifying CDN edge vs origin candidates…"
  python3 - "$all" "$dir/cdn_ips.txt" "$dir/origin_candidates.txt" <<'PYEOF'
import sys, ipaddress
# Major CDN / reverse-proxy edge ranges. Cloudflare is exhaustive (most common);
# others are representative. Anything NOT in here is treated as an origin candidate.
CDN_NETS = [
  # Cloudflare IPv4 (official)
  "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
  "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
  "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
  "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
  # Fastly (subset)
  "151.101.0.0/16","199.232.0.0/16",
  # Sucuri
  "192.88.134.0/23","185.93.228.0/22","66.248.200.0/22",
  # Incapsula / Imperva (subset)
  "199.83.128.0/21","198.143.32.0/19","149.126.72.0/21","45.60.0.0/16",
]
nets = [ipaddress.ip_network(c) for c in CDN_NETS]
cdn, origin = [], []
for line in open(sys.argv[1]):
    ip = line.strip()
    if not ip: continue
    try: a = ipaddress.ip_address(ip)
    except ValueError: continue
    (cdn if any(a in n for n in nets) else origin).append(ip)
open(sys.argv[2],"w").write("\n".join(sorted(set(cdn))))
open(sys.argv[3],"w").write("\n".join(sorted(set(origin))))
PYEOF

  # Bonus: if cdncheck exists, also subtract anything it flags as CDN/WAF/cloud
  if has cdncheck; then
    cdncheck -i "$dir/origin_candidates.txt" -silent 2>>"$LOG_FILE" > "$dir/_cdncheck_hits.txt" || true
    if nonempty "$dir/_cdncheck_hits.txt"; then
      grep -vxFf "$dir/_cdncheck_hits.txt" "$dir/origin_candidates.txt" \
        > "$dir/_oc.tmp" 2>/dev/null && mv "$dir/_oc.tmp" "$dir/origin_candidates.txt" || true
      cat "$dir/_cdncheck_hits.txt" >> "$dir/cdn_ips.txt"
      sort -u -o "$dir/cdn_ips.txt" "$dir/cdn_ips.txt"
    fi
    rm -f "$dir/_cdncheck_hits.txt"
  fi

  local cdn_n cand_n
  cdn_n=$(count "$dir/cdn_ips.txt"); cand_n=$(count "$dir/origin_candidates.txt")
  ok "CDN edge IPs: $cdn_n | origin candidates: $cand_n"
  if [ "$cdn_n" -gt 0 ] && [ "$cand_n" -eq 0 ]; then
    warn "Target is fully behind a CDN and no direct-origin IP leaked — that's good hygiene on their side."
  fi
  [ "$cand_n" -eq 0 ] && { state_mark_done "origin"; return 0; }

  if [ "$PASSIVE" = true ]; then
    info "Passive mode — skipping active origin verification ($cand_n candidates saved)"
    state_mark_done "origin"; return 0
  fi

  # 5. Verify candidates: hit the IP directly with the real Host/SNI and compare
  #    to the live baseline (title first, content-length as fallback signal).
  info "Verifying $cand_n candidate(s) against live baseline…"
  local bhost="$TARGET_HOST" btitle="" blen=""
  if [ -f "$OUT_DIR/http/alive.jsonl" ]; then
    btitle=$(jq -r --arg h "$bhost" 'select((.input // "")==$h or ((.url // "")|test($h;"i"))) | .title // ""' \
             "$OUT_DIR/http/alive.jsonl" 2>/dev/null | head -1)
    blen=$(jq -r --arg h "$bhost" 'select((.input // "")==$h or ((.url // "")|test($h;"i"))) | .content_length // ""' \
             "$OUT_DIR/http/alive.jsonl" 2>/dev/null | head -1)
  fi
  if [ -z "$btitle" ]; then
    btitle=$(curl -sk --max-time 15 -A "$CURL_UA" "https://$bhost/" 2>/dev/null \
             | grep -oiE '<title>[^<]*' | head -1 | sed -E 's/<title>//I')
  fi
  info "  baseline title: ${btitle:-<none>}"

  : > "$dir/confirmed_origins.txt"
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    for scheme in https http; do
      local port=443; [ "$scheme" = http ] && port=80
      local body title
      body=$(curl -sk --max-time 10 -A "$CURL_UA" \
               --resolve "$bhost:$port:$ip" "$scheme://$bhost/" 2>/dev/null) || continue
      [ -z "$body" ] && continue
      title=$(printf '%s' "$body" | grep -oiE '<title>[^<]*' | head -1 | sed -E 's/<title>//I')
      if [ -n "$btitle" ] && [ "$title" = "$btitle" ]; then
        echo "$ip  [$scheme]  CONFIRMED (title match): $title" >> "$dir/confirmed_origins.txt"
        echo "$ip" >> "$dir/origins.txt"
        break
      elif [ -n "$blen" ] && [ "${#body}" -gt 0 ]; then
        local diff=$(( ${#body} - blen )); diff=${diff#-}
        if [ "$diff" -lt 512 ]; then
          echo "$ip  [$scheme]  likely (size ~match): len=${#body} vs baseline=$blen" >> "$dir/confirmed_origins.txt"
          echo "$ip" >> "$dir/origins.txt"
          break
        fi
      fi
    done
  done < "$dir/origin_candidates.txt"

  [ -f "$dir/origins.txt" ] && sort -u -o "$dir/origins.txt" "$dir/origins.txt"
  local conf_n; conf_n=$(count "$dir/confirmed_origins.txt")
  if [ "$conf_n" -gt 0 ]; then
    warn "Possible ORIGIN IP(s) found → $dir/confirmed_origins.txt"
    warn "Later modules will also scan these directly (bypassing the CDN)."
  else
    ok "No origin confirmed (candidates saved for manual review → $dir/origin_candidates.txt)"
  fi
  state_mark_done "origin"
}

# ── MODULE 3: Port Scanning ──────────────────────────────────
run_ports() {
  state_is_done "ports" && { info "Ports: done (resume)"; return 0; }
  [ "$PASSIVE" = true ] && { section "PORT SCANNING"; info "skipped (passive mode)"; state_mark_done "ports"; return 0; }
  section "PORT SCANNING"
  local dir="$OUT_DIR/ports"
  local subs="$OUT_DIR/subdomains/subs.txt"
  mkdir -p "$dir"
  nonempty "$subs" || { warn "No hosts — run subdomains first"; return 0; }

  # Build the scan target list: in-scope hosts + any confirmed origin IPs,
  # so we hit the real backend rather than only the CDN edge.
  local targets="$dir/scan_targets.txt"
  cp "$subs" "$targets"
  if [ -s "$OUT_DIR/origin/origins.txt" ]; then
    cat "$OUT_DIR/origin/origins.txt" >> "$targets"
    info "Including $(count "$OUT_DIR/origin/origins.txt") confirmed origin IP(s) in scan"
  fi
  sort -u -o "$targets" "$targets"

  if has naabu; then
    info "naabu top-1000 ports…"
    retry 2 naabu -list "$targets" -top-ports 1000 -rate "$NAABU_RATE" \
      -c "$NAABU_THREADS" -silent -o "$dir/ports.txt" \
      || warn "naabu had issues — partial results possible"
  else
    warn "naabu not found — nc fallback (slow, top ports only)"
    : > "$dir/ports.txt"
    while IFS= read -r host; do
      for p in 80 443 8080 8443 3000 5000 6379 9200 27017 2375 10250 9000; do
        nc -z -w 2 "$host" "$p" 2>/dev/null && echo "${host}:${p}" >> "$dir/ports.txt"
      done
    done < "$targets"
  fi

  grep -E ':(2375|2376|6379|9200|9300|27017|28017|10250|4848|5900|7001|8888|9090|2379|5601)$' \
    "$dir/ports.txt" > "$dir/high_interest.txt" 2>/dev/null || true

  ok "Open ports: $(count "$dir/ports.txt") → $dir/ports.txt"
  [ "$(count "$dir/high_interest.txt")" -gt 0 ] && \
    warn "High-risk ports → $dir/high_interest.txt"
  state_mark_done "ports"
}

# ── MODULE 5: URL Collection ─────────────────────────────────
run_urls() {
  state_is_done "urls" && { info "URLs: done (resume)"; return 0; }
  section "URL COLLECTION"
  local dir="$OUT_DIR/urls"
  local alive; alive="$(scan_url_list)"
  mkdir -p "$dir"
  touch "$dir/katana.txt" "$dir/wayback.txt" "$dir/gau.txt"

  if has katana && nonempty "$alive" && [ "$PASSIVE" != true ]; then
    info "katana crawl (depth $KATANA_DEPTH)…"
    run_tool katana katana -list "$alive" -jc -d "$KATANA_DEPTH" -silent \
      -H "User-Agent: $BROWSER_UA" -rl "$NUCLEI_RATE" \
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
  [ "$PASSIVE" = true ] && { section "DIRECTORY BRUTEFORCE"; info "skipped (passive mode)"; state_mark_done "fuzz"; return 0; }
  section "DIRECTORY BRUTEFORCE"
  local dir="$OUT_DIR/fuzz"
  local urls; urls="$(scan_url_list)"
  mkdir -p "$dir"
  nonempty "$urls" || { warn "No live URLs — run http first"; state_mark_done "fuzz"; return 0; }
  has ffuf || { warn "ffuf not installed — skipping directory bruteforce"; state_mark_done "fuzz"; return 0; }

  if [ ! -f "$FFUF_WORDLIST" ]; then
    warn "Wordlist missing: $FFUF_WORDLIST — set FFUF_WORDLIST in config.env"
    state_mark_done "fuzz"; return 0
  fi

  info "ffuf against $(count "$urls") target(s)…"
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local safe; safe=$(echo "$url" | sed 's|[:/?#]|_|g')
    ffuf -u "${url}/FUZZ" -w "$FFUF_WORDLIST" -ac -t "$FFUF_THREADS" -s \
      -H "User-Agent: $BROWSER_UA" -rate "$NUCLEI_RATE" \
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
  local alive; alive="$(scan_url_list)"
  mkdir -p "$dir"

  if has arjun && nonempty "$alive" && [ "$PASSIVE" != true ]; then
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
  [ "$PASSIVE" = true ] && { section "VULNERABILITY SCANNING"; info "skipped (passive mode)"; state_mark_done "nuclei"; return 0; }
  section "VULNERABILITY SCANNING"
  local dir="$OUT_DIR/nuclei"
  mkdir -p "$dir"
  has nuclei || { warn "nuclei not installed — skipping vuln scan"; state_mark_done "nuclei"; return 0; }

  # ── Target selection ───────────────────────────────────────
  # Primary target = the edge-"clean" URL list (hosts NOT behind an active
  # anti-bot challenge) + any CONFIRMED origin IPs. Scanning the Cloudflare/
  # DataDome/etc. edge of a challenged host just burns requests on a JS/CAPTCHA
  # interstitial and trips rate limits, so those go through a separate, gentle
  # pass below instead.
  local primary="$dir/_targets.txt"; : > "$primary"
  local base; base="$(scan_url_list)"
  [ -n "$base" ] && cat "$base" >> "$primary"

  # Add confirmed origins (scheme-prefixed) so we hit the real backend directly.
  if [ -s "$OUT_DIR/origin/origins.txt" ]; then
    while IFS= read -r oip; do
      [ -z "$oip" ] && continue
      printf 'https://%s\nhttp://%s\n' "$oip" "$oip"
    done < "$OUT_DIR/origin/origins.txt" >> "$primary"
    info "Including $(count "$OUT_DIR/origin/origins.txt") confirmed origin IP(s) (direct, CDN-bypassed)"
  fi
  sort -u -o "$primary" "$primary"

  local challenged="$OUT_DIR/http/challenged.txt"
  if [ ! -s "$primary" ] && [ ! -s "$challenged" ]; then
    warn "No live URLs — run http first"; rm -f "$primary"; state_mark_done "nuclei"; return 0
  fi

  # Templates must be present or scans fail with "no templates provided".
  info "Syncing nuclei templates…"
  nuclei -update-templates -silent >>"$LOG_FILE" 2>&1 \
    || warn "template sync failed — continuing with whatever is installed"

  # ── Polite/robust flags shared by every pass ───────────────
  # Real-browser UA (some edges block the default nuclei UA outright), bounded
  # rate + concurrency, a retry, a per-request timeout, and -no-stdin so the
  # tool never blocks waiting on a TTY inside the pipeline.
  local common=( -H "User-Agent: $BROWSER_UA"
                 -rl "$NUCLEI_RATE" -c "$NUCLEI_CONC"
                 -retries "$NUCLEI_RETRIES" -timeout "$NUCLEI_TIMEOUT"
                 -no-stdin -silent )

  local raw="$dir/_raw.txt"; : > "$raw"

  if [ -s "$primary" ]; then
    info "nuclei — severity scan (low→critical) on $(count "$primary") target(s)…"
    run_tool nuclei nuclei -l "$primary" -severity low,medium,high,critical \
      "${common[@]}" -o "$dir/_sev.txt" && cat "$dir/_sev.txt" >> "$raw" 2>/dev/null || true

    info "nuclei — exposures + misconfig…"
    run_tool nuclei nuclei -l "$primary" -tags exposures,misconfig \
      "${common[@]}" -o "$dir/_exp.txt" && cat "$dir/_exp.txt" >> "$raw" 2>/dev/null || true
  fi

  # ── Gentle pass over edge-challenged hosts ─────────────────
  # We still look — but slowly and quietly. A challenge interstitial usually
  # blocks template matches, yet some findings (TLS, headers, info disclosures
  # served before the JS gate) still land. Heavily reduced rate/concurrency so
  # we don't hammer an edge that's already rate-limiting us.
  if [ -s "$challenged" ]; then
    info "nuclei — gentle pass on $(count "$challenged") edge-challenged host(s) (reduced rate)…"
    run_tool nuclei nuclei -l "$challenged" -severity medium,high,critical \
      -H "User-Agent: $BROWSER_UA" -rl 20 -c 5 \
      -retries "$NUCLEI_RETRIES" -timeout "$NUCLEI_TIMEOUT" -no-stdin -silent \
      -o "$dir/_chl.txt" && cat "$dir/_chl.txt" >> "$raw" 2>/dev/null || true
    warn "challenged hosts scanned gently — edge anti-bot may suppress results; prefer origin/manual."
  fi

  # Single authoritative, de-duplicated findings file
  sort -u "$raw" > "$dir/findings.txt" 2>/dev/null || : > "$dir/findings.txt"
  rm -f "$dir/_raw.txt" "$dir/_sev.txt" "$dir/_exp.txt" "$dir/_chl.txt" "$primary"

  # Categorize from the deduped source (no re-scanning, no duplicate lines)
  grep -iE 'CVE-[0-9]{4}-[0-9]+'                  "$dir/findings.txt" > "$dir/cves.txt"        2>/dev/null || true
  grep -iE 'exposure|exposed|disclosure|\.git|\.env|backup|listing' \
                                                  "$dir/findings.txt" > "$dir/exposures.txt"   2>/dev/null || true
  grep -iE 'misconfig|missing-security|security-headers|cors|default-' \
                                                  "$dir/findings.txt" > "$dir/misconfig.txt"   2>/dev/null || true

  local total crit high med low cve_n
  total=$(count "$dir/findings.txt")
  crit=$(grep -c '\[critical\]' "$dir/findings.txt" 2>/dev/null) || crit=0
  high=$(grep -c '\[high\]'     "$dir/findings.txt" 2>/dev/null) || high=0
  med=$(grep -c  '\[medium\]'   "$dir/findings.txt" 2>/dev/null) || med=0
  low=$(grep -c  '\[low\]'      "$dir/findings.txt" 2>/dev/null) || low=0
  cve_n=$(count "$dir/cves.txt")

  ok "Nuclei: $total unique finding(s) → $dir/findings.txt"
  _log "      ${RED}critical:$crit${RESET}  ${MAGENTA}high:$high${RESET}  ${YELLOW}medium:$med${RESET}  ${CYAN}low:$low${RESET}  ${BOLD}CVEs:$cve_n${RESET}"
  { [ "$crit" -gt 0 ] || [ "$high" -gt 0 ] || [ "$cve_n" -gt 0 ]; } && warn "High-signal findings present — review $dir/findings.txt"
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
    info "s3scanner (Go CLI)…"
    # Go s3scanner: single-dash flags, NO 'scan' subcommand, results go to stdout.
    s3scanner -bucket-file "$dir/bucket_names.txt" -threads 8 \
      > "$dir/s3_results.txt" 2>>"$LOG_FILE" || true

    # Each printed line is an existing bucket; "AllUsers" => publicly accessible.
    grep -iE 'allusers' "$dir/s3_results.txt" > "$dir/open_buckets.txt" 2>/dev/null || true

    local exist_n open_n
    exist_n=$(count "$dir/s3_results.txt")
    open_n=$(count "$dir/open_buckets.txt")
    ok "Buckets found: $exist_n | publicly exposed: $open_n → $dir/s3_results.txt"
    [ "$open_n" -gt 0 ] && warn "Public buckets → $dir/open_buckets.txt"
  else
    warn "s3scanner not found (go install github.com/sa7mon/s3scanner@latest) — names saved for manual check"
  fi
  state_mark_done "cloud"
}

# ── MODULE 12: Interactive HTML Report ───────────────────────
run_html_report() {
  section "INTERACTIVE HTML REPORT"
  local gen="$SCRIPT_DIR/tanya_report.py"
  [ -f "$gen" ] || { warn "tanya_report.py not found beside tanya.sh — skipping"; return 0; }
  need python3
  local out="$OUT_DIR/report/report.html"
  local pass=(); [ "$PASSIVE" = true ] && pass=(--passive)
  # On WSL, hand the generator the Windows-side path so the report can show a
  # path/URL that actually opens from a Windows browser or Explorer.
  local winargs=()
  if is_wsl; then winargs=(--win-dir "$(win_path "$OUT_DIR")"); fi
  if python3 "$gen" "$OUT_DIR" --target "$TARGET_HOST" --scope "$SCOPE_MODE" \
       "${pass[@]}" "${winargs[@]}" --out "$out" >>"$LOG_FILE" 2>&1; then
    ok "Interactive report → $out"
    if is_wsl; then
      local furl; furl="$(win_file_url "$out")"
      info "open in Windows browser: ${CYAN}${furl}${RESET}"
      info "or in Explorer: ${CYAN}$(win_path "$OUT_DIR/report")${RESET}"
    else
      info "open it in a browser: file://$out"
    fi
  else
    warn "HTML report generation failed (see log)"
  fi
}

_MULTI_SUFFIXES=" co.uk org.uk gov.uk ac.uk com.au net.au org.au com.br \
co.nz com.mx co.jp co.in co.za com.sg com.tr co.id com.cn "
registrable_apex() {
  local h="$1"; is_ip "$h" && { echo "$h"; return; }
  local labels n; IFS='.' read -ra labels <<< "$h"; n=${#labels[@]}
  (( n <= 2 )) && { echo "$h"; return; }
  local last2="${labels[n-2]}.${labels[n-1]}"
  if [[ " $_MULTI_SUFFIXES " == *" $last2 "* ]]; then echo "${labels[n-3]}.${last2}"
  else echo "$last2"; fi
}

# ── Report ───────────────────────────────────────────────────
run_report() {
  prune_empty "$OUT_DIR"            # clean 0-byte files before we list anything
  section "GENERATING REPORT"
  local dir="$OUT_DIR/report"
  mkdir -p "$dir"
  local report="$dir/report.txt"

  # ---- gather counts once ----
  local subs live waf chlng orig_c orig openb sec intsvc hiport
  subs=$(count "$OUT_DIR/subdomains/subs.txt")
  live=$(count "$OUT_DIR/http/live_urls.txt")
  waf=$(count "$OUT_DIR/http/waf.txt")
  chlng=$(count "$OUT_DIR/http/challenged.txt")
  orig_c=$(count "$OUT_DIR/origin/origin_candidates.txt")
  orig=$(count "$OUT_DIR/origin/origins.txt")
  openb=$(count "$OUT_DIR/cloud/open_buckets.txt")
  sec=$(count "$OUT_DIR/js/potential_secrets.txt")
  intsvc=$(count "$OUT_DIR/http/interesting.txt")
  hiport=$(count "$OUT_DIR/ports/high_interest.txt")

  local cve nfind ncrit nhigh
  cve=$(count "$OUT_DIR/nuclei/cves.txt")
  nfind=$(count "$OUT_DIR/nuclei/findings.txt")
  ncrit=0; nhigh=0
  if [ -f "$OUT_DIR/nuclei/findings.txt" ]; then
    ncrit=$(grep -c '\[critical\]' "$OUT_DIR/nuclei/findings.txt" 2>/dev/null) || ncrit=0
    nhigh=$(grep -c '\[high\]'     "$OUT_DIR/nuclei/findings.txt" 2>/dev/null) || nhigh=0
  fi

  local ssrf redir idor lfi intfiles
  ssrf=$(count "$OUT_DIR/params/ssrf_params.txt")
  redir=$(count "$OUT_DIR/params/redirect_params.txt")
  idor=$(count "$OUT_DIR/params/idor_params.txt")
  lfi=$(count "$OUT_DIR/params/lfi_params.txt")
  intfiles=$(count "$OUT_DIR/urls/interesting_files.txt")

  # ---- build prioritized triage list (tab-separated: GLYPH \t TEXT \t REL_PATH) ----
  local -a TRIAGE=()
  _t() { [ "${1:-0}" -gt 0 ] && TRIAGE+=("$2"$'\t'"$3"$'\t'"$4") || true; }
  _t "$ncrit"   "[!!!]" "$ncrit CRITICAL nuclei finding(s)"          "nuclei/findings.txt"
  _t "$openb"   "[!!!]" "$openb PUBLICLY exposed cloud bucket(s)"    "cloud/open_buckets.txt"
  _t "$nhigh"   "[!! ]" "$nhigh HIGH nuclei finding(s)"             "nuclei/findings.txt"
  _t "$cve"     "[!! ]" "$cve CVE match(es)"                        "nuclei/cves.txt"
  _t "$sec"     "[!! ]" "$sec potential secret(s) in JS"            "js/potential_secrets.txt"
  _t "$orig"    "[!  ]" "$orig confirmed ORIGIN IP(s) (CDN bypass)" "origin/confirmed_origins.txt"
  _t "$intsvc"  "[!  ]" "$intsvc interesting service(s) exposed"    "http/interesting.txt"
  _t "$hiport"  "[!  ]" "$hiport high-risk open port(s)"            "ports/high_interest.txt"
  _t "$ssrf"    "[ ? ]" "$ssrf SSRF param candidate(s)"             "params/ssrf_params.txt"
  _t "$idor"    "[ ? ]" "$idor IDOR param candidate(s)"             "params/idor_params.txt"
  _t "$lfi"     "[ ? ]" "$lfi LFI param candidate(s)"              "params/lfi_params.txt"
  _t "$redir"   "[ ? ]" "$redir open-redirect candidate(s)"        "params/redirect_params.txt"
  _t "$intfiles" "[ ? ]" "$intfiles interesting file URL(s)"       "urls/interesting_files.txt"

  # ---- module run status from .state ----
  local order=(subdomains http origin ports urls js fuzz params nuclei dorks cloud)

  {
    echo "════════════════════════════════════════════════════════"
    echo "  RECON REPORT — $TARGET_HOST"
    echo "  scope mode : $SCOPE_MODE$([ "$PASSIVE" = true ] && echo '  (passive)')"
    echo "  generated  : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  output dir : $OUT_DIR"
    if is_wsl; then
      echo "  windows dir: $(win_path "$OUT_DIR")"
      echo "  report url : $(win_file_url "$dir/report.html")"
    fi
    echo "════════════════════════════════════════════════════════"
    echo ""

    echo "── MODULE STATUS ───────────────────────────────────────"
    local m line=""
    for m in "${order[@]}"; do
      if state_is_done "$m"; then line+="  [x] $m"; else line+="  [ ] $m"; fi
    done
    echo "$line"
    echo ""

    echo "── WHERE TO START (highest signal first) ───────────────"
    if [ "${#TRIAGE[@]}" -eq 0 ]; then
      echo "  No high-signal findings were flagged automatically."
      echo "  Good manual starting points:"
      [ "$live" -gt 0 ]     && echo "    → http/alive.txt            (every live service + title/tech)"
      [ "$(count "$OUT_DIR/urls/urls.txt")" -gt 0 ] && \
                              echo "    → urls/urls.txt             (full URL archive)"
      [ "$(count "$OUT_DIR/params/parameterized.txt")" -gt 0 ] && \
                              echo "    → params/parameterized.txt  (URLs carrying parameters)"
      [ "$(count "$OUT_DIR/dorks/google_dorks.txt")" -gt 0 ] && \
                              echo "    → dorks/google_dorks.txt    (paste into a browser)"
    else
      local g txt p
      while IFS=$'\t' read -r g txt p; do
        printf "  %-5s %-46s → %s\n" "$g" "$txt" "$OUT_DIR/$p"
      done < <(printf '%s\n' "${TRIAGE[@]}")
      echo ""
      echo "  legend:  [!!!] critical / act now   [!! ] high   [!  ] notable   [ ? ] candidate to test"
    fi
    echo ""

    echo "── SUMMARY ─────────────────────────────────────────────"
    printf "  %-22s %s\n" "In-scope hosts:"   "$subs"
    printf "  %-22s %s\n" "Live URLs:"         "$live"
    printf "  %-22s %s\n" "WAF detections:"    "$waf"
    printf "  %-22s %s\n" "Edge-challenged:"   "$chlng"
    printf "  %-22s %s\n" "Origin candidates:" "$orig_c"
    printf "  %-22s %s\n" "Confirmed origins:" "$orig"
    printf "  %-22s %s\n" "Open ports:"        "$(count "$OUT_DIR/ports/ports.txt")"
    printf "  %-22s %s\n" "Total URLs:"        "$(count "$OUT_DIR/urls/urls.txt")"
    printf "  %-22s %s\n" "JS endpoints:"      "$(count "$OUT_DIR/js/endpoints.txt")"
    printf "  %-22s %s\n" "Secret hits:"       "$sec"
    printf "  %-22s %s\n" "Param URLs:"        "$(count "$OUT_DIR/params/parameterized.txt")"
    printf "  %-22s %s\n" "Public buckets:"    "$openb"
    printf "  %-22s %s\n" "Nuclei findings:"   "$nfind"
    printf "  %-22s %s\n" "  └ critical/high:" "$ncrit / $nhigh"
    echo ""

    _block() { [ "$(count "$2")" -gt 0 ] && { echo "── $1"; head -"${3:-50}" "$2"; echo ""; }; }
    _block "WAF DETECTIONS"            "$OUT_DIR/http/waf.txt"
    _block "EDGE-CHALLENGED HOSTS (anti-bot — prefer origin/manual)" \
                                       "$OUT_DIR/http/challenged.txt"
    _block "CONFIRMED ORIGIN IPs"      "$OUT_DIR/origin/confirmed_origins.txt"
    _block "PUBLIC CLOUD BUCKETS"      "$OUT_DIR/cloud/open_buckets.txt"
    _block "HIGH-RISK PORTS"           "$OUT_DIR/ports/high_interest.txt"
    _block "INTERESTING SERVICES"      "$OUT_DIR/http/interesting.txt"
    _block "SSRF CANDIDATES (top 20)"  "$OUT_DIR/params/ssrf_params.txt" 20
    _block "REDIRECT CANDIDATES (20)"  "$OUT_DIR/params/redirect_params.txt" 20
    _block "POTENTIAL SECRETS (20)"    "$OUT_DIR/js/potential_secrets.txt" 20

    echo "── OUTPUT FILES (non-empty only) ───────────────────────"
    find "$OUT_DIR" -type f \( -name '*.txt' -o -name '*.jsonl' -o -name '*.json' \) \
      | sort
    echo ""
    echo "════════════════════════════════════════════════════════"
  } > "$report"

  cat "$report"
  ok "Report → $report"
}

# ── Full pipeline ────────────────────────────────────────────
run_full() {
  local start=$SECONDS
  STEP_TOTAL=12; STEP_N=0           # enables [n/12] progress in section()
  run_subdomains
  run_http_probe
  run_origin
  run_ports
  run_urls
  run_js
  run_fuzz
  run_params
  run_nuclei
  run_dorks
  run_cloud
  run_report
  run_html_report  
  STEP_TOTAL=0
  prune_empty "$OUT_DIR"            # final sweep of any 0-byte files
  local elapsed=$(( SECONDS - start ))
  local mm=$(( elapsed / 60 )) ss=$(( elapsed % 60 ))

  # Completion box with headline numbers
  local subs live nucl orig chlng
  subs=$(count "$OUT_DIR/subdomains/subs.txt")
  live=$(count "$OUT_DIR/http/live_urls.txt")
  orig=$(count "$OUT_DIR/origin/origins.txt")
  nucl=$(count "$OUT_DIR/nuclei/findings.txt")
  chlng=$(count "$OUT_DIR/http/challenged.txt")
  echo ""
  local -a boxlines=(
    "hosts ${BOLD}$subs${RESET}   live ${BOLD}$live${RESET}   challenged ${BOLD}$chlng${RESET}   origins ${BOLD}$orig${RESET}   nuclei ${BOLD}$nucl${RESET}"
    "elapsed ${BOLD}${mm}m ${ss}s${RESET}"
    "report  ${CYAN}$OUT_DIR/report/report.txt${RESET}"
  )
  if is_wsl; then
    boxlines+=( "html    ${CYAN}$(win_file_url "$OUT_DIR/report/report.html")${RESET}" )
  fi
  box "$GREEN" "${BOLD}${GREEN}SCAN COMPLETE${RESET}  ${DIM}$TARGET_HOST${RESET}" "${boxlines[@]}"
  _log "  ${DIM}→ open the report above — it lists where to start.${RESET}"
}

# ── Interactive menu ─────────────────────────────────────────
interactive_menu() {
  while true; do
    local pmode="${SCOPE_MODE}"; [ "$PASSIVE" = true ] && pmode="${SCOPE_MODE} · passive"
    echo ""
    box "$DIM" "${BOLD}target${RESET} ${GREEN}$TARGET_HOST${RESET}   ${BOLD}mode${RESET} ${MAGENTA}${pmode}${RESET}"
    echo ""
    echo -e "   ${CYAN}RECON${RESET}                              ${CYAN}CONTENT${RESET}"
    echo -e "   $(_mk subdomains) ${BOLD}1${RESET}  Subdomain Enumeration    $(_mk urls)   ${BOLD}5${RESET}  URL Collection"
    echo -e "   $(_mk http) ${BOLD}2${RESET}  HTTP Probe + WAF         $(_mk js)   ${BOLD}6${RESET}  JavaScript Recon"
    echo -e "   $(_mk origin) ${BOLD}3${RESET}  Origin Discovery         $(_mk fuzz)   ${BOLD}7${RESET}  Directory Bruteforce"
    echo -e "   $(_mk ports) ${BOLD}4${RESET}  Port Scanning            $(_mk params)   ${BOLD}8${RESET}  Parameter Discovery"
    echo ""
    echo -e "   ${CYAN}VULN / OSINT${RESET}                       ${CYAN}ACTIONS${RESET}"
    echo -e "   $(_mk nuclei) ${BOLD}9${RESET}  Vulnerability Scan       ${BOLD}F${RESET}  ${GREEN}Run Full Pipeline${RESET}"
    echo -e "   $(_mk dorks) ${BOLD}10${RESET} Google / GitHub Dorks    ${BOLD}R${RESET}  Generate Report"
    echo -e "   $(_mk cloud) ${BOLD}11${RESET} Cloud Bucket Recon       ${BOLD}Q${RESET}  Quit"
    echo ""
    echo -e "   ${DIM}✓ = already run this session${RESET}"
    echo ""
    read -rp "$(echo -e "  ${BOLD}tanya${RESET} ${GREEN}>${RESET} ")" choice
    echo ""
    case "${choice^^}" in
      1) run_subdomains ;; 2) run_http_probe ;; 3) run_origin ;; 4) run_ports ;;
      5) run_urls ;; 6) run_js ;; 7) run_fuzz ;; 8) run_params ;;
      9) run_nuclei ;; 10) run_dorks ;; 11) run_cloud ;;
      R) run_report ;; H) run_html_report ;;
      F) run_full ;; Q) prune_empty "$OUT_DIR"; ok "Results in $OUT_DIR"; exit 0 ;;
      *) warn "Invalid choice"; continue ;;
    esac
    prune_empty "$OUT_DIR"          # tidy 0-byte files after every action
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
  --passive           Quiet mode: skip noisy active scans
                      (ports, fuzz, nuclei, crawling, origin verification)
  --help              This help

$(echo -e "${BOLD}Modules:${RESET}")
  subdomains http origin ports urls js fuzz params nuclei dorks cloud report

EOF
  exit 0
}

# ── Entry point ──────────────────────────────────────────────
main() {
  [ -t 1 ] && clear 2>/dev/null || true
  banner
  [ $# -eq 0 ] && usage
  [[ "$1" == "--help" || "$1" == "-h" ]] && usage

  parse_target "$1"; shift

  # scope overrides
  local args=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --single) SCOPE_MODE="single" ;;
      --apex)   SCOPE_MODE="apex"; DOMAIN="$(registrable_apex "$TARGET_HOST")"
                [ "$DOMAIN" != "$TARGET_HOST" ] && info "Apex scope: $DOMAIN" ;;
      --passive) PASSIVE=true ;;
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
  trap 'echo; warn "Interrupted — pruning + saving state"; prune_empty "$OUT_DIR" 2>/dev/null; exit 130' INT TERM
  touch "$STATE_FILE" "$LOG_FILE"

  check_deps
  local -a runlines=(
    "target  ${GREEN}$TARGET_HOST${RESET}"
    "scope   $DOMAIN ${DIM}(mode: $SCOPE_MODE$([ "$PASSIVE" = true ] && echo ', passive'))${RESET}"
    "output  ${CYAN}$OUT_DIR${RESET}"
  )
  if is_wsl; then
    runlines+=( "windir  ${CYAN}$(win_path "$OUT_DIR")${RESET}  ${DIM}(WSL)${RESET}" )
  fi
  box "$DIM" "${BOLD}RUN${RESET}" "${runlines[@]}"

  case "${1:-}" in
    --full) run_full ;;
    --module)
      [ -z "${2:-}" ] && die "Specify a module name"
      case "$2" in
        subdomains) run_subdomains ;; http) run_http_probe ;; origin) run_origin ;; ports) run_ports ;;
        urls) run_urls ;; js) run_js ;;
        fuzz) run_fuzz ;; params) run_params ;; nuclei) run_nuclei ;;
        dorks) run_dorks ;; cloud) run_cloud ;; report) run_report ;;
        html) run_html_report ;;     
        *) die "Unknown module: $2" ;;
      esac
      prune_empty "$OUT_DIR" ;;
    "") interactive_menu ;;
    *) die "Unknown option: $1 — use --help" ;;
  esac
}

main "$@"