#!/bin/bash
# ============================================================
#  recon.sh — Web Recon Pipeline
#  Usage: ./recon.sh [domain] [options]
# ============================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Config ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_BASE="$SCRIPT_DIR/output"
MODULES_DIR="$SCRIPT_DIR/modules"
CONFIG_FILE="$SCRIPT_DIR/config.env"

# Load config if it exists
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

TELEGRAM_TOKEN="${TELEGRAM_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# ── Helpers ──────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  cat << 'EOF'
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
         Web Recon Pipeline v1.0 by Oceanwarranty
EOF
  echo -e "${RESET}"
}

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
err()     { echo -e "${RED}[✗]${RESET} $*"; }
section() { echo -e "\n${BOLD}${YELLOW}━━━ $* ━━━${RESET}"; }

die() { err "$*"; exit 1; }

notify() {
  local msg="$1"
  if [[ -n "$TELEGRAM_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
      -d "chat_id=${TELEGRAM_CHAT_ID}" \
      -d "text=${msg}" \
      -d "parse_mode=Markdown" > /dev/null 2>&1 || true
  fi
}

check_tool() {
  command -v "$1" &>/dev/null
}

require_tool() {
  check_tool "$1" || die "Required tool '$1' not found. Run ./install.sh to install dependencies."
}

count_lines() {
  [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo "0"
}

# ── Module: Subdomain Enum ────────────────────────────────────
run_subdomains() {
  section "SUBDOMAIN ENUMERATION"
  local dir="$OUT_DIR/subdomains"
  mkdir -p "$dir"

  if check_tool subfinder; then
    info "Running subfinder..."
    subfinder -d "$DOMAIN" -all -recursive -silent -o "$dir/subfinder.txt" 2>/dev/null || true
    ok "subfinder: $(count_lines "$dir/subfinder.txt") results"
  else
    warn "subfinder not found, skipping"
  fi

  if check_tool amass; then
    info "Running amass (passive)..."
    timeout 120 amass enum -passive -d "$DOMAIN" -o "$dir/amass.txt" 2>/dev/null || true
    ok "amass: $(count_lines "$dir/amass.txt") results"
  else
    warn "amass not found, skipping"
  fi

  info "Querying crt.sh..."
  curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null \
    | grep -o '"name_value":"[^"]*"' \
    | cut -d'"' -f4 \
    | sed 's/\*\.//g' \
    | sort -u > "$dir/crtsh.txt" || true
  ok "crt.sh: $(count_lines "$dir/crtsh.txt") results"

  # Combine
  cat "$dir"/*.txt 2>/dev/null | sort -u > "$dir/all_subs.txt"
  local total
  total=$(count_lines "$dir/all_subs.txt")
  ok "Total unique subdomains: $total"

  # Resolve live
  if check_tool dnsx; then
    info "Resolving live subdomains..."
    cat "$dir/all_subs.txt" | dnsx -silent -resp -o "$dir/live_subs.txt" 2>/dev/null || true
    local live
    live=$(count_lines "$dir/live_subs.txt")
    ok "Live subdomains: $live"
    notify "📡 Subdomains done: $total found, $live live — $DOMAIN"
  else
    warn "dnsx not found — skipping DNS resolution"
    cp "$dir/all_subs.txt" "$dir/live_subs.txt"
  fi
}

# ── Module: HTTP Probe ────────────────────────────────────────
run_http_probe() {
  section "HTTP PROBING"
  local dir="$OUT_DIR/http"
  local subs="$OUT_DIR/subdomains/live_subs.txt"
  mkdir -p "$dir"

  [ -f "$subs" ] || { warn "No live subdomains found. Run subdomains first."; return; }

  require_tool httpx

  info "Probing HTTP services..."
  cat "$subs" | httpx \
    -title -tech-detect -status-code -content-length \
    -follow-redirects -silent \
    -o "$dir/httpx_results.txt" 2>/dev/null || true

  # Extract clean URLs
  awk '{print $1}' "$dir/httpx_results.txt" 2>/dev/null | sort -u > "$dir/live_urls.txt"
  local count
  count=$(count_lines "$dir/live_urls.txt")
  ok "Live HTTP services: $count"

  # Flag interesting tech
  grep -iE "jenkins|grafana|kibana|elastic|admin|dashboard|swagger|graphql" \
    "$dir/httpx_results.txt" > "$dir/interesting.txt" 2>/dev/null || true
  local interesting
  interesting=$(count_lines "$dir/interesting.txt")
  [ "$interesting" -gt 0 ] && warn "Interesting services found: $interesting (see http/interesting.txt)"

  notify "🌐 HTTP probe done: $count services — $DOMAIN"
}

# ── Module: Port Scan ─────────────────────────────────────────
run_ports() {
  section "PORT SCANNING"
  local dir="$OUT_DIR/ports"
  local subs="$OUT_DIR/subdomains/live_subs.txt"
  mkdir -p "$dir"

  [ -f "$subs" ] || { warn "No live subdomains found. Run subdomains first."; return; }

  if check_tool naabu; then
    info "Scanning common ports with naabu..."
    cat "$subs" | naabu \
      -p 21,22,80,443,2375,3000,4000,4848,5000,5900,6379,8080,8443,8888,9000,9200,9300,27017 \
      -silent -o "$dir/open_ports.txt" 2>/dev/null || true
    ok "Open ports found: $(count_lines "$dir/open_ports.txt")"

    # Flag high-interest ports
    grep -E ":3000|:4848|:6379|:9200|:9300|:27017|:2375|:5900" \
      "$dir/open_ports.txt" > "$dir/high_interest.txt" 2>/dev/null || true
    local hi
    hi=$(count_lines "$dir/high_interest.txt")
    [ "$hi" -gt 0 ] && warn "High-interest ports: $hi (Redis/Elastic/MongoDB/Docker?)"
    notify "🔍 Port scan done: $(count_lines "$dir/open_ports.txt") open ports — $DOMAIN"
  else
    warn "naabu not found, falling back to nc checks on common ports..."
    while IFS= read -r host; do
      for port in 80 443 8080 8443 3000 6379 9200 27017; do
        nc -z -w 1 "$host" "$port" 2>/dev/null && echo "${host}:${port}" >> "$dir/open_ports.txt" || true
      done
    done < "$subs"
    ok "Open ports found: $(count_lines "$dir/open_ports.txt")"
  fi
}

# ── Module: JS Mining ─────────────────────────────────────────
run_js() {
  section "JAVASCRIPT MINING"
  local dir="$OUT_DIR/js"
  mkdir -p "$dir/files"

  if check_tool gau; then
    info "Collecting JS URLs via gau..."
    gau "$DOMAIN" --threads 5 --blacklist png,jpg,gif,svg,css,woff,ttf,ico 2>/dev/null \
      | grep -E "\.js(\?|$)" | sort -u > "$dir/js_urls.txt" || true
  fi

  if check_tool katana; then
    info "Crawling with katana for JS..."
    katana -u "https://$DOMAIN" -jc -d 3 -silent 2>/dev/null \
      | grep -E "\.js(\?|$)" >> "$dir/js_urls.txt" || true
  fi

  if [ ! -f "$dir/js_urls.txt" ] || [ "$(count_lines "$dir/js_urls.txt")" -eq 0 ]; then
    warn "No JS URL tools available (gau/katana). Skipping JS mining."
    return
  fi

  sort -u "$dir/js_urls.txt" -o "$dir/js_urls.txt"
  local js_count
  js_count=$(count_lines "$dir/js_urls.txt")
  info "Found $js_count JS files. Downloading..."

  # Download JS files
  while IFS= read -r url; do
    local fn
    fn=$(echo "$url" | md5sum 2>/dev/null | cut -d' ' -f1 || echo "$RANDOM")
    curl -sk --max-time 10 "$url" -o "$dir/files/${fn}.js" 2>/dev/null || true
  done < "$dir/js_urls.txt"

  # Secret patterns grep
  info "Scanning for secrets..."
  grep -rihE \
    "(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|aws_access|private_key|password\s*=|db_pass)" \
    "$dir/files/" 2>/dev/null \
    | grep -v "//.*key" \
    | sort -u > "$dir/potential_secrets.txt" || true

  # Endpoint patterns
  grep -rihEo "(https?://[^\"\' ]+|/api/[^\"\' ]+|/v[0-9]+/[^\"\' ]+)" \
    "$dir/files/" 2>/dev/null \
    | sort -u > "$dir/endpoints.txt" || true

  ok "JS files: $js_count | Endpoints: $(count_lines "$dir/endpoints.txt") | Secrets: $(count_lines "$dir/potential_secrets.txt")"
  notify "📄 JS mining done: $(count_lines "$dir/potential_secrets.txt") potential secrets — $DOMAIN"
}

# ── Module: Parameter Discovery ───────────────────────────────
run_params() {
  section "PARAMETER DISCOVERY"
  local dir="$OUT_DIR/params"
  mkdir -p "$dir"

  if check_tool gau; then
    info "Mining URLs from archives..."
    gau "$DOMAIN" --threads 5 \
      --blacklist png,jpg,gif,svg,css,woff,ttf,ico,mp4,mp3 2>/dev/null \
      | sort -u > "$dir/all_urls.txt" || true
  elif check_tool waybackurls; then
    waybackurls "$DOMAIN" 2>/dev/null | sort -u > "$dir/all_urls.txt" || true
  else
    warn "Neither gau nor waybackurls found. Skipping."
    return
  fi

  ok "Total historical URLs: $(count_lines "$dir/all_urls.txt")"

  # Filter parameterized
  grep "?" "$dir/all_urls.txt" | sort -u > "$dir/parameterized.txt" 2>/dev/null || true

  # Filter juicy params
  grep -iE "(id=|user=|uid=|redirect=|url=|next=|file=|path=|include=|load=|fetch=|read=|page=|callback=|return=|dest=|redir=|token=|api_key=|ref=)" \
    "$dir/parameterized.txt" | sort -u > "$dir/juicy_params.txt" 2>/dev/null || true

  ok "Parameterized URLs: $(count_lines "$dir/parameterized.txt")"
  ok "Juicy params (SSRF/redirect/IDOR candidates): $(count_lines "$dir/juicy_params.txt")"
  notify "🔗 Param discovery done: $(count_lines "$dir/juicy_params.txt") juicy params — $DOMAIN"
}

# ── Module: Google Dorks ──────────────────────────────────────
run_dorks() {
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
EOF

  ok "Generated ${BOLD}$(count_lines "$dir/dorks.txt")${RESET} dorks → $dir/dorks.txt"
  info "Open these in your browser or use a Google Dorking tool:"
  echo ""
  while IFS= read -r dork; do
    echo -e "  ${CYAN}→${RESET} ${dork}"
  done < "$dir/dorks.txt"
  echo ""
}

# ── Module: Cloud Buckets ─────────────────────────────────────
run_cloud() {
  section "CLOUD BUCKET RECON"
  local dir="$OUT_DIR/cloud"
  mkdir -p "$dir"

  local company
  company=$(echo "$DOMAIN" | cut -d'.' -f1)

  info "Generating bucket name permutations for: $company"
  python3 - << EOF > "$dir/bucket_names.txt"
company = "$company"
suffixes = ["dev","prod","staging","backup","data","assets","files",
            "internal","logs","temp","test","media","uploads","static",
            "public","private","infra","cdn","storage"]
prefixes = ["","aws-","s3-","cdn-","app-"]
names = set()
for p in prefixes:
    for s in suffixes:
        names.add(f"{p}{company}-{s}")
        names.add(f"{p}{company}.{s}")
        names.add(f"{p}{s}-{company}")
    names.add(f"{p}{company}")
for n in sorted(names):
    print(n)
EOF

  ok "Generated $(count_lines "$dir/bucket_names.txt") bucket name permutations"

  if check_tool s3scanner; then
    info "Scanning buckets with s3scanner..."
    s3scanner scan --bucket-file "$dir/bucket_names.txt" \
      --out-file "$dir/s3_results.txt" 2>/dev/null || true
    grep -i "open\|public\|accessible" "$dir/s3_results.txt" \
      > "$dir/open_buckets.txt" 2>/dev/null || true
    ok "Open/misconfigured buckets: $(count_lines "$dir/open_buckets.txt")"
  else
    warn "s3scanner not found. Check buckets manually:"
    info "Install: pip install s3scanner"
    info "Or check manually: aws s3 ls s3://BUCKET_NAME"
    info "Bucket list saved to: $dir/bucket_names.txt"
  fi
}

# ── Module: Screenshots ───────────────────────────────────────
run_screenshots() {
  section "SCREENSHOTS"
  local urls="$OUT_DIR/http/live_urls.txt"
  local dir="$OUT_DIR/screenshots"
  mkdir -p "$dir"

  [ -f "$urls" ] || { warn "No live URLs found. Run http_probe first."; return; }

  if check_tool gowitness; then
    info "Taking screenshots with gowitness..."
    gowitness file -f "$urls" \
      --delay 2 --threads 8 \
      --screenshot-path "$dir/" 2>/dev/null || true
    ok "Screenshots saved to $dir/"
    check_tool gowitness && gowitness report generate --db-location gowitness.sqlite 2>/dev/null || true
  elif check_tool eyewitness; then
    info "Taking screenshots with eyewitness..."
    eyewitness --web -f "$urls" --timeout 10 --threads 8 -d "$dir/" 2>/dev/null || true
    ok "Screenshots saved to $dir/"
  else
    warn "No screenshot tool found (gowitness/eyewitness). Skipping."
    info "Install: go install github.com/sensepost/gowitness@latest"
  fi
}

# ── Full Pipeline ─────────────────────────────────────────────
run_full() {
  section "FULL PIPELINE"
  notify "🚀 Full recon started for \`$DOMAIN\`"
  local start=$SECONDS

  run_subdomains
  run_http_probe
  run_ports
  run_js
  run_params
  run_dorks
  run_cloud

  local elapsed=$(( SECONDS - start ))
  local summary="
✅ Recon complete for $DOMAIN (${elapsed}s)
• Subdomains: $(count_lines "$OUT_DIR/subdomains/live_subs.txt") live
• HTTP: $(count_lines "$OUT_DIR/http/live_urls.txt") services
• Ports: $(count_lines "$OUT_DIR/ports/open_ports.txt") open
• JS secrets: $(count_lines "$OUT_DIR/js/potential_secrets.txt")
• Juicy params: $(count_lines "$OUT_DIR/params/juicy_params.txt")
• Results: $OUT_DIR"

  section "SUMMARY"
  echo -e "$summary"
  notify "$summary"
}

# ── Interactive Menu ──────────────────────────────────────────
interactive_menu() {
  while true; do
    echo ""
    echo -e "${BOLD}Target: ${GREEN}$DOMAIN${RESET}  |  Output: ${CYAN}$OUT_DIR${RESET}"
    echo ""
    echo -e "  ${BOLD}[1]${RESET} Subdomain Enumeration"
    echo -e "  ${BOLD}[2]${RESET} HTTP Probing"
    echo -e "  ${BOLD}[3]${RESET} Port Scanning"
    echo -e "  ${BOLD}[4]${RESET} JavaScript Mining"
    echo -e "  ${BOLD}[5]${RESET} Parameter Discovery"
    echo -e "  ${BOLD}[6]${RESET} Google Dorks"
    echo -e "  ${BOLD}[7]${RESET} Cloud Bucket Recon"
    echo -e "  ${BOLD}[8]${RESET} Screenshots"
    echo -e "  ${BOLD}[9]${RESET} 🚀 Run Full Pipeline"
    echo -e "  ${BOLD}[0]${RESET} Exit"
    echo ""
    read -rp "$(echo -e "${BOLD}Select module:${RESET} ")" choice

    case "$choice" in
      1) run_subdomains ;;
      2) run_http_probe ;;
      3) run_ports ;;
      4) run_js ;;
      5) run_params ;;
      6) run_dorks ;;
      7) run_cloud ;;
      8) run_screenshots ;;
      9) run_full ;;
      0) ok "Done. Results in $OUT_DIR"; exit 0 ;;
      *) warn "Invalid choice" ;;
    esac
  done
}

# ── Usage ─────────────────────────────────────────────────────
usage() {
  echo -e "
${BOLD}Usage:${RESET}
  ./recon.sh <domain>                     Interactive menu
  ./recon.sh <domain> --full              Run full pipeline
  ./recon.sh <domain> --module <name>     Run specific module

${BOLD}Modules:${RESET}
  subdomains, http, ports, js, params, dorks, cloud, screenshots

${BOLD}Examples:${RESET}
  ./recon.sh example.com
  ./recon.sh example.com --full
  ./recon.sh example.com --module js
  ./recon.sh example.com --module subdomains

${BOLD}Config (optional):${RESET}
  Edit config.env to set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID for alerts.
"
  exit 0
}

# ── Entry Point ───────────────────────────────────────────────
main() {
  banner

  [ $# -eq 0 ] && usage

  DOMAIN="${1,,}"  # lowercase
  DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"
  [ -z "$DOMAIN" ] && die "Invalid domain"

  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  OUT_DIR="$OUTPUT_BASE/${DOMAIN}_${TIMESTAMP}"
  mkdir -p "$OUT_DIR"

  info "Target: $DOMAIN"
  info "Output: $OUT_DIR"

  shift
  case "${1:-}" in
    --full)           run_full ;;
    --module)
      [ -z "${2:-}" ] && die "Specify a module name"
      case "$2" in
        subdomains)  run_subdomains ;;
        http)        run_http_probe ;;
        ports)       run_ports ;;
        js)          run_js ;;
        params)      run_params ;;
        dorks)       run_dorks ;;
        cloud)       run_cloud ;;
        screenshots) run_screenshots ;;
        *)           die "Unknown module: $2" ;;
      esac
      ;;
    --help|-h)        usage ;;
    "")               interactive_menu ;;
    *)                die "Unknown option: $1. Use --help for usage." ;;
  esac
}

main "$@"
