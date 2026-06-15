#!/usr/bin/env bash
# ================================================================
#  install.sh  —  dependency installer for tanya.sh  v6.1
#
#  Tiers:
#    core         curl  jq  python3  pip(rich)          (always)
#    recommended  subfinder httpx naabu nuclei katana ffuf cdncheck
#    optional     assetfinder amass waybackurls gau hakrawler arjun
#                 dnsx subzy dalfox gf chaos puredns
#                 trufflehog gitleaks s3scanner
#                 + system: host / nslookup (dnsutils)  nc (netcat)
#                 + openssl (headers/graphql/ssl modules)
#
#  Usage:
#    ./install.sh                core + recommended
#    ./install.sh --optional     + optional tools
#    ./install.sh --seclists     + clone SecLists → ~/SecLists
#    ./install.sh --all          recommended + optional + seclists
#    ./install.sh --minimal      core only
#    ./install.sh --help
#
#  Package managers: apt / dnf / pacman / brew
#  Go tools:        go install  (toolchain auto-installed if absent)
# ================================================================
set -uo pipefail

# ── Colors ───────────────────────────────────────────────────────
if [ -t 1 ]; then
  C=$'\033[1;36m'; G=$'\033[0;32m'; Y=$'\033[1;33m'
  R=$'\033[0;31m'; D=$'\033[2m';    B=$'\033[1m';    Z=$'\033[0m'
else
  C=''; G=''; Y=''; R=''; D=''; B=''; Z=''
fi

_hdr()  { printf '\n%s◆  %s%s\n' "$C" "$*" "$Z"; }
_hr()   { printf '%s%s%s\n' "$D" "$(printf '─%.0s' $(seq 1 60))" "$Z"; }
_ok()   { printf '  %s✓%s  %s\n' "$G" "$Z" "$*"; }
_warn() { printf '  %s⚠%s  %s\n' "$Y" "$Z" "$*"; }
_err()  { printf '  %s✘%s  %s\n' "$R" "$Z" "$*" >&2; }
_info() { printf '  %s·%s  %s\n' "$D" "$Z" "$*"; }

has() { command -v "$1" >/dev/null 2>&1; }

# ── Flags ────────────────────────────────────────────────────────
DO_RECOMMENDED=true
DO_OPTIONAL=false
DO_SECLISTS=false

for _a in "$@"; do
  case "$_a" in
    --minimal)  DO_RECOMMENDED=false ;;
    --optional) DO_OPTIONAL=true ;;
    --seclists) DO_SECLISTS=true ;;
    --all)      DO_OPTIONAL=true; DO_SECLISTS=true ;;
    --help|-h)
      cat <<'HELP'

install.sh  —  tanya.sh dependency installer  v6.1

Tiers:
  core         curl  jq  python3  rich(pip)              (always)
  recommended  subfinder httpx naabu nuclei katana ffuf cdncheck
  optional     assetfinder amass waybackurls gau hakrawler arjun
               dnsx subzy dalfox gf chaos puredns
               trufflehog gitleaks s3scanner  +  host / nc

Usage:
  ./install.sh                 core + recommended
  ./install.sh --optional      also install optional tools
  ./install.sh --seclists      also clone SecLists into ~/SecLists
  ./install.sh --all           recommended + optional + seclists
  ./install.sh --minimal       core only
  ./install.sh --help

Uses apt / dnf / pacman / brew for system packages.
Go tools are installed with `go install` (Go is auto-installed if absent).

HELP
      exit 0 ;;
    *) _err "Unknown flag: $_a  (try --help)"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOBIN="${GOBIN:-$(go env GOPATH 2>/dev/null)/bin}"
[ -z "${GOBIN%/bin}" ] && GOBIN="$HOME/go/bin"

# ── Detect package manager ───────────────────────────────────────
PM=""; PM_INSTALL=""
if   has apt-get;  then PM="apt";    PM_INSTALL="sudo apt-get install -y"
elif has dnf;      then PM="dnf";    PM_INSTALL="sudo dnf install -y"
elif has pacman;   then PM="pacman"; PM_INSTALL="sudo pacman -S --noconfirm"
elif has brew;     then PM="brew";   PM_INSTALL="brew install"
fi

# pkg <name> [apt-pkg] [dnf-pkg] [pacman-pkg] [brew-pkg]
pkg() {
  local name="$1" apt="${2:-$1}" dnf="${3:-$1}" pac="${4:-$1}" brew="${5:-$1}" p
  case "$PM" in
    apt)    p="$apt"  ;;
    dnf)    p="$dnf"  ;;
    pacman) p="$pac"  ;;
    brew)   p="$brew" ;;
    *) _warn "no package manager — install '$name' manually"; return 1 ;;
  esac
  _info "installing $name  ($PM: $p)"
  # shellcheck disable=SC2086
  $PM_INSTALL $p >/dev/null 2>&1 \
    && _ok "$name" \
    || { _err "failed: $name"; return 1; }
}

# goget <binary> <module@version>
goget() {
  local bin="$1" mod="$2"
  if has "$bin"; then _ok "$bin  ${D}(already installed)${Z}"; return 0; fi
  has go || { _err "Go not found — cannot install $bin"; return 1; }
  _info "go install $bin"
  GOBIN="$GOBIN" go install "$mod" >/dev/null 2>&1 \
    && _ok "$bin  ${D}→ $GOBIN${Z}" \
    || { _err "go install failed: $bin ($mod)"; return 1; }
}

# ── Go toolchain ─────────────────────────────────────────────────
ensure_go() {
  if has go; then _ok "go  ${D}($(go version | awk '{print $3}'))${Z}"; return 0; fi
  _info "Go toolchain not found — installing"
  case "$PM" in
    apt)    pkg go golang-go golang go go ;;
    dnf)    pkg go golang   golang go go ;;
    pacman) pkg go go       go     go go ;;
    brew)   pkg go go       go     go go ;;
    *) _err "install Go manually: https://go.dev/dl/ then re-run"; return 1 ;;
  esac
  has go || { _err "Go still not on PATH — open a new shell and re-run"; return 1; }
}

# ── Tier: core ───────────────────────────────────────────────────
install_core() {
  _hdr "Core  ${D}(required)${Z}"
  _hr

  has curl    && _ok "curl"    || pkg curl
  has jq      && _ok "jq"      || pkg jq
  has python3 && _ok "python3" || pkg python3 python3 python3 python python

  # Python TUI dependency
  if has pip3 || has pip; then
    local _pip; has pip3 && _pip=pip3 || _pip=pip
    if python3 -c "import rich" 2>/dev/null; then
      _ok "rich  ${D}(already installed)${Z}"
    else
      _info "pip install rich"
      "$_pip" install --quiet rich >/dev/null 2>&1 \
        && _ok "rich" || _warn "pip install rich failed — run manually"
    fi
  else
    _warn "pip not found — install rich manually:  pip install rich"
  fi
}

# ── Tier: recommended ────────────────────────────────────────────
install_recommended() {
  _hdr "Recommended  ${D}(ProjectDiscovery suite + ffuf)${Z}"
  _hr

  ensure_go || { _warn "skipping Go tools (no toolchain)"; return 0; }

  goget subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  goget httpx     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  goget naabu     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  goget nuclei    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  goget katana    "github.com/projectdiscovery/katana/cmd/katana@latest"
  goget cdncheck  "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
  goget ffuf      "github.com/ffuf/ffuf/v2@latest"

  if has nuclei; then
    _info "updating nuclei templates"
    nuclei -update-templates >/dev/null 2>&1 \
      && _ok "nuclei templates" \
      || _warn "template update skipped (network issue?)"
  fi

  if [ "$PM" = "apt" ] && ! dpkg -l libpcap-dev >/dev/null 2>&1; then
    _warn "naabu may need libpcap:  sudo apt-get install -y libpcap-dev"
  fi
}

# ── Tier: optional ───────────────────────────────────────────────
install_optional() {
  _hdr "Optional  ${D}(subdomain sources, crawling, vuln tools)${Z}"
  _hr

  ensure_go >/dev/null 2>&1

  # Subdomain / DNS
  goget assetfinder "github.com/tomnomnom/assetfinder@latest"
  goget waybackurls "github.com/tomnomnom/waybackurls@latest"
  goget gau         "github.com/lc/gau/v2/cmd/gau@latest"
  goget dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  goget chaos       "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
  goget puredns     "github.com/d3mondev/puredns/v2@latest"
  goget amass       "github.com/owasp-amass/amass/v4/...@master"

  # Crawling
  goget hakrawler   "github.com/hakluke/hakrawler@latest"

  # Bug bounty
  goget dalfox      "github.com/hahwul/dalfox/v2@latest"
  goget subzy       "github.com/PentestPad/subzy@latest"
  goget gf          "github.com/tomnomnom/gf@latest"

  # Secrets / cloud
  goget gitleaks    "github.com/gitleaks/gitleaks/v8@latest"
  goget s3scanner   "github.com/sa7mon/s3scanner@latest"

  # gf patterns
  if has gf; then
    local gfd="$HOME/.gf"
    mkdir -p "$gfd"
    if [ ! -d "$gfd/Gf-Patterns" ]; then
      _info "cloning gf patterns"
      git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git \
        "$gfd/Gf-Patterns" >/dev/null 2>&1 \
        && cp "$gfd/Gf-Patterns/"*.json "$gfd/" 2>/dev/null \
        && _ok "gf patterns  → $gfd" \
        || _warn "gf pattern clone failed — clone manually from github.com/1ndianl33t/Gf-Patterns"
    else
      _ok "gf patterns  ${D}(already present)${Z}"
    fi
  fi

  # arjun (Python)
  if has arjun; then
    _ok "arjun  ${D}(already installed)${Z}"
  elif has pipx; then
    _info "pipx install arjun"
    pipx install arjun >/dev/null 2>&1 && _ok "arjun" || _err "arjun (pipx) failed"
  elif has pip3; then
    _info "pip3 install --user arjun"
    pip3 install --quiet --user arjun >/dev/null 2>&1 && _ok "arjun" || _err "arjun (pip3) failed"
  else
    _warn "no pipx/pip3 — install arjun manually:  pip install arjun"
  fi

  # trufflehog (official installer)
  if has trufflehog; then
    _ok "trufflehog  ${D}(already installed)${Z}"
  else
    _info "installing trufflehog"
    if curl -sSfL \
         https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
         | sh -s -- -b "$GOBIN" >/dev/null 2>&1; then
      _ok "trufflehog  → $GOBIN"
    else
      _warn "trufflehog install failed — see github.com/trufflesecurity/trufflehog"
    fi
  fi

  # System utilities
  _hdr "System utilities  ${D}(DNS + netcat)${Z}"
  _hr
  has nc       && _ok "nc"       || pkg netcat   netcat-openbsd nmap-ncat openbsd-netcat netcat
  has host     && _ok "host"     || pkg host     dnsutils bind-utils bind-tools bind
  has nslookup && _ok "nslookup" || pkg nslookup dnsutils bind-utils bind-tools bind
  has openssl  && _ok "openssl"  || pkg openssl  openssl openssl openssl openssl
}

# ── SecLists ─────────────────────────────────────────────────────
install_seclists() {
  _hdr "SecLists  ${D}(wordlists)${Z}"
  _hr
  local dest="$HOME/SecLists"
  if [ -d "$dest/.git" ] || [ -d "$dest/Discovery" ]; then
    _ok "SecLists  ${D}(already at $dest)${Z}"
  else
    _info "cloning SecLists (shallow clone) → $dest"
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$dest" >/dev/null 2>&1 \
      && _ok "SecLists  → $dest" \
      || _err "clone failed — fetch manually from github.com/danielmiessler/SecLists"
  fi
}

# ── Finalize: config.env + executable bits ───────────────────────
finalize() {
  _hdr "Finishing up"
  _hr

  local cfg="$SCRIPT_DIR/config.env"
  if [ -f "$cfg" ]; then
    _ok "config.env  ${D}(left untouched)${Z}"
  else
    cat > "$cfg" <<'CFG'
# tanya.sh configuration  v6.1
# All keys are optional.  Source order: script defaults → this file.

# ── Threading & rate limits ──────────────────────────────────────
HTTPX_THREADS=100
NAABU_THREADS=200
NAABU_RATE=2000
FFUF_THREADS=100
KATANA_DEPTH=5

# ── Nuclei tuning ────────────────────────────────────────────────
# NUCLEI_RATE=150
# NUCLEI_CONC=25
# CHALLENGE_THREADS=15

# ── Wordlists ────────────────────────────────────────────────────
FFUF_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"
# DNS_WORDLIST="$HOME/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"

# ── API keys  (blank = feature silently skipped) ─────────────────
SECURITYTRAILS_API_KEY=""
SHODAN_API_KEY=""
# CHAOS_KEY=""
CFG
    _ok "wrote starter config.env"
  fi

  [ -f "$SCRIPT_DIR/tanya.sh"    ] && chmod +x "$SCRIPT_DIR/tanya.sh"    && _ok "tanya.sh    is executable"
  [ -f "$SCRIPT_DIR/tanya_ui.py" ] && chmod +x "$SCRIPT_DIR/tanya_ui.py" && _ok "tanya_ui.py is executable"

  case ":$PATH:" in
    *":$GOBIN:"*) : ;;
    *)
      _warn "Go bin dir not in PATH:  export PATH=\"\$PATH:$GOBIN\""
      _warn "  append to ~/.bashrc or ~/.zshrc to persist"
      ;;
  esac
}

# ── Run ──────────────────────────────────────────────────────────
printf '\n%s◆  tanya.sh installer  v6.1%s\n' "$C$B" "$Z"
[ -n "$PM" ] \
  && _info "package manager: $PM" \
  || _warn "no apt/dnf/pacman/brew detected — system packages must be installed manually"

install_core
$DO_RECOMMENDED && install_recommended
$DO_OPTIONAL    && install_optional
$DO_SECLISTS    && install_seclists
finalize

_hr
printf '\n%s◆  Done.%s  tanya.sh v6.1 ready.\n' "$C" "$Z"
_info "dep check:  ${C}./tanya.sh example.com --module subdomains${Z}"
_info "bash TUI:   ${C}./tanya.sh example.com${Z}"
_info "python TUI: ${C}python3 tanya_ui.py example.com${Z}"
_info "full scan:  ${C}./tanya.sh example.com --full${Z}  ${D}(authorized targets only)${Z}"
printf '\n'
