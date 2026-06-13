#!/usr/bin/env bash
# ============================================================
#  install.sh — dependency installer for tanya.sh
#
#  Tiers:
#    core         curl, jq, python3            (required)
#    recommended  subfinder httpx naabu nuclei katana ffuf
#    optional     assetfinder amass waybackurls gau arjun
#                 trufflehog gitleaks s3scanner dnsx cdncheck
#                 + system: host/nslookup (dnsutils), nc (netcat)
#
#  Usage:
#    ./install.sh                 core + recommended
#    ./install.sh --optional      also install optional tools
#    ./install.sh --seclists      also clone SecLists into ~/SecLists
#    ./install.sh --all           recommended + optional + seclists
#    ./install.sh --minimal       core only
#    ./install.sh --help
#
#  Supports apt / dnf / pacman / brew for system packages, and
#  `go install` for the Go-based recon tools (installs Go if absent).
# ============================================================
set -uo pipefail

# ── pretty output ────────────────────────────────────────────
if [ -t 1 ]; then
  G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; C='\033[0;36m'; B='\033[1m'; D='\033[2m'; X='\033[0m'
else
  G=''; Y=''; R=''; C=''; B=''; D=''; X=''
fi
say()  { echo -e "${C}::${X} $*"; }
ok()   { echo -e "  ${G}✓${X} $*"; }
warn() { echo -e "  ${Y}!${X} $*"; }
err()  { echo -e "  ${R}✗${X} $*" >&2; }
hr()   { echo -e "${D}────────────────────────────────────────────────────────${X}"; }
has()  { command -v "$1" >/dev/null 2>&1; }

# ── flags ────────────────────────────────────────────────────
DO_RECOMMENDED=true
DO_OPTIONAL=false
DO_SECLISTS=false
for a in "$@"; do
  case "$a" in
    --minimal)   DO_RECOMMENDED=false ;;
    --optional)  DO_OPTIONAL=true ;;
    --seclists)  DO_SECLISTS=true ;;
    --all)       DO_OPTIONAL=true; DO_SECLISTS=true ;;
    --help|-h)
      cat <<'HELP'
install.sh — dependency installer for tanya.sh

Tiers:
  core         curl, jq, python3                         (always installed)
  recommended  subfinder httpx naabu nuclei katana ffuf  (default)
  optional     assetfinder amass waybackurls gau arjun trufflehog
               gitleaks s3scanner dnsx cdncheck + host/nslookup/nc

Usage:
  ./install.sh                core + recommended
  ./install.sh --optional     also install optional tools
  ./install.sh --seclists     also clone SecLists into ~/SecLists
  ./install.sh --all          recommended + optional + seclists
  ./install.sh --minimal      core only
  ./install.sh --help         this help

Uses apt / dnf / pacman / brew for system packages and `go install`
for the Go-based recon tools (installs the Go toolchain if absent).
HELP
      exit 0 ;;
    *) err "Unknown flag: $a (try --help)"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOBIN="${GOBIN:-$(go env GOPATH 2>/dev/null)/bin}"
[ -z "${GOBIN%/bin}" ] && GOBIN="$HOME/go/bin"

# ── detect system package manager ────────────────────────────
PM=""; PM_INSTALL=""
if has apt-get;   then PM="apt";    PM_INSTALL="sudo apt-get install -y"
elif has dnf;     then PM="dnf";    PM_INSTALL="sudo dnf install -y"
elif has pacman;  then PM="pacman"; PM_INSTALL="sudo pacman -S --noconfirm"
elif has brew;    then PM="brew";   PM_INSTALL="brew install"
fi

pkg() { # pkg <generic-name> [apt] [dnf] [pacman] [brew]
  local name="$1" apt="${2:-$1}" dnf="${3:-$1}" pac="${4:-$1}" brew="${5:-$1}" p
  case "$PM" in
    apt) p="$apt" ;; dnf) p="$dnf" ;; pacman) p="$pac" ;; brew) p="$brew" ;;
    *) warn "no supported package manager — install '$name' manually"; return 1 ;;
  esac
  say "installing $name ($PM: $p)"
  # shellcheck disable=SC2086
  $PM_INSTALL $p >/dev/null 2>&1 && ok "$name" || { err "failed to install $name"; return 1; }
}

# go install helper: goget <binary> <module@version>
goget() {
  local bin="$1" mod="$2"
  if has "$bin"; then ok "$bin (already present)"; return 0; fi
  if ! has go; then err "Go toolchain missing — cannot install $bin"; return 1; fi
  say "go install $bin"
  if GOBIN="$GOBIN" go install "$mod" >/dev/null 2>&1; then
    ok "$bin → $GOBIN"
  else
    err "go install failed for $bin ($mod)"
    return 1
  fi
}

# ── Go toolchain ─────────────────────────────────────────────
ensure_go() {
  if has go; then ok "go ($(go version | awk '{print $3}'))"; return 0; fi
  say "Go toolchain not found — installing"
  case "$PM" in
    apt)    pkg go golang-go golang go go ;;
    dnf)    pkg go golang   golang go go ;;
    pacman) pkg go go       go     go go ;;
    brew)   pkg go go       go     go go ;;
    *) err "install Go manually from https://go.dev/dl/ then re-run"; return 1 ;;
  esac
  has go || { err "Go still not on PATH — open a new shell or add it, then re-run"; return 1; }
}

# ── tier: core ───────────────────────────────────────────────
install_core() {
  hr; say "${B}Core (required)${X}"
  has curl    && ok "curl"    || pkg curl
  has jq      && ok "jq"      || pkg jq
  has python3 && ok "python3" || pkg python3 python3 python3 python python
}

# ── tier: recommended (Go tools) ─────────────────────────────
install_recommended() {
  hr; say "${B}Recommended recon tools${X}"
  ensure_go || { warn "skipping Go tools"; return 0; }
  goget subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  goget httpx     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  goget naabu     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  goget nuclei    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  goget katana    "github.com/projectdiscovery/katana/cmd/katana@latest"
  goget ffuf      "github.com/ffuf/ffuf/v2@latest"
  if has nuclei; then
    say "updating nuclei templates"
    nuclei -update-templates >/dev/null 2>&1 && ok "nuclei templates" || warn "template update skipped"
  fi
  # naabu needs libpcap headers to build on Linux
  if [ "$PM" = "apt" ] && ! has naabu; then
    warn "naabu build often needs libpcap-dev: sudo apt-get install -y libpcap-dev"
  fi
}

# ── tier: optional ───────────────────────────────────────────
install_optional() {
  hr; say "${B}Optional tools${X}"
  ensure_go >/dev/null 2>&1
  # Go-based
  goget assetfinder "github.com/tomnomnom/assetfinder@latest"
  goget waybackurls "github.com/tomnomnom/waybackurls@latest"
  goget gau         "github.com/lc/gau/v2/cmd/gau@latest"
  goget dnsx        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  goget cdncheck    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
  goget gitleaks    "github.com/gitleaks/gitleaks/v8@latest"
  goget amass       "github.com/owasp-amass/amass/v4/...@master"
  goget s3scanner   "github.com/sa7mon/s3scanner@latest"

  # Python-based: arjun (prefer pipx, fall back to pip --user)
  if has arjun; then ok "arjun (already present)"
  elif has pipx; then say "pipx install arjun"; pipx install arjun >/dev/null 2>&1 && ok "arjun" || err "arjun (pipx) failed"
  elif has pip3; then say "pip3 install --user arjun"; pip3 install --user arjun >/dev/null 2>&1 && ok "arjun" || err "arjun (pip) failed"
  else warn "no pipx/pip3 — install arjun manually"; fi

  # trufflehog (official installer script → GOBIN)
  if has trufflehog; then ok "trufflehog (already present)"
  else
    say "installing trufflehog"
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
         | sh -s -- -b "$GOBIN" >/dev/null 2>&1; then ok "trufflehog → $GOBIN"
    else warn "trufflehog install script failed — see github.com/trufflesecurity/trufflehog"; fi
  fi

  # system DNS/netcat utilities
  hr; say "${B}System utilities${X}"
  has nc      && ok "nc"      || pkg netcat  netcat-openbsd nmap-ncat openbsd-netcat netcat
  has host    && ok "host"    || pkg host    dnsutils bind-utils bind-tools bind
  has nslookup&& ok "nslookup"|| pkg nslookup dnsutils bind-utils bind-tools bind
}

# ── SecLists ─────────────────────────────────────────────────
install_seclists() {
  hr; say "${B}SecLists wordlists${X}"
  local dest="$HOME/SecLists"
  if [ -d "$dest/.git" ] || [ -d "$dest/Discovery" ]; then
    ok "SecLists already at $dest"
  else
    say "cloning SecLists (shallow) → $dest"
    if git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$dest" >/dev/null 2>&1; then
      ok "SecLists → $dest"
    else
      err "clone failed — fetch manually from github.com/danielmiessler/SecLists"
    fi
  fi
}

# ── starter config + executable bit ──────────────────────────
finalize() {
  hr; say "${B}Finishing up${X}"
  local cfg="$SCRIPT_DIR/config.env"
  if [ -f "$cfg" ]; then
    ok "config.env exists (left untouched)"
  else
    cat > "$cfg" <<'CFG'
# tanya.sh configuration — all keys optional, sourced at startup.
HTTPX_THREADS=50
NAABU_THREADS=100
NAABU_RATE=1000
KATANA_DEPTH=3
FFUF_THREADS=40
FFUF_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"
CURL_UA="Mozilla/5.0 (recon; +tanya.sh)"

# Optional API keys for richer origin discovery (blank = skipped)
SECURITYTRAILS_API_KEY=""
SHODAN_API_KEY=""
CFG
    ok "wrote starter config.env"
  fi
  if [ -f "$SCRIPT_DIR/tanya.sh" ]; then
    chmod +x "$SCRIPT_DIR/tanya.sh" && ok "tanya.sh is executable"
  else
    warn "tanya.sh not found next to install.sh — place it here before running"
  fi

  # PATH hint for Go bin
  case ":$PATH:" in
    *":$GOBIN:"*) : ;;
    *) warn "add Go bin to PATH:  export PATH=\"\$PATH:$GOBIN\""
       warn "  (append that line to your ~/.bashrc or ~/.zshrc to persist)" ;;
  esac
}

# ── run ──────────────────────────────────────────────────────
echo -e "${B}${C}tanya.sh installer${X}"
[ -n "$PM" ] && say "package manager: $PM" || warn "no apt/dnf/pacman/brew detected — system packages must be installed manually"

install_core
$DO_RECOMMENDED && install_recommended
$DO_OPTIONAL    && install_optional
$DO_SECLISTS    && install_seclists
finalize

hr
say "${B}Done.${X} Verify with:  ${C}./tanya.sh example.com --help${X}"
say "Run a scan with:  ${C}./tanya.sh example.com --full${X}  ${D}(authorized targets only)${X}"