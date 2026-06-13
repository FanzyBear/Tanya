#!/bin/bash
# install.sh — Install all recon pipeline dependencies for tanyaa.sh
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[✗]${RESET} $*"; }

TOOLS_OK=0
TOOLS_FAIL=0

check() {
  if command -v "$1" &>/dev/null; then
    ok "$1 already installed"
    (( TOOLS_OK++ )) || true
    return 0
  fi
  return 1
}

install_go_tool() {
  local name="$1"; local pkg="$2"
  check "$name" && return
  info "Installing $name..."
  if go install "$pkg" 2>/dev/null; then
    ok "$name installed"
    (( TOOLS_OK++ )) || true
  else
    err "Failed to install $name ($pkg)"
    (( TOOLS_FAIL++ )) || true
  fi
}

install_pip_tool() {
  local name="$1"; local pkg="$2"
  check "$name" && return
  info "Installing $name..."
  if pip3 install --quiet "$pkg" 2>/dev/null; then
    ok "$name installed"
    (( TOOLS_OK++ )) || true
  else
    err "Failed to install $name"
    (( TOOLS_FAIL++ )) || true
  fi
}

echo -e "${CYAN}"
echo "  ┌─────────────────────────────────────┐"
echo "  │   tanyaa.sh — Dependency Installer  │"
echo "  └─────────────────────────────────────┘"
echo -e "${RESET}"

# ── Check Prerequisites ───────────────────────────────────────
info "Checking prerequisites..."

GO_OK=false
PY_OK=false

if ! command -v go &>/dev/null; then
  warn "Go not found — Go-based tools will be skipped"
  warn "Install from: https://go.dev/dl/"
else
  ok "Go: $(go version | awk '{print $3}')"
  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:$GOPATH/bin"
  GO_OK=true
fi

if ! command -v python3 &>/dev/null; then
  warn "Python3 not found — pip-based tools will be skipped"
elif ! command -v pip3 &>/dev/null; then
  warn "pip3 not found — pip-based tools will be skipped"
else
  ok "Python3: $(python3 --version)"
  PY_OK=true
fi

# ── Go Tools ─────────────────────────────────────────────────
# Used in: subdomains, http, ports, screenshots, urls, vuln scanning
if $GO_OK; then
  info "Installing Go-based tools..."

  # MODULE 1 — Subdomain Enumeration
  install_go_tool subfinder    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool assetfinder  "github.com/tomnomnom/assetfinder@latest"

  # MODULE 2 — HTTP Probing
  install_go_tool httpx        "github.com/projectdiscovery/httpx/cmd/httpx@latest"

  # MODULE 3 — Port Scanning
  install_go_tool naabu        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

  # MODULE 4 — Screenshots
  install_go_tool gowitness    "github.com/sensepost/gowitness@latest"

  # MODULE 5 — URL Collection
  install_go_tool katana       "github.com/projectdiscovery/katana/cmd/katana@latest"
  install_go_tool gau          "github.com/lc/gau/v2/cmd/gau@latest"
  install_go_tool waybackurls  "github.com/tomnomnom/waybackurls@latest"

  # MODULE 7 — Directory Bruteforce
  install_go_tool ffuf         "github.com/ffuf/ffuf/v2@latest"

  # MODULE 9 — Vulnerability Scanning
  install_go_tool nuclei       "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

  # MODULE 6 — JS Secret Scanning (primary tools, grep is fallback)
  install_go_tool trufflehog   "github.com/trufflesecurity/trufflehog/v3@latest"
  install_go_tool gitleaks     "github.com/gitleaks/gitleaks/v8@latest"

  # Utility
  install_go_tool anew         "github.com/tomnomnom/anew@latest"
  install_go_tool notify       "github.com/projectdiscovery/notify/cmd/notify@latest"
  install_go_tool dnsx         "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
fi

# ── Pip Tools ────────────────────────────────────────────────
# Used in: cloud bucket recon, parameter discovery
if $PY_OK; then
  info "Installing Python-based tools..."

  # MODULE 8 — Parameter Discovery
  install_pip_tool arjun    "arjun"

  # MODULE 11 — Cloud Bucket Recon
  install_pip_tool s3scanner "s3scanner"
fi

# ── Package Manager Tools ─────────────────────────────────────
# MODULE 1 — Subdomain Enumeration (amass)
# MODULE 4 — Screenshots (eyewitness fallback)
if command -v apt-get &>/dev/null; then
  info "Installing system packages..."

  sudo apt-get install -y -q amass 2>/dev/null \
    && ok "amass installed" \
    || warn "amass: install manually → https://github.com/owasp-amass/amass/releases"

  # eyewitness is a fallback for gowitness (module 4)
  if ! command -v gowitness &>/dev/null; then
    sudo apt-get install -y -q eyewitness 2>/dev/null \
      && ok "eyewitness installed" \
      || warn "eyewitness: install manually → https://github.com/RedSiege/EyeWitness"
  fi

elif command -v brew &>/dev/null; then
  info "Homebrew detected — installing system packages..."
  brew install amass 2>/dev/null && ok "amass installed" || warn "amass: brew install failed"
else
  warn "No supported package manager (apt/brew) — install amass manually"
  warn "  → https://github.com/owasp-amass/amass/releases"
fi

# ── nuclei templates ──────────────────────────────────────────
if command -v nuclei &>/dev/null; then
  info "Updating nuclei templates..."
  nuclei -update-templates -silent 2>/dev/null && ok "nuclei templates updated" \
    || warn "nuclei template update failed — run: nuclei -update-templates"
fi

# ── SecLists (wordlist for ffuf) ──────────────────────────────
SECLIST_DIR="$HOME/SecLists"
FFUF_WORDLIST="$SECLIST_DIR/Discovery/Web-Content/common.txt"

if [ ! -f "$FFUF_WORDLIST" ]; then
  warn "SecLists not found at $SECLIST_DIR"
  if command -v git &>/dev/null; then
    read -rp "$(echo -e "${CYAN}[?]${RESET} Clone SecLists now? (~1GB) [y/N]: ")" yn
    if [[ "${yn,,}" == "y" ]]; then
      info "Cloning SecLists..."
      git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLIST_DIR" \
        && ok "SecLists cloned → $SECLIST_DIR" \
        || warn "SecLists clone failed — clone manually: https://github.com/danielmiessler/SecLists"
    else
      warn "Skipping SecLists — set FFUF_WORDLIST in config.env to your wordlist path"
    fi
  else
    warn "git not found — clone SecLists manually: https://github.com/danielmiessler/SecLists"
    warn "Then set FFUF_WORDLIST in config.env"
  fi
else
  ok "SecLists wordlist found: $FFUF_WORDLIST"
fi

# ── Add Go bin to PATH ────────────────────────────────────────
SHELL_RC=""
[ -f "$HOME/.zshrc"  ] && SHELL_RC="$HOME/.zshrc"
[ -f "$HOME/.bashrc" ] && SHELL_RC="$HOME/.bashrc"

if [[ -n "$SHELL_RC" ]] && $GO_OK; then
  if ! grep -q 'GOPATH/bin' "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> "$SHELL_RC"
    info "Added \$HOME/go/bin to PATH in $SHELL_RC"
  fi
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━ Install Summary ━━━${RESET}"
ok "Installed/available : $TOOLS_OK"
[ "$TOOLS_FAIL" -gt 0 ] && warn "Failed              : $TOOLS_FAIL (check output above)"
echo ""
info "Next steps:"
info "  1. Reload shell  →  source ~/.bashrc  (or restart terminal)"
info "  2. Make executable →  chmod +x tanyaa.sh"
info "  3. Run recon     →  ./tanyaa.sh example.com"