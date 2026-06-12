#!/bin/bash
# install.sh — Install all recon pipeline dependencies
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[✗]${RESET} $*"; }

INSTALL_DIR="$HOME/go/bin"
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
echo "  ┌─────────────────────────────┐"
echo "  │   TaNyaaaaaaaa~~ Installer  │"
echo "  └─────────────────────────────┘"
echo -e "${RESET}"

# ── Check Prerequisites ───────────────────────────────────────
info "Checking prerequisites..."

if ! command -v go &>/dev/null; then
  warn "Go not found. Many tools require Go."
  warn "Install from: https://go.dev/dl/"
  warn "Continuing with available tools..."
else
  ok "Go: $(go version | awk '{print $3}')"
  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:$GOPATH/bin"
fi

if ! command -v python3 &>/dev/null; then
  warn "Python3 not found — pip-based tools will be skipped"
else
  ok "Python3: $(python3 --version)"
fi

# ── Go Tools ─────────────────────────────────────────────────
if command -v go &>/dev/null; then
  info "Installing Go-based tools..."
  install_go_tool subfinder      "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool dnsx           "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  install_go_tool httpx          "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  install_go_tool naabu          "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  install_go_tool katana         "github.com/projectdiscovery/katana/cmd/katana@latest"
  install_go_tool gau            "github.com/lc/gau/v2/cmd/gau@latest"
  install_go_tool waybackurls    "github.com/tomnomnom/waybackurls@latest"
  install_go_tool gowitness      "github.com/sensepost/gowitness@latest"
  install_go_tool notify         "github.com/projectdiscovery/notify/cmd/notify@latest"
  install_go_tool anew           "github.com/tomnomnom/anew@latest"
fi

# ── Pip Tools ────────────────────────────────────────────────
if command -v pip3 &>/dev/null; then
  info "Installing Python-based tools..."
  install_pip_tool s3scanner "s3scanner"
fi

# ── Package Manager Tools ─────────────────────────────────────
if command -v apt-get &>/dev/null; then
  info "Installing system packages..."
  sudo apt-get install -y -q amass 2>/dev/null && ok "amass installed" || warn "amass: install manually from https://github.com/owasp-amass/amass"
fi

# ── Add Go bin to PATH ────────────────────────────────────────
SHELL_RC=""
[ -f "$HOME/.bashrc" ] && SHELL_RC="$HOME/.bashrc"
[ -f "$HOME/.zshrc"  ] && SHELL_RC="$HOME/.zshrc"

if [[ -n "$SHELL_RC" ]]; then
  if ! grep -q 'GOPATH/bin' "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> "$SHELL_RC"
    info "Added \$HOME/go/bin to PATH in $SHELL_RC"
  fi
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━ Install Summary ━━━${RESET}"
ok "Installed/available: $TOOLS_OK"
[ "$TOOLS_FAIL" -gt 0 ] && warn "Failed: $TOOLS_FAIL (check output above)"
echo ""
info "Run: source ~/.bashrc  (or restart terminal)"
info "Then: chmod +x recon.sh && ./recon.sh example.com"
