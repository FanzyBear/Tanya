#!/usr/bin/env bash
# ================================================================
#  lib/utils.sh — general helpers for tanya.sh  (v6.0)
#  Sourced by tanya.sh; expects globals (DOMAIN, OUT_DIR, etc.) set.
# ================================================================

# ── Tool detection ────────────────────────────────────────────
has()  { command -v "$1" >/dev/null 2>&1; }
need() { has "$1" || die "'$1' not found — install it first"; }

# ── File helpers ──────────────────────────────────────────────
count()    { [ -f "$1" ] && awk 'END{print NR+0}' "$1" 2>/dev/null || echo 0; }
nonempty() { [ -s "$1" ]; }

# ── Retry wrapper ─────────────────────────────────────────────
retry() {
  local attempts="$1"; shift
  local delay=2 n=0
  until "$@" 2>>"${LOG_FILE:-/dev/null}"; do
    n=$(( n + 1 ))
    [ "$n" -ge "$attempts" ] && { warn "Failed after $attempts attempt(s)"; return 1; }
    warn "Attempt $n failed — retrying in ${delay}s…"
    sleep "$delay"; delay=$(( delay * 2 ))
  done
}

# ── Subdomain normalization ───────────────────────────────────
# Extracts FQDNs from any tool output line (not just clean hostnames).
# Handles formats like "www.example.com (FQDN) --> a_record --> 1.2.3.4"
normalize_hosts() {
  tr '[:upper:]' '[:lower:]' \
    | sed -E 's#https?://##g' \
    | grep -oE '([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,}' \
    | sed -E 's/^\*\.//; s/\.$//' \
    | sort -u
}

# ── Best URL list for active scanning ────────────────────────
# Prefers the edge-challenge-free list (clean_urls.txt) over the raw
# live list, so nuclei/fuzz/crawl don't waste requests on CDN interstit.
scan_url_list() {
  local clean="$OUT_DIR/http/clean_urls.txt"
  local live="$OUT_DIR/http/live_urls.txt"
  if nonempty "$clean"; then printf '%s' "$clean"
  elif nonempty "$live"; then printf '%s' "$live"
  else printf ''; fi
}

# ── WSL awareness ────────────────────────────────────────────
is_wsl() {
  [ -n "${WSL_DISTRO_NAME:-}" ] && return 0
  grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null
}

win_path() {
  if has wslpath; then wslpath -w "$1" 2>/dev/null || printf '%s' "$1"
  else printf '%s' "$1"; fi
}

win_file_url() {
  local w; w=$(win_path "$1"); w=${w//\\//}
  if [[ "$w" == //* ]]; then printf 'file://%s' "${w#//}"
  else printf 'file:///%s' "$w"; fi
}

# ── Prune empty output files ──────────────────────────────────
prune_empty() {
  local root="${1:-$OUT_DIR}"
  [ -d "$root" ] || return 0
  find "$root" -type f -empty ! -name 'recon.log' ! -name '.state' -delete 2>/dev/null || true
  find "$root" -mindepth 1 -type d -empty -delete 2>/dev/null || true
}

# ── Resume state ──────────────────────────────────────────────
state_mark_done() { echo "$1" >> "$STATE_FILE"; }
state_is_done()   { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }

# Status glyph for the interactive menu (✓ if done, · if not)
_mk() { state_is_done "$1" 2>/dev/null && printf "${GREEN}✓${RESET}" || printf "${DIM}·${RESET}"; }

# ── Target helpers ────────────────────────────────────────────
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
  if [[ "$raw" =~ ^([a-zA-Z]+):// ]]; then
    TARGET_SCHEME="${BASH_REMATCH[1],,}"
  fi
  raw="${raw#http://}"; raw="${raw#https://}"
  raw="${raw%%/*}"; raw="${raw%%\?*}"; raw="${raw%%:*}"; raw="${raw,,}"
  [ -n "$raw" ] || die "Empty target"

  if is_ip "$raw"; then
    TARGET_HOST="$raw"; DOMAIN="$raw"; SCOPE_MODE="single"
    info "Target is an IP — single-host mode"
  elif echo "$raw" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'; then
    TARGET_HOST="$raw"
    if is_paas_host "$raw"; then
      DOMAIN="$raw"; SCOPE_MODE="single"
      info "PaaS host detected — single-host mode (no subdomain enum)"
    else
      DOMAIN="$raw"; SCOPE_MODE="apex"
    fi
  else
    die "Invalid target: '$1' — provide a domain, URL, or IP"
  fi

  if has host && host "$TARGET_HOST" >/dev/null 2>&1; then
    ok "DNS resolves: $TARGET_HOST"
  elif has nslookup && nslookup "$TARGET_HOST" >/dev/null 2>&1; then
    ok "DNS resolves: $TARGET_HOST"
  else
    warn "Could not confirm DNS resolution for $TARGET_HOST — continuing"
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
