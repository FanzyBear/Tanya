#!/usr/bin/env bash
# ================================================================
#  lib/ui.sh  —  terminal UI for tanya.sh  v6.1
#
#  Sourced by tanya.sh.  Expects LOG_FILE to be set before first use.
#  Theme: cyan accent  (Claude Code palette)
# ================================================================

# ── Colors ───────────────────────────────────────────────────────
CYAN=$'\033[0;36m';    BCYAN=$'\033[1;36m'
GREEN=$'\033[0;32m';   BGREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m';  RED=$'\033[0;31m';   BRED=$'\033[1;31m'
MAGENTA=$'\033[0;35m'; BLUE=$'\033[0;34m'
BOLD=$'\033[1m';       DIM=$'\033[2m';      RESET=$'\033[0m'

# ── Logging (terminal + ANSI-stripped log file) ──────────────────
_log() {
  printf '%s\n' "$*"
  if [ -n "${LOG_FILE:-}" ]; then
    printf '%s\n' "$*" | sed -E $'s/\x1b\\[[0-9;]*m//g' >> "$LOG_FILE"
  fi
}

# ── Spinner (TTY-only, suppressed when piped) ────────────────────
_SPIN_PID=""
_STEP_TS=0

spin_start() {
  [ -t 1 ] || return 0
  local msg="${1:-working…}"
  local ts0=$SECONDS
  ( trap 'exit 0' TERM INT
    local i=0 frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
    while true; do
      printf '\r  %s%s%s  %s  %s%ds%s   ' \
        "$BCYAN" "${frames[$((i % 10))]}" "$RESET" "$msg" "$DIM" $(( SECONDS - ts0 )) "$RESET"
      (( i++ )) || true
      sleep 0.08
    done
  ) &
  _SPIN_PID=$!
}

spin_watch() {
  [ -t 1 ] || return 0
  local msg="${1:-}" file="${2:-}"
  local ts0=$SECONDS
  ( trap 'exit 0' TERM INT
    local i=0 n=0 frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
    while true; do
      [ -n "$file" ] && [ -f "$file" ] \
        && n=$(awk 'END{print NR+0}' "$file" 2>/dev/null) || true
      local cnt=""
      [ "$n" -gt 0 ] && cnt="${BGREEN}[${n}]${RESET}${DIM}"
      printf '\r  %s%s%s  %s %s  %s%ds%s   ' \
        "$BCYAN" "${frames[$((i % 10))]}" "$RESET" \
        "$msg" "$cnt" "$DIM" $(( SECONDS - ts0 )) "$RESET"
      (( i++ )) || true
      sleep 0.1
    done
  ) &
  _SPIN_PID=$!
}

spin_stop() {
  [ -n "${_SPIN_PID:-}" ] || return 0
  kill "$_SPIN_PID" 2>/dev/null || true
  wait "$_SPIN_PID" 2>/dev/null || true
  _SPIN_PID=""
  [ -t 1 ] && printf '\r\033[2K'
}

# ── Progress bar ─────────────────────────────────────────────────
_pbar() {
  local cur=$1 tot=$2 w=${3:-48}
  local f=$(( cur * w / tot )) e=$(( w - f ))
  local bar="" i
  for (( i = 0; i < f; i++ )); do bar+='█'; done
  for (( i = 0; i < e; i++ )); do bar+='░'; done
  printf '%s%s%s%s%s' "$BCYAN" "${bar:0:$f}" "$RESET$DIM" "${bar:$f}" "$RESET"
}

# ── Output helpers ───────────────────────────────────────────────
info() { spin_stop; _log "  ${DIM}·${RESET}  $*"; }
ok()   { spin_stop; _log "  ${BGREEN}✓${RESET}  $*"; }
warn() { spin_stop; _log "  ${YELLOW}⚠${RESET}  $*"; }
err()  { spin_stop; _log "  ${BRED}✘${RESET}  $*"; }
high() { spin_stop; _log "  ${YELLOW}▲${RESET}  $*"; }
crit() { spin_stop; _log "  ${BRED}!!${RESET} $*"; }
die()  { err "$*"; exit 1; }

# ── Section header ───────────────────────────────────────────────
STEP_N=0; STEP_TOTAL=0

section() {
  spin_stop
  _log ""

  if [ "${STEP_TOTAL:-0}" -gt 0 ]; then
    local elapsed=""
    [ "$_STEP_TS" -gt 0 ] && elapsed="  ${DIM}$(( SECONDS - _STEP_TS ))s${RESET}"
    _STEP_TS=$SECONDS
    STEP_N=$(( STEP_N + 1 ))
    local pct=$(( STEP_N * 100 / STEP_TOTAL ))
    local bar; bar=$(_pbar "$STEP_N" "$STEP_TOTAL" 46)
    _log "  ${bar}${elapsed}"
    _log "  ${BCYAN}◆${RESET}  ${BOLD}$*${RESET}  ${DIM}${STEP_N}/${STEP_TOTAL} · ${pct}%${RESET}"
  else
    local rule; rule=$(printf '─%.0s' $(seq 1 60))
    _log "  ${DIM}${rule}${RESET}"
    _log "  ${BCYAN}◆${RESET}  ${BOLD}$*${RESET}"
  fi
}

# ── Banner ───────────────────────────────────────────────────────
banner() {
  local C="${BCYAN}" R="${RESET}" D="${DIM}" Y="${YELLOW}"

  _log ""
  local logo=(
    "  ${C} ████████╗ █████╗ ███╗   ██╗██╗   ██╗  █████╗ ${R}"
    "  ${C}    ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝ ██╔══██╗${R}"
    "  ${C}    ██║   ███████║██╔██╗ ██║ ╚████╔╝  ███████║${R}"
    "  ${C}    ██║   ██╔══██║██║╚██╗██║  ╚██╔╝   ██╔══██║${R}"
    "  ${C}    ██║   ██║  ██║██║ ╚████║   ██║    ██║  ██║${R}"
    "  ${C}    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═╝  ╚═╝${R}"
  )
  local l
  for l in "${logo[@]}"; do
    _log "$l"
    [ -t 1 ] && sleep 0.04
  done

  local cat_pad="                                        "
  _log "  ${cat_pad}${Y} _._     _,-'\`-._${R}"
  _log "  ${cat_pad}${Y}(,-.\`._,'(       |\\${R}${Y}\`-/|${R}"
  _log "  ${cat_pad}${Y}    \`-.-' \\ )-\`( , o o)${R}"
  _log "  ${cat_pad}${Y}          \`-    \\${R}${Y}\`_\`\"'-${R}"
  _log ""

  local W=62
  local rule; rule=$(printf '─%.0s' $(seq 1 $W))
  _log "  ${D}${rule}${R}"
  _log "  ${BOLD}Bug Bounty Web Recon Pipeline${R}  ${BCYAN}v6.1${R}  ${D}·  web-focused · authorized targets only${R}"
  _log "  ${D}${rule}${R}"
  _log ""
}

# ── Visible string length (strips ANSI) ──────────────────────────
_vlen() {
  printf '%s' "$1" | sed -E $'s/\x1b\\[[0-9;]*m//g' | awk '{print length}'
}

# ── Auto-width box ───────────────────────────────────────────────
box() {
  local color="$1" title="$2"; shift 2
  local lines=("$@") l vl maxw=0
  vl=$(_vlen "$title"); (( vl > maxw )) && maxw=$vl
  for l in "${lines[@]}"; do vl=$(_vlen "$l"); (( vl > maxw )) && maxw=$vl; done
  local iw=$(( maxw + 4 ))
  local bar;  bar=$(printf  '═%.0s' $(seq 1 "$iw"))
  local thin; thin=$(printf '─%.0s' $(seq 1 "$iw"))
  _log "${color}╔${bar}╗${RESET}"
  vl=$(_vlen "$title")
  _log "$(printf "${color}║${RESET}  %s%*s${color}║${RESET}" "$title" "$(( iw - 2 - vl ))" "")"
  if [ "${#lines[@]}" -gt 0 ]; then
    _log "${color}╟${thin}╢${RESET}"
    for l in "${lines[@]}"; do
      vl=$(_vlen "$l"); local rpad=$(( iw - 2 - vl ))
      (( rpad < 0 )) && rpad=0
      _log "$(printf "${color}║${RESET}  %s%*s${color}║${RESET}" "$l" "$rpad" "")"
    done
  fi
  _log "${color}╚${bar}╝${RESET}"
}

# ── run_tool — spinner wrapper ────────────────────────────────────
run_tool() {
  local label="$1"; shift
  [ -z "${_SPIN_PID:-}" ] && spin_start "$label"
  if "$@" 2>>"${LOG_FILE:-/dev/null}"; then
    spin_stop; return 0
  else
    spin_stop; warn "$label exited non-zero (see log)"; return 1
  fi
}
