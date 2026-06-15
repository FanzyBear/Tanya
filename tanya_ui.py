#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ================================================================
#  tanya_ui.py  v2.0  —  Python TUI for tanya.sh
#
#  Usage:
#    python3 tanya_ui.py <target>             interactive menu
#    python3 tanya_ui.py <target> --full      all modules
#    python3 tanya_ui.py <target> --passive   skip active scans
#    python3 tanya_ui.py <target> --resume    continue last run
#    python3 tanya_ui.py <target> --module <name>
#
#  Requires:  pip install rich
#  Platform:  Linux / macOS / WSL  (curses not available on native Windows)
# ================================================================

import os, sys, re, subprocess, threading, time, argparse
from pathlib import Path
from datetime import datetime

SCRIPT_DIR  = Path(__file__).parent

import signal as _signal

def _handle_sigwinch(signum, frame):
    """No-op — curses generates KEY_RESIZE on next getch() after SIGWINCH."""
    pass

if hasattr(_signal, "SIGWINCH"):
    _signal.signal(_signal.SIGWINCH, _handle_sigwinch)

TANYA_SH    = SCRIPT_DIR / "tanya.sh"
OUTPUT_BASE = SCRIPT_DIR / "output"

# ── Optional deps ─────────────────────────────────────────────
try:
    import curses
    CURSES = True
except ImportError:
    CURSES = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.table import Table
    from rich.live import Live
    from rich.columns import Columns
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.rule import Rule
    from rich import box as rbox
    from rich.console import Group
    con = Console(highlight=False)
    RICH = True
except ImportError:
    RICH = False
    con = None
    print("\033[33m  pip install rich   — for the full TUI experience\033[0m\n")


# ================================================================
#  Theme  (Claude Code palette, cyan accent)
# ================================================================

# Curses color pair IDs
_CP_CYAN   = 1   # cyan on default        — headers, accents
_CP_SEL    = 2   # black on cyan          — selected row
_CP_GREEN  = 3   # green on default       — done / success
_CP_YELLOW = 4   # yellow on default      — warnings / actions
_CP_DIM    = 5   # black+bright on default — secondary text
_CP_RED    = 6   # red on default         — danger / critical
_CP_DONE_S = 7   # black on green         — done + selected
_CP_ACT_S  = 8   # black on yellow        — action + selected
_CP_WHITE  = 9   # white on default       — normal text

def _init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(_CP_CYAN,   curses.COLOR_CYAN,    -1)
    curses.init_pair(_CP_SEL,    curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(_CP_GREEN,  curses.COLOR_GREEN,   -1)
    curses.init_pair(_CP_YELLOW, curses.COLOR_YELLOW,  -1)
    curses.init_pair(_CP_DIM,    curses.COLOR_WHITE,   -1)   # using A_DIM for dimming
    curses.init_pair(_CP_RED,    curses.COLOR_RED,     -1)
    curses.init_pair(_CP_DONE_S, curses.COLOR_BLACK,   curses.COLOR_GREEN)
    curses.init_pair(_CP_ACT_S,  curses.COLOR_BLACK,   curses.COLOR_YELLOW)
    curses.init_pair(_CP_WHITE,  curses.COLOR_WHITE,   -1)

def _cp(n, bold=False, dim=False):
    a = curses.color_pair(n)
    if bold: a |= curses.A_BOLD
    if dim:  a |= curses.A_DIM
    return a


# ================================================================
#  Module catalogue
# ================================================================

MODULES = [
    ("subdomains", "Subdomain Enum",     "subfinder · assetfinder · amass · crt.sh"),
    ("http",       "HTTP Probe + WAF",   "httpx · WAF fingerprint · edge challenge detection"),
    ("origin",     "Origin Discovery",   "CDN bypass · SecurityTrails · Shodan · title-match"),
    ("ports",      "Port Scanning",      "naabu · CDN-aware · web-service probe"),
    ("urls",       "URL Collection",     "katana · waybackurls · gau · hakrawler"),
    ("js",         "JavaScript Recon",   "endpoint extraction · trufflehog / gitleaks"),
    ("fuzz",       "Dir Bruteforce",     "ffuf · SecLists wordlist"),
    ("params",     "Params + CORS",      "arjun · SSRF/IDOR/LFI/redirect/CORS/methods"),
    ("nuclei",     "Vuln Scan",          "nuclei · CVEs · misconfigs · exposures"),
    ("takeover",   "Subdomain Takeover", "subzy · nuclei takeover templates"),
    ("403bypass",  "403/401 Bypass",     "header injection · path manipulation"),
    ("xss",        "XSS Scan",           "dalfox · gf pre-filter"),
    ("dorks",      "Dorks",              "Google & GitHub dork generation"),
    ("cloud",      "Cloud Buckets",      "s3scanner · name permutation"),
    ("headers",    "Header Audit",       "security headers · host injection · CORS deep · CRLF"),
    ("graphql",    "GraphQL Recon",      "endpoint discovery · introspection · batch · nuclei"),
    ("ssl",        "TLS / SSL",          "cert expiry · deprecated protocols · nuclei ssl"),
]

STAT_FILES = [
    ("Subdomains",   "subdomains/subs.txt",              False),
    ("Live URLs",    "http/live_urls.txt",               False),
    ("Challenged",   "http/challenged.txt",              True),
    ("Open Ports",   "ports/ports.txt",                  False),
    ("Total URLs",   "urls/urls.txt",                    False),
    ("JS Endpoints", "js/endpoints.txt",                 False),
    ("Secrets",      "js/potential_secrets.txt",         True),
    ("Nuclei Hits",  "nuclei/findings.txt",              True),
    ("Critical",     None,                               True),   # computed
    ("High",         None,                               True),   # computed
    ("Takeovers",    "takeover/takeovers.txt",           True),
    ("Bypasses",     "bypass403/bypassed.txt",           True),
    ("XSS",          "xss/dalfox_results.txt",          True),
    ("CORS",         "params/cors_vuln.txt",             True),
    ("Host Inject",  "headers/host_injection.txt",       True),
    ("GraphQL EP",   "graphql/endpoints.txt",            False),
    ("GQL Intro",    "graphql/introspection_enabled.txt",True),
    ("SSL Issues",   "ssl/issues.txt",                   True),
]


# ================================================================
#  Helpers
# ================================================================

def _count(path) -> int:
    try:
        with open(path, errors="replace") as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0

def _get_done(state_file) -> set:
    try:
        return set(Path(state_file).read_text(errors="replace").split())
    except OSError:
        return set()

def _latest_outdir(target_host) -> "Path | None":
    dirs = sorted(OUTPUT_BASE.glob(f"{target_host}_*"), reverse=True)
    return dirs[0] if dirs else None

def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)

def _parse_host(raw: str) -> str:
    raw = re.sub(r"^[a-zA-Z]+://", "", raw)
    return raw.split("/")[0].split("?")[0].split(":")[0].lower()

def _nf_counts(out_dir: Path):
    crit = high = 0
    nf = out_dir / "nuclei" / "findings.txt"
    try:
        txt = nf.read_text(errors="replace").lower()
        crit = txt.count("[critical]")
        high = txt.count("[high]")
    except OSError:
        pass
    return crit, high

def _addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y >= h - 1 or x >= w - 1:
        return
    text = str(text)[: w - x - 1]
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass


# ================================================================
#  Curses layout — interactive menu
# ================================================================

BANNER = [
    " ████████╗ █████╗ ███╗   ██╗██╗   ██╗  █████╗ ",
    "    ██╔══╝██╔══██╗████╗  ██║╚██╗ ██╔╝ ██╔══██╗",
    "    ██║   ███████║██╔██╗ ██║ ╚████╔╝  ███████║",
    "    ██║   ██╔══██║██║╚██╗██║  ╚██╔╝   ██╔══██║",
    "    ██║   ██║  ██║██║ ╚████║   ██║    ██║  ██║",
    "    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═╝  ╚═╝",
]

def _draw_banner(win, y0: int) -> int:
    h, w = win.getmaxyx()
    for i, line in enumerate(BANNER):
        ry = y0 + i
        if ry >= h - 1:
            break
        x = max(2, (w - len(line)) // 2)
        _addstr(win, ry, x, line[: w - x - 1], _cp(_CP_CYAN, bold=True))
    return y0 + len(BANNER)

def _draw_hline(win, y, char="─", attr=None):
    h, w = win.getmaxyx()
    if y >= h - 1:
        return
    a = attr if attr is not None else _cp(_CP_DIM, dim=True)
    _addstr(win, y, 0, char * (w - 1), a)

def _draw_stats(win, out_dir: Path, x0: int, y0: int, max_h: int):
    crit, high = _nf_counts(out_dir)
    computed   = {"Critical": crit, "High": high}

    h, w = win.getmaxyx()
    _addstr(win, y0, x0, " STATS", _cp(_CP_CYAN, bold=True))
    y = y0 + 1

    for label, rel, is_finding in STAT_FILES:
        if y >= y0 + max_h or y >= h - 2:
            break
        if rel is None:
            n = computed.get(label, 0)
        else:
            n = _count(out_dir / rel)

        val = str(n) if n else "—"
        row = f"  {label:<14} {val:>4}"

        if is_finding and n > 0:
            attr = _cp(_CP_YELLOW, bold=True) if label not in ("Critical", "High") else \
                   (_cp(_CP_RED, bold=True) if label == "Critical" else _cp(_CP_YELLOW, bold=True))
        else:
            attr = _cp(_CP_DIM, dim=True) if n == 0 else _cp(_CP_WHITE)

        _addstr(win, y, x0, row[: w - x0 - 1], attr)
        y += 1


def interactive_menu(stdscr, target_host: str, out_dir: Path, passive: bool = False):
    """
    Full-screen curses menu.
    Returns ("module", key) | ("full"|"report"|"deps"|"quit", None)
    """
    curses.curs_set(0)
    _init_colors()
    stdscr.keypad(True)
    stdscr.timeout(500)          # unblock every 500 ms so resize is caught quickly

    state_file = out_dir / ".state"
    ACTIONS = [
        ("F", "Full Pipeline", "run all 17 modules end-to-end"),
        ("R", "Reports",       "generate text + HTML report"),
        ("D", "Dep Check",     "show installed / missing tools"),
        ("Q", "Quit",          "exit tanya_ui"),
    ]
    N_MOD  = len(MODULES)
    N_ACT  = len(ACTIONS)
    TOTAL  = N_MOD + N_ACT
    sel    = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        # ── banner (compact: show if enough height) ──────────
        y = 0
        if h >= 26:
            y = _draw_banner(stdscr, 0) + 1
        else:
            title = " ◆ TANYA  v6.1"
            _addstr(stdscr, 0, 2, title, _cp(_CP_CYAN, bold=True))
            y = 2

        # ── target info bar ──────────────────────────────────
        mode = "passive" if passive else "active"
        info = f" ◆ {target_host}  ·  {mode}  ·  {out_dir.name}"
        _addstr(stdscr, y, 0, info[: w - 1], _cp(_CP_CYAN))
        y += 1
        _draw_hline(stdscr, y)
        y += 1

        # ── column split — adaptive to terminal width ─────────
        SHOW_STATS = w >= 74
        stat_w  = 24 if SHOW_STATS else 0
        mod_w   = w - stat_w - (1 if SHOW_STATS else 0)
        stat_x  = mod_w + 1 if SHOW_STATS else w

        # column headers
        _addstr(stdscr, y, 2,      " MODULES",  _cp(_CP_CYAN, bold=True))
        if SHOW_STATS:
            _addstr(stdscr, y, stat_x, " STATS",    _cp(_CP_CYAN, bold=True))
        y += 1

        # vertical separator (only when stats sidebar is visible)
        sep_x = mod_w
        if SHOW_STATS:
            for ry in range(y, min(h - 5, y + N_MOD + 2)):
                _addstr(stdscr, ry, sep_x, "│", _cp(_CP_DIM, dim=True))

        # ── module rows ──────────────────────────────────────
        done    = _get_done(state_file)
        row_y   = y
        crit, high = _nf_counts(out_dir)
        computed    = {"Critical": crit, "High": high}

        for i, (key, lbl, desc) in enumerate(MODULES):
            ry = row_y + i
            if ry >= h - 5:
                break
            is_done = key in done
            is_sel  = sel == i

            if is_done:
                glyph = "✓"
                base  = _cp(_CP_GREEN)
            else:
                glyph = "◇"
                base  = _cp(_CP_DIM, dim=True)

            num  = f"{i + 1:2d}"
            row  = f"  {glyph}  {num}  {lbl}"

            if is_sel:
                sel_attr = _cp(_CP_DONE_S, bold=True) if is_done else _cp(_CP_SEL, bold=True)
                padded = row.ljust(mod_w - 1)[: mod_w - 1]
                _addstr(stdscr, ry, 0, padded, sel_attr)
                # show description right of selection
                dtext = f"  {desc}"[: w - mod_w - 2]
                _addstr(stdscr, ry, mod_w + 1, dtext, _cp(_CP_DIM, dim=True))
            else:
                _addstr(stdscr, ry, 0, row[: mod_w - 1], base)

        # ── stats sidebar (only if terminal wide enough) ──────
        if SHOW_STATS:
            sy = row_y
            for label, rel, is_finding in STAT_FILES:
                if sy >= h - 5:
                    break
                n = computed.get(label, 0) if rel is None else _count(out_dir / rel)
                val = str(n) if n else "—"
                text = f" {label:<13}{val:>4}"

                if is_finding and n > 0:
                    a = _cp(_CP_RED, bold=True) if label == "Critical" else \
                        _cp(_CP_YELLOW)
                elif n > 0:
                    a = _cp(_CP_WHITE)
                else:
                    a = _cp(_CP_DIM, dim=True)

                _addstr(stdscr, sy, stat_x, text[: stat_w], a)
                sy += 1

        # ── actions row ──────────────────────────────────────
        act_y = row_y + N_MOD
        if act_y < h - 4:
            _draw_hline(stdscr, act_y)
            act_y += 1
            for ai, (akey, albl, adesc) in enumerate(ACTIONS):
                ry  = act_y + ai
                idx = N_MOD + ai
                if ry >= h - 2:
                    break
                is_sel = sel == idx
                row    = f"  [{akey}]  {albl:<18}  {adesc}"

                if is_sel:
                    a = _cp(_CP_ACT_S, bold=True) if akey != "Q" else _cp(_CP_RED, bold=True)
                    _addstr(stdscr, ry, 0, row.ljust(w - 1)[: w - 1], a)
                else:
                    a = _cp(_CP_RED) if akey == "Q" else \
                        (_cp(_CP_YELLOW, bold=True) if akey == "F" else _cp(_CP_WHITE))
                    _addstr(stdscr, ry, 0, row[: w - 1], a)

        # ── key legend ───────────────────────────────────────
        _draw_hline(stdscr, h - 2)
        legend = "  ↑↓ navigate   Enter select   1-17 jump   F full   Q quit"
        if not SHOW_STATS:
            legend += "   [widen terminal for stats]"
        _addstr(stdscr, h - 1, 0, legend[: w - 1], _cp(_CP_DIM, dim=True))

        stdscr.refresh()

        # ── input ────────────────────────────────────────────
        key = stdscr.getch()

        if key == curses.KEY_RESIZE or key == -1:
            # -1 = timeout (500 ms) — just redraw for live stats
            # KEY_RESIZE = terminal was resized
            try:
                h, w = stdscr.getmaxyx()
                curses.resizeterm(h, w)
            except Exception:
                pass
            stdscr.erase()
            continue

        if key == curses.KEY_UP:
            sel = (sel - 1) % TOTAL
        elif key == curses.KEY_DOWN:
            sel = (sel + 1) % TOTAL
        elif key == curses.KEY_PPAGE:
            sel = max(0, sel - 5)
        elif key == curses.KEY_NPAGE:
            sel = min(TOTAL - 1, sel + 5)
        elif key in (curses.KEY_ENTER, 10, 13):
            if sel < N_MOD:
                return "module", MODULES[sel][0]
            akey = ACTIONS[sel - N_MOD][0]
            if akey == "F": return "full",   None
            if akey == "R": return "report", None
            if akey == "D": return "deps",   None
            if akey == "Q": return "quit",   None
        elif key in (ord("q"), ord("Q")):
            return "quit", None
        elif key in (ord("f"), ord("F")):
            return "full", None
        elif key in (ord("r"), ord("R")):
            return "report", None
        elif key in (ord("d"), ord("D")):
            return "deps", None
        elif ord("1") <= key <= ord("9"):
            n = key - ord("0") - 1
            if 0 <= n < N_MOD:
                sel = n
        # two-digit jump: handled on next Enter press after navigation


# ================================================================
#  Rich stats table
# ================================================================

def _stats_table(out_dir: Path) -> "Table":
    tbl = Table(box=None, padding=(0, 0), show_header=False, min_width=22)
    tbl.add_column("l", style="dim", no_wrap=True)
    tbl.add_column("v", justify="right", no_wrap=True, min_width=4)

    crit, high = _nf_counts(out_dir)
    computed   = {"Critical": crit, "High": high}

    for label, rel, is_finding in STAT_FILES:
        n  = computed.get(label, 0) if rel is None else _count(out_dir / rel)
        vs = str(n) if n else "—"

        if is_finding and n > 0:
            if label == "Critical":
                v = f"[bold red]{vs}[/]"
            elif label in ("High", "Secrets", "Takeovers", "XSS",
                           "Host Inject", "GQL Intro", "SSL Issues"):
                v = f"[bold yellow]{vs}[/]"
            else:
                v = f"[yellow]{vs}[/]"
        elif n > 0:
            v = f"[cyan]{vs}[/]"
        else:
            v = f"[dim]{vs}[/]"

        tbl.add_row(f"[dim]{label}[/]", v)
    return tbl


# ================================================================
#  Module runner (rich output + live stats)
# ================================================================

def _colorize_line(ln: str) -> tuple[str, str]:
    """Return (rich_style, text) for a single log line."""
    if re.search(r"✓|✔|\bok\b|done|found|complete|confirmed", ln, re.I):
        return "green", ln
    if re.search(r"⚠|warn|missing|challenge|skipping", ln, re.I):
        return "yellow", ln
    if re.search(r"✘|error|fail|critical|high\b", ln, re.I):
        return "bold red", ln
    if re.search(r"·|→|running|probing|scanning|crawl", ln, re.I):
        return "dim", ln
    return "", ln


def run_module(module_key: str, target: str, out_dir: Path,
               passive: bool = False, extra: list | None = None):
    """Run one tanya.sh module, streaming output with rich."""
    extra = extra or []
    cmd   = ["bash", str(TANYA_SH), target, "--module", module_key]
    if passive:
        cmd.insert(3, "--passive")
    cmd += extra

    mod_info  = next((m for m in MODULES if m[0] == module_key),
                     (module_key, module_key.title(), ""))
    _, lbl, desc = mod_info

    if not RICH:
        _run_plain(cmd, lbl)
        return

    log: list[str] = []
    lock = threading.Lock()
    start = time.time()

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
        env={**os.environ, "TANYA_OUT_DIR": str(out_dir)},
    )

    def _reader():
        for raw in proc.stdout:
            ln = _strip_ansi(raw.rstrip("\n"))
            if ln:
                with lock:
                    log.append(ln)
                    if len(log) > 300:
                        log.pop(0)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    with Live(console=con, refresh_per_second=8,
              vertical_overflow="crop", transient=False) as live:
        while proc.poll() is None or t.is_alive():
            with lock:
                visible = log[-20:]

            out_text = Text()
            for ln in visible:
                style, _ = _colorize_line(ln)
                out_text.append(ln + "\n", style=style or "")

            stats_panel = Panel(
                _stats_table(out_dir),
                title="[bold cyan]stats[/]",
                border_style="dim cyan",
                padding=(0, 1),
            )
            log_panel = Panel(
                out_text,
                title=f"[bold cyan]◆  {lbl}[/]",
                subtitle=f"[dim]{desc}[/]",
                border_style="cyan",
                padding=(0, 1),
            )
            live.update(Columns([log_panel, stats_panel],
                                expand=True, equal=False))
            time.sleep(0.1)

    t.join(timeout=3)
    rc      = proc.wait()
    elapsed = time.time() - start

    with lock:
        tail = log[-6:]
    tail_text = Text()
    for ln in tail:
        style, _ = _colorize_line(ln)
        tail_text.append(ln + "\n", style=style or "dim")

    border = "green" if rc == 0 else "red"
    status = "[bold green]✓  done[/]" if rc == 0 else f"[bold red]✘  exit {rc}[/]"
    con.print(Panel(
        tail_text,
        title=f"{status}  [bold]{lbl}[/]",
        subtitle=f"[dim]{elapsed:.1f}s[/]",
        border_style=border,
        padding=(0, 1),
    ))
    return rc


# ================================================================
#  Full pipeline runner
# ================================================================

def run_full(target: str, out_dir: Path, passive: bool = False):
    cmd = ["bash", str(TANYA_SH), target, "--full"]
    if passive:
        cmd.append("--passive")

    if not RICH:
        subprocess.call(cmd)
        return

    log: list[str] = []
    lock  = threading.Lock()
    start = time.time()

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
        env={**os.environ, "TANYA_OUT_DIR": str(out_dir)},
    )

    mod_pattern = re.compile(
        r"SUBDOMAIN|HTTP PROB|ORIGIN|PORT SCAN|URL COLL|JAVASCRIPT|"
        r"DIRECTORY|PARAMETER|VULNERAB|TAKEOVER|403|XSS SCAN|DORKS|CLOUD|REPORT",
        re.I,
    )
    current = "initializing…"
    step    = 0

    def _reader():
        nonlocal current, step
        for raw in proc.stdout:
            ln = _strip_ansi(raw.rstrip("\n"))
            if ln:
                with lock:
                    log.append(ln)
                    if len(log) > 400:
                        log.pop(0)
                if mod_pattern.search(ln):
                    current = ln.strip()[:60]
                    step   += 1

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None, style="cyan", complete_style="bold cyan"),
        TextColumn("[cyan]{task.completed}[/]/[dim]17[/]"),
        TimeElapsedColumn(),
        console=con, transient=False,
    ) as prog:
        task = prog.add_task("Full Pipeline", total=17, completed=0)

        with Live(console=con, refresh_per_second=6,
                  vertical_overflow="crop", transient=False) as live:
            while proc.poll() is None or t.is_alive():
                with lock:
                    visible = log[-18:]
                    done_n  = min(step, 17)
                prog.update(task, completed=done_n, description=current[:50])

                out_text = Text()
                for ln in visible:
                    style, _ = _colorize_line(ln)
                    out_text.append(ln + "\n", style=style or "")

                live.update(Columns([
                    Panel(out_text,
                          title="[bold cyan]◆  Full Pipeline[/]",
                          subtitle=f"[dim]{current[:55]}[/]",
                          border_style="cyan",
                          padding=(0, 1)),
                    Panel(_stats_table(out_dir),
                          title="[bold cyan]stats[/]",
                          border_style="dim cyan",
                          padding=(0, 1)),
                ], expand=True, equal=False))
                time.sleep(0.12)

    t.join(timeout=3)
    proc.wait()
    _print_summary(out_dir, target, time.time() - start)


# ================================================================
#  Completion summary
# ================================================================

def _print_summary(out_dir: Path, target: str, elapsed: float):
    if not RICH:
        return
    mm, ss = divmod(int(elapsed), 60)
    crit, high = _nf_counts(out_dir)

    grid = Table.grid(padding=(0, 3))
    grid.add_column(no_wrap=True)
    grid.add_column(no_wrap=True)
    grid.add_column(no_wrap=True)

    def s(label, rel):
        n = _count(out_dir / rel) if rel else 0
        c = "cyan" if n else "dim"
        return f"[dim]{label}[/]  [{c}]{n if n else '—'}[/]"

    grid.add_row(
        s("Subdomains", "subdomains/subs.txt"),
        s("Live URLs",  "http/live_urls.txt"),
        s("Open Ports", "ports/ports.txt"),
    )
    grid.add_row(
        s("Total URLs", "urls/urls.txt"),
        s("Secrets",    "js/potential_secrets.txt"),
        s("Nuclei",     "nuclei/findings.txt"),
    )
    grid.add_row(
        f"[dim]Critical[/]  [bold red]{crit if crit else '—'}[/]",
        f"[dim]High[/]  [bold yellow]{high if high else '—'}[/]",
        f"[dim]Elapsed[/]  [cyan]{mm}m {ss}s[/]",
    )

    paths = Text()
    rpt_txt  = out_dir / "report" / "report.txt"
    rpt_html = out_dir / "report" / "report.html"
    if rpt_txt.exists():
        paths.append(f"  {rpt_txt}\n", style="cyan")
    if rpt_html.exists():
        paths.append(f"  {rpt_html}\n", style="cyan underline")

    con.print()
    con.print(Panel(
        Group(grid, Rule(style="dim cyan"), paths),
        title="[bold green]✓  SCAN COMPLETE[/]  [dim cyan]" + target + "[/]",
        border_style="bold green",
        padding=(1, 2),
    ))


# ================================================================
#  Dep check
# ================================================================

def run_deps(target: str, out_dir: Path):
    cmd = ["bash", str(TANYA_SH), target or "example.com", "--module", "subdomains"]
    if not RICH:
        subprocess.call(cmd)
        return

    con.print(Rule("[bold cyan]Dependency Check[/]", style="cyan"))
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    in_dep = False
    for raw in proc.stdout:
        ln = _strip_ansi(raw.rstrip("\n"))
        if "DEPENDENCY" in ln.upper():
            in_dep = True
        if in_dep and re.search(r"SUBDOMAIN", ln.upper()) and "DEPENDENCY" not in ln.upper():
            proc.terminate()
            break
        if in_dep and ln.strip():
            if "✓" in ln or "installed" in ln.lower():
                con.print(f"[green]  {ln}[/]")
            elif "✘" in ln or "REQUIRED" in ln.upper():
                con.print(f"[bold red]  {ln}[/]")
            elif "missing" in ln.lower() or "·" in ln:
                con.print(f"[yellow]  {ln}[/]")
            else:
                con.print(f"[dim]  {ln}[/]")
    proc.wait()


# ================================================================
#  Plain fallback (no rich, no curses)
# ================================================================

def _run_plain(cmd, label: str):
    print(f"\n\033[1;36m◆  {label}\033[0m\n")
    subprocess.call(cmd)
    print()

def _fallback_menu(target_raw: str, target_host: str, out_dir: Path,
                   passive: bool, dispatch):
    C = "\033[1;36m"; G = "\033[32m"; Y = "\033[1;33m"
    R = "\033[1;31m"; D = "\033[2m";  Z = "\033[0m"
    while True:
        print(f"\n{C}{'─' * 62}{Z}")
        print(f"{C}  ◆ TANYA  v6.1  {D}·  {target_host}{Z}")
        print(f"{C}{'─' * 62}{Z}\n")
        done = _get_done(out_dir / ".state")
        for i, (key, lbl, desc) in enumerate(MODULES, 1):
            g = f"{G}✓{Z}" if key in done else f"{D}◇{Z}"
            print(f"  {g}  {D}[{i:2d}]{Z}  {lbl:<22}  {D}{desc}{Z}")
        print(f"\n  {Y}[F]{Z}  Full Pipeline   {D}[R]{Z}  Reports   {D}[D]{Z}  Dep Check   {R}[Q]{Z}  Quit")
        print(f"\n{D}{'─' * 62}{Z}")
        try:
            ch = input(f"  {C}select ›{Z} ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            break
        if ch == "Q":
            break
        elif ch == "F":
            dispatch("full", None)
        elif ch == "R":
            dispatch("report", None)
        elif ch == "D":
            dispatch("deps", None)
        elif ch.isdigit() and 1 <= int(ch) <= len(MODULES):
            dispatch("module", MODULES[int(ch) - 1][0])
        else:
            print(f"\n  {Y}Enter 1–{len(MODULES)}, F, R, D, or Q{Z}")
            continue
        try:
            input(f"\n  {D}Press Enter to continue…{Z}")
        except (EOFError, KeyboardInterrupt):
            break


# ================================================================
#  Main
# ================================================================

def main():
    ap = argparse.ArgumentParser(
        prog="tanya_ui",
        description="Modern TUI launcher for tanya.sh",
    )
    ap.add_argument("target",             help="domain, URL, or IP to scan")
    ap.add_argument("--full",    action="store_true", help="run all modules")
    ap.add_argument("--passive", action="store_true", help="skip active scans")
    ap.add_argument("--resume",  action="store_true", help="continue last run")
    ap.add_argument("--module",           help="run one module and exit")
    args = ap.parse_args()

    if not TANYA_SH.exists():
        sys.exit(f"ERROR: tanya.sh not found at {TANYA_SH}")

    host = _parse_host(args.target)
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)

    if args.resume:
        out_dir = _latest_outdir(host) or \
                  OUTPUT_BASE / f"{host}_{datetime.now():%Y%m%d_%H%M%S}"
        if RICH:
            con.print(f"[dim]Resuming:[/] [cyan]{out_dir}[/]")
        else:
            print(f"\033[36mResuming: {out_dir}\033[0m")
    else:
        out_dir = OUTPUT_BASE / f"{host}_{datetime.now():%Y%m%d_%H%M%S}"

    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Single-shot modes ────────────────────────────────────
    if args.module:
        run_module(args.module, args.target, out_dir, passive=args.passive)
        sys.exit(0)

    if args.full:
        run_full(args.target, out_dir, passive=args.passive)
        sys.exit(0)

    # ── Interactive loop ─────────────────────────────────────
    def _dispatch(action, value):
        if action == "module":
            run_module(value, args.target, out_dir, passive=args.passive)
        elif action == "full":
            run_full(args.target, out_dir, passive=args.passive)
        elif action == "report":
            run_module("report", args.target, out_dir)
            gen = SCRIPT_DIR / "tanya_report.py"
            if gen.exists():
                subprocess.call(
                    ["python3", str(gen), str(out_dir),
                     "--target", host, "--scope", "apex",
                     "--out", str(out_dir / "report" / "report.html")]
                )
        elif action == "deps":
            run_deps(args.target, out_dir)

    if CURSES:
        def _tui(stdscr):
            while True:
                action, value = interactive_menu(
                    stdscr, host, out_dir, passive=args.passive
                )
                if action == "quit":
                    break
                curses.endwin()
                _dispatch(action, value)
                try:
                    input("\n  Press Enter to return to menu…")
                except (EOFError, KeyboardInterrupt):
                    break
                stdscr = curses.initscr()
                curses.noecho()
                curses.cbreak()
                stdscr.keypad(True)
                _init_colors()

        try:
            curses.wrapper(_tui)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                curses.endwin()
            except Exception:
                pass
    else:
        _fallback_menu(args.target, host, out_dir, args.passive, _dispatch)

    if RICH:
        con.print(f"\n[dim]Results →[/] [cyan]{out_dir}[/]")
    else:
        print(f"\n\033[36m  Results → {out_dir}\033[0m")


if __name__ == "__main__":
    main()
