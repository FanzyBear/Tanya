#!/usr/bin/env python3
# ============================================================
#  tanya_report.py — interactive HTML report for tanya.sh  (v5.5)
#
#  Walks a tanya.sh run directory and emits ONE self-contained
#  .html file (no external assets, works offline / air-gapped /
#  emailed to a client). Mirrors the triage logic in run_report.
#
#  v5.5: surfaces WSL Windows paths (\\wsl.localhost\...) + a clickable
#  file:// URL, and an "edge challenges" (Cloudflare/anti-bot) section.
#
#  Usage:
#    python3 tanya_report.py <OUT_DIR> [--out report.html]
#                            [--target host] [--scope apex|single]
#                            [--passive] [--win-dir '\\wsl.localhost\...']
#
#  Exit codes: 0 ok, 2 bad/empty dir.
# ============================================================
import os, sys, json, html, re, argparse, datetime, subprocess, shutil

# ---- WSL path helpers ---------------------------------------------------
def detect_wsl():
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as f:
            return bool(re.search(r"microsoft|wsl", f.read(), re.I))
    except OSError:
        return False

def to_win_path(linux_path):
    """Linux path -> Windows path via wslpath; echoes input back on failure."""
    if not shutil.which("wslpath"):
        return linux_path
    try:
        return subprocess.run(["wslpath", "-w", linux_path],
                              capture_output=True, text=True, timeout=5
                              ).stdout.strip() or linux_path
    except Exception:
        return linux_path

def win_file_url(win_path):
    """Windows path -> file:// URL openable from a Windows browser."""
    if not win_path:
        return ""
    w = win_path.replace("\\", "/")
    if w.startswith("//"):          # UNC \\wsl.localhost\...
        return "file://" + w[2:]
    return "file:///" + w           # drive C:\...


# ---- tiny IO helpers ----------------------------------------------------
def lines(path):
    """Return non-empty stripped lines, or [] if file missing/empty."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]
    except OSError:
        return []

def count(path):
    return len(lines(path))

def first(path):
    ls = lines(path)
    return ls[0] if ls else ""

# ---- parse one run dir into a data model --------------------------------
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def parse_alive(d):
    """http/alive.txt rows: url \t [code] \t title \t tech(csv)."""
    rows = []
    for ln in lines(os.path.join(d, "http", "alive.txt")):
        parts = ln.split("\t")
        url = parts[0] if parts else ln
        code = re.sub(r"[\[\]]", "", parts[1]) if len(parts) > 1 else "?"
        title = parts[2] if len(parts) > 2 else ""
        tech = [t for t in (parts[3].split(",") if len(parts) > 3 else []) if t]
        rows.append({"url": url, "code": code, "title": title, "tech": tech})
    return rows

def parse_findings(d):
    """nuclei/findings.txt rows: [tmpl] [proto] [severity] url."""
    rows = []
    for ln in lines(os.path.join(d, "nuclei", "findings.txt")):
        sev = "info"
        m = re.search(r"\[(critical|high|medium|low|info)\]", ln, re.I)
        if m:
            sev = m.group(1).lower()
        tmpl = ""
        mt = re.match(r"\s*\[([^\]]+)\]", ln)
        if mt:
            tmpl = mt.group(1)
        url = ""
        mu = re.search(r"(https?://\S+)", ln)
        if mu:
            url = mu.group(1)
        rows.append({"raw": ln, "sev": sev, "template": tmpl, "url": url})
    rows.sort(key=lambda r: SEV_RANK.get(r["sev"], 9))
    return rows

def parse_ports(d):
    rows = []
    high = set(lines(os.path.join(d, "ports", "high_interest.txt")))
    for ln in lines(os.path.join(d, "ports", "ports.txt")):
        host, _, port = ln.rpartition(":")
        rows.append({"host": host or ln, "port": port, "high": ln in high})
    rows.sort(key=lambda r: (not r["high"], r["host"]))
    return rows

def parse_origins(d):
    return lines(os.path.join(d, "origin", "confirmed_origins.txt"))

def parse_challenges(d):
    """http/challenge_detail.txt rows: url \t code \t verdict \t vendor.
    Return only the rows actually behind a challenge."""
    rows = []
    for ln in lines(os.path.join(d, "http", "challenge_detail.txt")):
        parts = ln.split("\t")
        if len(parts) < 4:
            continue
        url, code, verdict, vendor = parts[0], parts[1], parts[2], parts[3]
        if verdict.strip().lower() != "challenge":
            continue
        rows.append({"url": url, "code": code, "vendor": vendor})
    rows.sort(key=lambda r: (r["vendor"], r["url"]))
    return rows

def state_modules(d):
    done = set(lines(os.path.join(d, ".state")))
    order = ["subdomains","http","origin","ports","urls","js","fuzz","params","nuclei","dorks","cloud"]
    return [{"name": m, "done": m in done} for m in order]

def build_triage(d):
    """Prioritised 'where to start' list — mirrors run_report()."""
    def n(p): return count(os.path.join(d, p))
    nf = os.path.join(d, "nuclei", "findings.txt")
    ncrit = sum(1 for l in lines(nf) if "[critical]" in l.lower())
    nhigh = sum(1 for l in lines(nf) if "[high]" in l.lower())
    items = [
        ("critical", ncrit,                          "critical nuclei finding(s)",        "nuclei/findings.txt"),
        ("critical", n("cloud/open_buckets.txt"),    "publicly exposed cloud bucket(s)",  "cloud/open_buckets.txt"),
        ("high",     nhigh,                           "high nuclei finding(s)",            "nuclei/findings.txt"),
        ("high",     n("nuclei/cves.txt"),            "CVE match(es)",                     "nuclei/cves.txt"),
        ("high",     n("js/potential_secrets.txt"),   "potential secret(s) in JS",         "js/potential_secrets.txt"),
        ("notable",  n("origin/origins.txt"),         "confirmed origin IP(s) (CDN bypass)","origin/confirmed_origins.txt"),
        ("notable",  n("http/interesting.txt"),       "interesting service(s) exposed",    "http/interesting.txt"),
        ("notable",  n("ports/high_interest.txt"),    "high-risk open port(s)",            "ports/high_interest.txt"),
        ("candidate",n("params/ssrf_params.txt"),     "SSRF param candidate(s)",           "params/ssrf_params.txt"),
        ("candidate",n("params/idor_params.txt"),     "IDOR param candidate(s)",           "params/idor_params.txt"),
        ("candidate",n("params/lfi_params.txt"),      "LFI param candidate(s)",            "params/lfi_params.txt"),
        ("candidate",n("params/redirect_params.txt"), "open-redirect candidate(s)",        "params/redirect_params.txt"),
        ("candidate",n("urls/interesting_files.txt"), "interesting file URL(s)",           "urls/interesting_files.txt"),
    ]
    return [{"tier": t, "n": c, "label": lbl, "path": p} for (t, c, lbl, p) in items if c > 0]

def collect(d, target, scope, passive, win_dir=None):
    nf = os.path.join(d, "nuclei", "findings.txt")
    sev_counts = {s: sum(1 for l in lines(nf) if f"[{s}]" in l.lower())
                  for s in ["critical","high","medium","low","info"]}
    abs_d = os.path.abspath(d)
    # Windows-side paths (WSL): use the value tanya.sh computed if it passed one,
    # else derive it here. Empty when not on WSL.
    win = win_dir or (to_win_path(abs_d) if detect_wsl() else "")
    win_report = ""
    file_url = ""
    if win:
        sep = "" if win.endswith("\\") else "\\"
        win_report = f"{win}{sep}report\\report.html"
        file_url = win_file_url(win_report)
    challenges = parse_challenges(d)
    return {
        "target": target,
        "scope": scope,
        "passive": passive,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "out_dir": abs_d,
        "win_dir": win,
        "win_report": win_report,
        "file_url": file_url,
        "modules": state_modules(d),
        "triage": build_triage(d),
        "summary": {
            "hosts":   count(os.path.join(d,"subdomains","subs.txt")),
            "live":    count(os.path.join(d,"http","live_urls.txt")),
            "waf":     count(os.path.join(d,"http","waf.txt")),
            "challenged": count(os.path.join(d,"http","challenged.txt")),
            "orig_c":  count(os.path.join(d,"origin","origin_candidates.txt")),
            "origins": count(os.path.join(d,"origin","origins.txt")),
            "ports":   count(os.path.join(d,"ports","ports.txt")),
            "urls":    count(os.path.join(d,"urls","urls.txt")),
            "jsendp":  count(os.path.join(d,"js","endpoints.txt")),
            "secrets": count(os.path.join(d,"js","potential_secrets.txt")),
            "params":  count(os.path.join(d,"params","parameterized.txt")),
            "buckets": count(os.path.join(d,"cloud","open_buckets.txt")),
            "findings": count(nf),
            "sev": sev_counts,
        },
        "alive":    parse_alive(d),
        "findings": parse_findings(d),
        "ports":    parse_ports(d),
        "origins":  parse_origins(d),
        "challenges": challenges,
        "challenged": lines(os.path.join(d,"http","challenged.txt")),
        "hosts":    lines(os.path.join(d,"subdomains","subs.txt")),
        "secrets":  lines(os.path.join(d,"js","potential_secrets.txt")),
        "endpoints":lines(os.path.join(d,"js","endpoints.txt")),
        "interesting": lines(os.path.join(d,"http","interesting.txt")),
        "buckets":  lines(os.path.join(d,"cloud","s3_results.txt")),
        "open_buckets": lines(os.path.join(d,"cloud","open_buckets.txt")),
        "params": {
            "ssrf":     lines(os.path.join(d,"params","ssrf_params.txt")),
            "idor":     lines(os.path.join(d,"params","idor_params.txt")),
            "lfi":      lines(os.path.join(d,"params","lfi_params.txt")),
            "redirect": lines(os.path.join(d,"params","redirect_params.txt")),
        },
        "interesting_files": lines(os.path.join(d,"urls","interesting_files.txt")),
        "dorks": {
            "google": lines(os.path.join(d,"dorks","google_dorks.txt")),
            "github": lines(os.path.join(d,"dorks","github_dorks.txt")),
        },
    }

# ---- HTML rendering -----------------------------------------------------
HTML_SHELL = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tanya recon · __TARGET__</title>
<style>__CSS__</style>
</head><body>
<div id="app"></div>
<script type="application/json" id="recon-data">__DATA__</script>
<script>__JS__</script>
</body></html>"""

CSS = r"""
:root{
  --base:#101218; --panel:#171a22; --panel2:#1d212b; --line:#2a2f3d;
  --ink:#e7e9f0; --dim:#8b91a3; --faint:#5c6173;
  --amber:#ffb02e; --cyan:#56d3e8;
  --crit:#ff3b3b; --high:#ff8a3d; --med:#f5c451; --low:#6f7c91; --info:#56d3e8; --cand:#9b8cff;
  --mono:ui-monospace,"SFMono-Regular","JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--base);color:var(--ink);font-family:var(--mono);
  font-size:13.5px;line-height:1.5;-webkit-font-smoothing:antialiased;
  background-image:radial-gradient(circle at 1px 1px,#ffffff08 1px,transparent 0);
  background-size:22px 22px;}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px 80px}

/* top bar */
.bar{position:sticky;top:0;z-index:30;background:#0c0e13ee;backdrop-filter:blur(8px);
  border-bottom:1px solid var(--line);}
.bar-in{max-width:1180px;margin:0 auto;padding:11px 20px;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.brand{display:flex;align-items:baseline;gap:9px;font-weight:700}
.brand .cat{color:var(--amber);letter-spacing:.16em;font-size:15px}
.brand .v{color:var(--faint);font-size:11px}
.tgt{color:var(--ink);font-weight:700}
.scope{color:var(--dim);font-size:11px;border:1px solid var(--line);border-radius:99px;padding:2px 9px}
.scope.pass{color:var(--amber);border-color:#3a3318}
.bar .grow{flex:1}
.search{display:flex;align-items:center;gap:7px;background:var(--panel);border:1px solid var(--line);
  border-radius:7px;padding:6px 9px;min-width:210px}
.search:focus-within{border-color:var(--amber)}
.search input{background:0;border:0;color:var(--ink);font-family:var(--mono);font-size:12.5px;outline:0;width:100%}
.search .kbd{color:var(--faint);font-size:10px;border:1px solid var(--line);border-radius:4px;padding:0 5px}

/* hero / beacon */
.hero{padding:30px 0 8px}
.eyebrow{color:var(--amber);letter-spacing:.28em;font-size:10.5px;text-transform:uppercase;margin-bottom:10px}
.beacon{display:flex;gap:0;border:1px solid var(--line);border-radius:11px;overflow:hidden;background:var(--panel)}
.beacon .rail{width:7px;flex:none}
.beacon .body{padding:17px 20px;flex:1;min-width:0}
.beacon .k{font-size:10.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim)}
.beacon .big{font-size:23px;font-weight:700;margin:5px 0 3px;line-height:1.15}
.beacon .sub{color:var(--dim);font-size:12px}
.beacon .dot{display:inline-block;width:8px;height:8px;border-radius:99px;margin-right:7px;vertical-align:middle;
  animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.7)}}
.clean{color:var(--dim)}

/* module ribbon */
.ribbon{display:flex;gap:6px;flex-wrap:wrap;margin:16px 0 4px}
.pip{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--dim);
  border:1px solid var(--line);border-radius:6px;padding:4px 9px;background:var(--panel)}
.pip .led{width:7px;height:7px;border-radius:99px;background:var(--faint)}
.pip.on{color:var(--ink)} .pip.on .led{background:var(--amber);box-shadow:0 0 7px var(--amber)}

/* WSL path strip */
.wslbar{margin:10px 0 0;display:flex;gap:9px;align-items:center;flex-wrap:wrap;
  background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:8px 12px;font-size:11.5px;color:var(--dim)}
.wslbar .wk{color:var(--amber);font-weight:700;letter-spacing:.14em;font-size:10px;
  border:1px solid #3a3318;border-radius:5px;padding:1px 7px}
.wslbar code{color:var(--ink);word-break:break-all}

/* summary cards */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(132px,1fr));gap:10px;margin:22px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:13px 14px}
.card .n{font-size:24px;font-weight:700;letter-spacing:-.02em}
.card .l{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim);margin-top:2px}
.card.alert .n{color:var(--crit)} .card.warn .n{color:var(--high)} .card.acc .n{color:var(--amber)}

/* sections */
section{margin:30px 0;scroll-margin-top:64px}
.h{display:flex;align-items:center;gap:11px;margin:0 0 13px;cursor:pointer;user-select:none}
.h .idx{color:var(--amber);font-size:11px;letter-spacing:.1em}
.h h2{font-size:14px;letter-spacing:.04em;margin:0;text-transform:uppercase;font-weight:700}
.h .cnt{color:var(--faint);font-size:11px}
.h .chev{margin-left:auto;color:var(--faint);transition:transform .18s}
.h.collapsed .chev{transform:rotate(-90deg)}
.panel{border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:hidden}
.collapsed + .panel{display:none}
.empty{padding:18px 16px;color:var(--faint);font-size:12px}

/* filter pills */
.pills{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 12px}
.pill{font-size:11px;color:var(--dim);background:var(--panel);border:1px solid var(--line);
  border-radius:99px;padding:4px 11px;cursor:pointer;letter-spacing:.04em}
.pill:hover{color:var(--ink)}
.pill.active{color:var(--base);font-weight:700}
.pill[data-sev=all].active{background:var(--ink);border-color:var(--ink)}
.pill[data-sev=critical].active{background:var(--crit);border-color:var(--crit)}
.pill[data-sev=high].active{background:var(--high);border-color:var(--high)}
.pill[data-sev=medium].active{background:var(--med);border-color:var(--med)}
.pill[data-sev=low].active{background:var(--low);border-color:var(--low)}
.pill[data-sev=info].active{background:var(--info);border-color:var(--info)}

/* finding rows */
.row{display:flex;align-items:flex-start;gap:11px;padding:10px 14px;border-top:1px solid var(--line)}
.row:first-child{border-top:0}
.row .sevbar{width:4px;align-self:stretch;border-radius:99px;flex:none}
.tag{font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;font-weight:700;
  border-radius:5px;padding:2px 7px;flex:none}
.t-crit{background:#3a1414;color:var(--crit)} .t-high{background:#3a230f;color:var(--high)}
.t-med{background:#3a3210;color:var(--med)} .t-low{background:#222732;color:#aeb6c7}
.t-info{background:#0f2e34;color:var(--info)} .t-cand{background:#231f3a;color:var(--cand)}
.row .meat{min-width:0;flex:1}
.row .tmpl{font-weight:700}
.row .u{color:var(--dim);font-size:12px;word-break:break-all}
.copy{margin-left:auto;flex:none;background:0;border:1px solid var(--line);color:var(--dim);
  font-family:var(--mono);font-size:10.5px;border-radius:5px;padding:3px 8px;cursor:pointer}
.copy:hover{color:var(--ink);border-color:var(--amber)}
.copy.done{color:var(--amber);border-color:var(--amber)}

/* generic data table */
.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl td{padding:8px 14px;border-top:1px solid var(--line);vertical-align:top;word-break:break-all}
.tbl tr:first-child td{border-top:0}
.code-i{font-size:11px;color:var(--dim);background:var(--panel2);border-radius:4px;padding:1px 6px}
.chip{font-size:10px;color:var(--dim);border:1px solid var(--line);border-radius:5px;padding:1px 6px;margin-right:4px;display:inline-block;margin-top:2px}
.scode{font-weight:700} .s2{color:#62d196} .s3{color:var(--cyan)} .s4{color:var(--high)} .s5{color:var(--crit)}
.hot{color:var(--crit);font-weight:700}
.mono-list{margin:0;padding:0;list-style:none}
.mono-list li{padding:7px 14px;border-top:1px solid var(--line);word-break:break-all;display:flex;gap:10px;align-items:center}
.mono-list li:first-child{border-top:0}
.mono-list .grow{flex:1;min-width:0}

/* dork blocks */
.dork{display:flex;gap:8px;align-items:center;padding:6px 14px;border-top:1px solid var(--line)}
.dork:first-child{border-top:0}
.dork code{flex:1;color:var(--ink);word-break:break-all}

.hide{display:none!important}
.foot{margin-top:42px;color:var(--faint);font-size:11px;text-align:center;
  border-top:1px solid var(--line);padding-top:18px}
.foot .auth{color:var(--amber)}
@media (prefers-reduced-motion:reduce){*{animation:none!important;scroll-behavior:auto}}
@media (max-width:640px){.bar-in{padding:9px 14px}.wrap{padding:0 14px 60px}.beacon .big{font-size:19px}}
"""

JS = r"""
const D = JSON.parse(document.getElementById('recon-data').textContent);
const SEVC={critical:'var(--crit)',high:'var(--high)',medium:'var(--med)',low:'var(--low)',info:'var(--info)',candidate:'var(--cand)',notable:'var(--amber)'};
const TIERC={critical:'var(--crit)',high:'var(--high)',notable:'var(--amber)',candidate:'var(--cand)'};
const TIERLBL={critical:'ACT NOW',high:'HIGH',notable:'NOTABLE',candidate:'TO TEST'};
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const E=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e;};

function copyBtn(text){
  const b=E('button','copy','copy');
  b.onclick=async ev=>{ev.stopPropagation();
    try{await navigator.clipboard.writeText(text);}catch(_){
      const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();}
    b.textContent='copied';b.classList.add('done');setTimeout(()=>{b.textContent='copy';b.classList.remove('done');},1100);};
  return b;
}
const sevClass=s=>({critical:'t-crit',high:'t-high',medium:'t-med',low:'t-low',info:'t-info'}[s]||'t-info');

/* ---- build ---- */
const app=document.getElementById('app');

// top bar
const bar=E('div','bar');
const sc=D.passive?'scope pass':'scope';
bar.innerHTML=`<div class="bar-in">
  <div class="brand"><span class="cat">≽ܫ≼ tanya</span><span class="v">recon</span></div>
  <span class="tgt">${esc(D.target)}</span>
  <span class="${sc}">${esc(D.scope)}${D.passive?' · passive':''}</span>
  <span class="grow"></span>
  <label class="search"><input id="q" type="text" placeholder="filter findings, hosts, urls…" autocomplete="off"><span class="kbd">/</span></label>
</div>`;
app.appendChild(bar);

const wrap=E('div','wrap');app.appendChild(wrap);

// hero beacon (highest-severity triage item)
const hero=E('div','hero');
const topItem=D.triage[0];
if(topItem){
  const col=TIERC[topItem.tier]||'var(--amber)';
  hero.innerHTML=`<div class="eyebrow">attack surface · where to start</div>
   <div class="beacon"><div class="rail" style="background:${col}"></div>
    <div class="body"><div class="k"><span class="dot" style="background:${col}"></span>highest signal — ${TIERLBL[topItem.tier]}</div>
     <div class="big">${topItem.n} ${esc(topItem.label)}</div>
     <div class="sub">→ ${esc(D.out_dir)}/${esc(topItem.path)}</div></div></div>`;
}else{
  hero.innerHTML=`<div class="eyebrow">attack surface · where to start</div>
   <div class="beacon"><div class="rail" style="background:var(--low)"></div>
    <div class="body"><div class="k">no high-signal findings flagged</div>
     <div class="big clean">Surface looks quiet</div>
     <div class="sub">Start manual review from http/alive and the URL archive below.</div></div></div>`;
}
wrap.appendChild(hero);

// module ribbon
const rib=E('div','ribbon');
rib.innerHTML=D.modules.map(m=>`<span class="pip ${m.done?'on':''}"><span class="led"></span>${m.name}</span>`).join('');
wrap.appendChild(rib);

// WSL path strip — Windows-side dir + clickable file:// report link
if(D.win_dir){
  const ws=E('div','wslbar');
  const link=D.file_url?` · <a href="${esc(D.file_url)}">open report in Windows browser ↗</a>`:'';
  ws.innerHTML=`<span class="wk">WSL</span><code>${esc(D.win_dir)}</code>${link}`;
  wrap.appendChild(ws);
}

// triage list (full, filterable by search)
if(D.triage.length){
  const sec=section('00','Triage queue',D.triage.length,'triage');
  const p=sec.panel;
  D.triage.forEach(t=>{
    const col=TIERC[t.tier]||'var(--amber)';
    const r=E('div','row searchable');
    r.dataset.text=(t.label+' '+t.path).toLowerCase();
    r.innerHTML=`<div class="sevbar" style="background:${col}"></div>
      <span class="tag ${t.tier==='candidate'?'t-cand':t.tier==='notable'?'t-info':t.tier==='high'?'t-high':'t-crit'}">${TIERLBL[t.tier]}</span>
      <div class="meat"><div class="tmpl">${t.n} ${esc(t.label)}</div><div class="u">${esc(t.path)}</div></div>`;
    r.appendChild(copyBtn(D.out_dir+'/'+t.path));
    p.appendChild(r);
  });
}

// summary cards
const s=D.summary;
const cards=E('div','cards');
const cardDefs=[
  ['hosts','in-scope hosts',''],['live','live services',''],
  ['challenged','edge-challenged',s.challenged>0?'acc':''],
  ['findings','nuclei findings',s.sev.critical+s.sev.high>0?'warn':''],
  ['secrets','secret hits',s.secrets>0?'alert':''],
  ['buckets','public buckets',s.buckets>0?'alert':''],
  ['origins','confirmed origins',s.origins>0?'acc':''],
  ['ports','open ports',''],['urls','urls collected',''],
  ['jsendp','js endpoints',''],['params','param urls',''],
];
cards.innerHTML=cardDefs.map(([k,l,cl])=>`<div class="card ${cl}"><div class="n">${s[k]}</div><div class="l">${l}</div></div>`).join('');
wrap.appendChild(cards);

// findings (with severity pills)
{
  const sec=section('01','Nuclei findings',D.findings.length,'findings');
  if(D.findings.length){
    const counts=s.sev;
    const pills=E('div','pills');
    const order=['all','critical','high','medium','low','info'];
    pills.innerHTML=order.map(o=>{
      const c=o==='all'?D.findings.length:counts[o];
      return `<span class="pill ${o==='all'?'active':''}" data-sev="${o}">${o}${o==='all'?'':' '+c}</span>`;
    }).join('');
    sec.head.after(pills);
    D.findings.forEach(f=>{
      const r=E('div','row searchable finding');
      r.dataset.sev=f.sev; r.dataset.text=(f.raw).toLowerCase();
      r.innerHTML=`<div class="sevbar" style="background:${SEVC[f.sev]}"></div>
        <span class="tag ${sevClass(f.sev)}">${f.sev}</span>
        <div class="meat"><div class="tmpl">${esc(f.template||'finding')}</div>
        <div class="u">${f.url?`<a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.url)}</a>`:esc(f.raw)}</div></div>`;
      r.appendChild(copyBtn(f.raw));
      sec.panel.appendChild(r);
    });
    pills.addEventListener('click',e=>{
      const p=e.target.closest('.pill'); if(!p)return;
      pills.querySelectorAll('.pill').forEach(x=>x.classList.toggle('active',x===p));
      const sev=p.dataset.sev;
      sec.panel.querySelectorAll('.finding').forEach(r=>r.classList.toggle('hide',sev!=='all'&&r.dataset.sev!==sev));
    });
  }
}

// live services table
const CHSET=new Set(D.challenged||[]);
tableSection('02','Live services',D.alive,'alive',rows=>{
  const t=E('table','tbl');
  t.innerHTML=rows.map(a=>{
    const sc=String(a.code)[0];
    const cls=sc==='2'?'s2':sc==='3'?'s3':sc==='4'?'s4':sc==='5'?'s5':'';
    const tech=a.tech.map(x=>`<span class="chip">${esc(x)}</span>`).join('');
    const chl=CHSET.has(a.url)?'<span class="chip" style="color:var(--amber);border-color:#3a3318">edge-challenged</span>':'';
    return `<tr class="searchable" data-text="${esc((a.url+' '+a.title+' '+a.tech.join(' ')+(CHSET.has(a.url)?' challenged':'')).toLowerCase())}">
      <td style="width:64px"><span class="scode ${cls}">${esc(a.code)}</span></td>
      <td><a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.url)}</a><div style="color:var(--dim);margin-top:2px">${esc(a.title)}</div></td>
      <td style="width:38%">${tech}${chl}</td></tr>`;
  }).join('');
  return t;
});

// edge challenges (Cloudflare / anti-bot)
tableSection('02b','Edge challenges (WAF / anti-bot)',D.challenges,'challenges',rows=>{
  const t=E('table','tbl');
  t.innerHTML=rows.map(c=>`<tr class="searchable" data-text="${esc((c.url+' '+c.vendor+' '+c.code).toLowerCase())}">
    <td><a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.url)}</a></td>
    <td style="width:70px"><span class="scode s4">${esc(c.code)}</span></td>
    <td style="width:150px"><span class="chip" style="color:var(--amber);border-color:#3a3318">${esc(c.vendor)}</span></td></tr>`).join('');
  return t;
});

// confirmed origins
listSection('03','Confirmed origin IPs (CDN bypass)',D.origins,'origins','hot');
// interesting services
listSection('04','Interesting services',D.interesting,'interesting');
// open buckets + all buckets
listSection('05','Public cloud buckets',D.open_buckets,'buckets','hot');

// ports table
tableSection('06','Open ports',D.ports,'ports',rows=>{
  const t=E('table','tbl');
  t.innerHTML=rows.map(p=>`<tr class="searchable" data-text="${esc((p.host+':'+p.port).toLowerCase())}">
    <td>${esc(p.host)}</td>
    <td style="width:90px">${p.high?`<span class="hot">${esc(p.port)}</span>`:esc(p.port)}</td>
    <td style="width:120px">${p.high?'<span class="chip" style="color:var(--high);border-color:#3a230f">high-risk</span>':''}</td></tr>`).join('');
  return t;
});

// secrets
listSection('07','Potential secrets in JS',D.secrets,'secrets','',true);
// js endpoints
listSection('08','JS endpoints',D.endpoints,'endpoints');

// params (grouped)
{
  const groups=[['ssrf','SSRF'],['idor','IDOR'],['lfi','LFI'],['redirect','open-redirect']];
  const total=groups.reduce((a,[k])=>a+D.params[k].length,0);
  const sec=section('09','Parameter candidates',total,'params');
  if(total){
    groups.forEach(([k,lbl])=>{
      D.params[k].forEach(u=>{
        const r=E('div','row searchable');r.dataset.text=u.toLowerCase();
        r.innerHTML=`<div class="sevbar" style="background:var(--cand)"></div>
          <span class="tag t-cand">${lbl}</span><div class="meat u">${esc(u)}</div>`;
        r.appendChild(copyBtn(u));sec.panel.appendChild(r);
      });
    });
  }else emptyPanel(sec);
}

// interesting files
listSection('10','Interesting file URLs',D.interesting_files,'intfiles');

// dorks (copyable)
{
  const total=D.dorks.google.length+D.dorks.github.length;
  const sec=section('11','Dorks',total,'dorks');
  if(total){
    [['google','Google'],['github','GitHub']].forEach(([k,lbl])=>{
      if(!D.dorks[k].length)return;
      const hd=E('div','row');hd.style.background='var(--panel2)';
      hd.innerHTML=`<div class="meat tmpl" style="color:var(--amber)">${lbl} — paste into a browser</div>`;
      hd.appendChild(copyBtn(D.dorks[k].join('\n')));
      sec.panel.appendChild(hd);
      D.dorks[k].forEach(q=>{
        const d=E('div','dork searchable');d.dataset.text=q.toLowerCase();
        d.innerHTML=`<code>${esc(q)}</code>`;d.appendChild(copyBtn(q));
        sec.panel.appendChild(d);
      });
    });
  }else emptyPanel(sec);
}

// footer
const winFoot = D.file_url
  ? `<br>windows: ${esc(D.win_dir)} · <a href="${esc(D.file_url)}">open report in Windows browser</a>`
  : "";
wrap.appendChild(E('div','foot',
  `generated ${esc(D.generated)} · ${esc(D.out_dir)}${winFoot}<br>
   <span class="auth">authorized targets only</span> — recon output is signal, not proof. verify every finding manually.`));

/* ---- section builders ---- */
function section(idx,title,cnt,id){
  const sec=E('section');sec.id='sec-'+id;
  const head=E('div','h');
  head.innerHTML=`<span class="idx">${idx}</span><h2>${title}</h2><span class="cnt">${cnt}</span><span class="chev">▾</span>`;
  const panel=E('div','panel');
  head.onclick=()=>head.classList.toggle('collapsed');
  sec.appendChild(head);sec.appendChild(panel);wrap.appendChild(sec);
  return {sec,head,panel};
}
function emptyPanel(sec){sec.panel.appendChild(E('div','empty','— no data —'));sec.head.classList.add('collapsed');}
function listSection(idx,title,items,id,extra,copyEach){
  const sec=section(idx,title,items.length,id);
  if(!items.length){emptyPanel(sec);return;}
  const ul=E('ul','mono-list');
  items.forEach(it=>{
    const li=E('li');li.classList.add('searchable');li.dataset.text=it.toLowerCase();
    const span=E('span','grow '+(extra||''),esc(it));li.appendChild(span);
    if(copyEach)li.appendChild(copyBtn(it));
    ul.appendChild(li);
  });
  sec.panel.appendChild(ul);
}
function tableSection(idx,title,rows,id,render){
  const sec=section(idx,title,rows.length,id);
  if(!rows.length){emptyPanel(sec);return;}
  sec.panel.appendChild(render(rows));
}

/* ---- global search ---- */
const q=document.getElementById('q');
q.addEventListener('input',()=>{
  const v=q.value.trim().toLowerCase();
  document.querySelectorAll('.searchable').forEach(el=>{
    el.classList.toggle('hide', v && !(el.dataset.text||'').includes(v));
  });
  // collapse sections with no visible rows
  document.querySelectorAll('section').forEach(sec=>{
    const items=sec.querySelectorAll('.searchable');
    if(!items.length)return;
    const any=[...items].some(i=>!i.classList.contains('hide'));
    sec.classList.toggle('hide', v && !any);
  });
});
document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement!==q){e.preventDefault();q.focus();}
  if(e.key==='Escape'&&document.activeElement===q){q.value='';q.dispatchEvent(new Event('input'));q.blur();}
});
"""

def render(data):
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    out = HTML_SHELL.replace("__CSS__", CSS).replace("__JS__", JS)
    out = out.replace("__DATA__", payload)
    out = out.replace("__TARGET__", html.escape(data["target"]))
    return out

# ---- cli ----------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Interactive HTML report for a tanya.sh run dir")
    ap.add_argument("out_dir")
    ap.add_argument("--out", default=None, help="output html path (default: <dir>/report/report.html)")
    ap.add_argument("--target", default=None)
    ap.add_argument("--scope", default="apex")
    ap.add_argument("--passive", action="store_true")
    ap.add_argument("--win-dir", default=None,
                    help="Windows-side path of OUT_DIR (WSL); auto-detected if omitted")
    a = ap.parse_args()

    d = a.out_dir.rstrip("/")
    if not os.path.isdir(d):
        sys.stderr.write(f"not a directory: {d}\n"); sys.exit(2)

    target = a.target
    if not target:  # infer from "<host>_<timestamp>" dir name
        base = os.path.basename(d)
        target = re.sub(r"_\d{8}_\d{6}$", "", base) or base

    data = collect(d, target, a.scope, a.passive, win_dir=a.win_dir)
    out = a.out or os.path.join(d, "report", "report.html")
    out_parent = os.path.dirname(out)
    if out_parent:
        os.makedirs(out_parent, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(render(data))
    print(out)

if __name__ == "__main__":
    main()