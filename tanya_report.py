#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ================================================================
#  tanya_report.py  v3.0  —  HTML report for tanya.sh
#
#  Self-contained single-file HTML report.  No CDN, works offline.
#
#  Usage:
#    python3 tanya_report.py <OUT_DIR> [--out report.html]
#                            [--target host] [--scope apex|single]
#                            [--passive] [--win-dir '\\wsl.localhost\...']
#
#  Exit codes: 0 ok, 2 bad dir
# ================================================================
import os, sys, json, html as _html, re, argparse, datetime, subprocess, shutil

# ── WSL helpers ───────────────────────────────────────────────────
def _is_wsl():
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return bool(re.search(r"microsoft|wsl",
                               open("/proc/version", errors="replace").read(), re.I))
    except OSError:
        return False

def _win_path(p):
    if not shutil.which("wslpath"):
        return p
    try:
        return subprocess.run(["wslpath", "-w", p],
                              capture_output=True, text=True, timeout=5).stdout.strip() or p
    except Exception:
        return p

def _file_url(wp):
    if not wp:
        return ""
    w = wp.replace("\\", "/")
    return ("file://" + w[2:]) if w.startswith("//") else ("file:///" + w)

# ── IO helpers ────────────────────────────────────────────────────
def _lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]
    except OSError:
        return []

def _count(path):
    return len(_lines(path))

# ── Data parsers ──────────────────────────────────────────────────
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _parse_alive(d):
    rows = []
    for ln in _lines(os.path.join(d, "http", "alive.txt")):
        parts = ln.split("\t")
        url   = parts[0] if parts else ln
        code  = re.sub(r"[\[\]]", "", parts[1]) if len(parts) > 1 else "?"
        title = parts[2] if len(parts) > 2 else ""
        tech  = [t for t in (parts[3].split(",") if len(parts) > 3 else []) if t]
        rows.append({"url": url, "code": code, "title": title, "tech": tech})
    return rows

def _parse_findings(d):
    rows = []
    for ln in _lines(os.path.join(d, "nuclei", "findings.txt")):
        m_sev  = re.search(r"\[(critical|high|medium|low|info)\]", ln, re.I)
        sev    = m_sev.group(1).lower() if m_sev else "info"
        m_tmpl = re.match(r"\s*\[([^\]]+)\]", ln)
        tmpl   = m_tmpl.group(1) if m_tmpl else ""
        m_url  = re.search(r"(https?://\S+)", ln)
        url    = m_url.group(1) if m_url else ""
        rows.append({"raw": ln, "sev": sev, "template": tmpl, "url": url})
    rows.sort(key=lambda r: SEV_RANK.get(r["sev"], 9))
    return rows

def _parse_ports(d):
    high = set(_lines(os.path.join(d, "ports", "high_interest.txt")))
    rows = []
    for ln in _lines(os.path.join(d, "ports", "ports.txt")):
        host, _, port = ln.rpartition(":")
        rows.append({"host": host or ln, "port": port, "high": ln in high})
    rows.sort(key=lambda r: (not r["high"], r["host"]))
    return rows

def _parse_challenges(d):
    rows = []
    for ln in _lines(os.path.join(d, "http", "challenge_detail.txt")):
        parts = ln.split("\t")
        if len(parts) < 4:
            continue
        url, code, verdict, vendor = parts[0], parts[1], parts[2], parts[3]
        if verdict.strip().lower() != "challenge":
            continue
        rows.append({"url": url, "code": code, "vendor": vendor.strip()})
    rows.sort(key=lambda r: (r["vendor"], r["url"]))
    return rows

def _parse_bypasses(d):
    rows = []
    for ln in _lines(os.path.join(d, "bypass403", "bypassed.txt")):
        parts = ln.split("  |  BYPASS: ", 1)
        url    = parts[0].strip()
        method = parts[1].strip() if len(parts) > 1 else ""
        rows.append({"url": url, "method": method})
    return rows

def _parse_cors(d):
    rows = []
    for ln in _lines(os.path.join(d, "params", "cors_vuln.txt")):
        parts = [p.strip() for p in ln.split("  |  ")]
        rows.append({
            "url":   parts[0] if parts else ln,
            "acao":  parts[1] if len(parts) > 1 else "",
            "acac":  parts[2] if len(parts) > 2 else "",
        })
    return rows

def _parse_host_injection(d):
    rows = []
    for ln in _lines(os.path.join(d, "headers", "host_injection.txt")):
        parts = [p.strip() for p in ln.split("  |  ")]
        rows.append({"url": parts[0], "detail": parts[1] if len(parts) > 1 else ""})
    return rows

def _parse_graphql(d):
    endpoints   = _lines(os.path.join(d, "graphql", "endpoints.txt"))
    introspect  = set(_lines(os.path.join(d, "graphql", "introspection_enabled.txt")))
    nuclei_hits = _lines(os.path.join(d, "graphql", "nuclei_graphql.txt"))
    rows = []
    for ep in endpoints:
        rows.append({"url": ep, "introspection": ep in introspect})
    return {"endpoints": rows, "nuclei": nuclei_hits,
            "batch": _lines(os.path.join(d, "graphql", "batch_allowed.txt"))}

def _parse_ssl(d):
    rows = []
    for ln in _lines(os.path.join(d, "ssl", "issues.txt")):
        parts = [p.strip() for p in ln.split("  |  ")]
        rows.append({"host": parts[0], "issue": parts[1] if len(parts) > 1 else ln})
    nuclei_ssl = _lines(os.path.join(d, "ssl", "nuclei_ssl.txt"))
    return {"issues": rows, "nuclei": nuclei_ssl}

def _sev_counts(d):
    nf = os.path.join(d, "nuclei", "findings.txt")
    return {s: sum(1 for l in _lines(nf) if f"[{s}]" in l.lower())
            for s in ["critical", "high", "medium", "low", "info"]}

def _state_modules(d):
    done  = set(_lines(os.path.join(d, ".state")))
    order = ["subdomains", "http", "origin", "ports", "urls", "js",
             "fuzz", "params", "nuclei", "takeover", "403bypass",
             "xss", "dorks", "cloud", "headers", "graphql", "ssl"]
    labels = {
        "subdomains": "Subs", "http": "HTTP", "origin": "Origin",
        "ports": "Ports", "urls": "URLs", "js": "JS",
        "fuzz": "Fuzz", "params": "Params", "nuclei": "Nuclei",
        "takeover": "Takeover", "403bypass": "403", "xss": "XSS",
        "dorks": "Dorks", "cloud": "Cloud",
        "headers": "Headers", "graphql": "GraphQL", "ssl": "SSL/TLS",
    }
    return [{"id": m, "label": labels.get(m, m), "done": m in done} for m in order]

def _build_triage(d):
    def n(p): return _count(os.path.join(d, p))
    nf   = os.path.join(d, "nuclei", "findings.txt")
    ls   = _lines(nf)
    crit = sum(1 for l in ls if "[critical]" in l.lower())
    high = sum(1 for l in ls if "[high]"     in l.lower())
    rows = [
        ("critical", crit,                       "critical nuclei finding(s)",           "nuclei/findings.txt"),
        ("critical", n("cloud/open_buckets.txt"), "publicly exposed cloud bucket(s)",    "cloud/open_buckets.txt"),
        ("critical", n("takeover/takeovers.txt"), "subdomain takeover candidate(s)",     "takeover/"),
        ("high",     high,                        "high nuclei finding(s)",              "nuclei/findings.txt"),
        ("high",     n("nuclei/cves.txt"),         "CVE match(es)",                      "nuclei/cves.txt"),
        ("high",     n("js/potential_secrets.txt"),"potential secret(s) in JS",          "js/potential_secrets.txt"),
        ("high",     n("xss/dalfox_results.txt"),  "XSS finding(s) (dalfox)",           "xss/dalfox_results.txt"),
        ("high",     n("bypass403/bypassed.txt"),   "403/401 bypass(es) confirmed",      "bypass403/bypassed.txt"),
        ("high",     n("params/cors_vuln.txt"),     "CORS misconfiguration(s)",          "params/cors_vuln.txt"),
        ("high",     n("params/methods_vuln.txt"),  "dangerous HTTP method(s) allowed",  "params/methods_vuln.txt"),
        ("notable",  n("origin/origins.txt"),       "confirmed origin IP(s) (CDN bypass)","origin/confirmed_origins.txt"),
        ("notable",  n("http/interesting.txt"),     "interesting service(s) exposed",    "http/interesting.txt"),
        ("notable",  n("ports/high_interest.txt"),  "high-risk open port(s)",            "ports/high_interest.txt"),
        ("candidate",n("params/ssrf_params.txt"),   "SSRF param candidate(s)",           "params/ssrf_params.txt"),
        ("candidate",n("params/idor_params.txt"),   "IDOR param candidate(s)",           "params/idor_params.txt"),
        ("candidate",n("params/lfi_params.txt"),    "LFI param candidate(s)",            "params/lfi_params.txt"),
        ("candidate",n("params/redirect_params.txt"),"open-redirect candidate(s)",       "params/redirect_params.txt"),
        ("candidate",n("urls/interesting_files.txt"),"interesting file URL(s)",          "urls/interesting_files.txt"),
        ("high",     n("headers/host_injection.txt"), "host-header injection potential(s)","headers/host_injection.txt"),
        ("high",     n("graphql/introspection_enabled.txt"),"GraphQL introspection enabled","graphql/introspection_enabled.txt"),
        ("high",     n("ssl/issues.txt"),             "TLS/SSL issue(s)",                 "ssl/issues.txt"),
    ]
    return [{"tier": t, "n": c, "label": l, "path": p} for t, c, l, p in rows if c > 0]

def _build_graph(data):
    """Build a force-graph node/edge payload from the collected recon data."""
    nodes = {}
    edges = []

    def add_node(key, label, ntype, sev=None, detail=""):
        if key not in nodes:
            nodes[key] = {"id": key, "lb": label[:42], "t": ntype,
                          "s": sev, "d": detail[:80]}
        return key

    def add_edge(src, tgt, rel=""):
        if src in nodes and tgt in nodes and src != tgt:
            edges.append({"s": src, "t": tgt, "r": rel})

    add_node("root", data["target"], "target")

    # subdomains — prioritise live ones
    alive_hosts = set()
    for a in data.get("alive", []):
        m = re.search(r"https?://([^/:]+)", a["url"])
        if m: alive_hosts.add(m.group(1))

    alive_subs = [s for s in data.get("hosts", []) if s     in alive_hosts]
    other_subs = [s for s in data.get("hosts", []) if s not in alive_hosts]
    host_map = {}
    for host in (alive_subs + other_subs)[:60]:
        k = "h:" + host
        add_node(k, host, "subdomain")
        host_map[host] = k
        add_edge("root", k)

    # services — mark those with findings
    finding_hosts = set()
    for f in data.get("findings", []):
        m = re.search(r"https?://([^/:]+)", f.get("url", ""))
        if m: finding_hosts.add(m.group(1))

    svc_map = {}
    for a in data.get("alive", [])[:40]:
        url  = a["url"]
        m    = re.search(r"https?://([^/:]+)", url)
        host = m.group(1) if m else None
        k    = "s:" + url[:60]
        lbl  = url.replace("https://", "").replace("http://", "")[:36]
        nt   = "svc-vuln" if (host in finding_hosts) else "service"
        add_node(k, lbl, nt, detail=a.get("title", "")[:60])
        svc_map[url] = k
        add_edge(host_map.get(host, "root"), k, "http")

    # nuclei findings (cap by severity so graph stays readable)
    caps = {"critical": 18, "high": 14, "medium": 10, "low": 5, "info": 3}
    seen = {k: 0 for k in caps}
    for f in data.get("findings", []):
        sev = f.get("sev", "info")
        if seen.get(sev, 0) >= caps.get(sev, 3): continue
        seen[sev] += 1
        tmpl = f.get("template", "finding")[:32]
        url  = f.get("url", "")
        k    = f"fn:{sev}:{tmpl}:{seen[sev]}"
        add_node(k, tmpl, "finding", sev=sev)
        m    = re.search(r"https?://([^/:]+)", url)
        host = m.group(1) if m else None
        parent = svc_map.get(url) or host_map.get(host) or "root"
        add_edge(parent, k, "vuln")

    # origin IPs (real backend)
    for o in data.get("origins", [])[:8]:
        k = "ip:" + o
        add_node(k, o, "origin")
        add_edge("root", k, "origin")

    # CDN/WAF challenges
    seen_chal = set()
    for c in data.get("challenges", [])[:15]:
        m    = re.search(r"https?://([^/:]+)", c["url"])
        host = m.group(1) if m else c["url"][:30]
        if host in seen_chal: continue
        seen_chal.add(host)
        k = "chal:" + host
        add_node(k, host[:30], "challenge", detail=c.get("vendor", ""))
        add_edge(host_map.get(host, "root"), k, "waf")

    # XSS findings
    for i, x in enumerate(data.get("xss", [])[:10]):
        m    = re.search(r"https?://([^/:]+)", x)
        host = m.group(1) if m else None
        k    = f"xss:{i}"
        add_node(k, "XSS", "xss", sev="critical", detail=x[:60])
        add_edge(host_map.get(host, "root"), k, "xss")

    # Subdomain takeovers
    for i, t in enumerate(data.get("takeovers", [])[:8]):
        host = t.split("/")[0].split(":")[0]
        k    = f"to:{i}"
        add_node(k, t[:30], "takeover", detail=t)
        add_edge(host_map.get(host, "root"), k, "takeover")

    # 403 bypasses
    for i, b in enumerate(data.get("bypasses", [])[:8]):
        m    = re.search(r"https?://([^/:]+)", b["url"])
        host = m.group(1) if m else None
        k    = f"bp:{i}"
        lbl  = (host or b["url"])[:28]
        add_node(k, lbl, "bypass", sev="high", detail=b.get("method", ""))
        parent = svc_map.get(b["url"]) or host_map.get(host) or "root"
        add_edge(parent, k, "bypass")

    # Public cloud buckets
    for i, bk in enumerate(data.get("open_buckets", [])[:6]):
        k = f"bk:{i}"
        add_node(k, bk[:30], "bucket", sev="critical", detail=bk)
        add_edge("root", k, "bucket")

    # GraphQL endpoints with introspection
    gql = data.get("graphql", {})
    for i, ep in enumerate(gql.get("endpoints", [])[:8]):
        url = ep.get("url", "")
        sev = "high" if ep.get("introspection") else None
        lbl = url.replace("https://", "").replace("http://", "")[:36]
        k   = f"gql:{i}"
        add_node(k, lbl, "graphql", sev=sev, detail="introspection ON" if ep.get("introspection") else "")
        m    = re.search(r"https?://([^/:]+)", url)
        host = m.group(1) if m else None
        parent = host_map.get(host, "root")
        add_edge(parent, k, "graphql")

    # SSL/TLS issues
    ssl = data.get("ssl", {})
    for i, iss in enumerate(ssl.get("issues", [])[:6]):
        host = iss.get("host", "")
        k    = f"ssl:{i}"
        add_node(k, host[:30], "ssl-issue", sev="high", detail=iss.get("issue", "")[:60])
        bare = host.split(":")[0]
        parent = host_map.get(bare, "root")
        add_edge(parent, k, "ssl")

    return {"nodes": list(nodes.values()), "edges": edges}


def collect(d, target, scope, passive, win_dir=None):
    abs_d   = os.path.abspath(d)
    sev     = _sev_counts(d)
    win     = win_dir or (_win_path(abs_d) if _is_wsl() else "")
    win_rpt = (win.rstrip("\\") + "\\report\\report.html") if win else ""
    furl    = _file_url(win_rpt)

    data = {
        "target":    target,
        "scope":     scope,
        "passive":   passive,
        "generated": datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"),
        "out_dir":   abs_d,
        "win_dir":   win,
        "win_rpt":   win_rpt,
        "file_url":  furl,

        "modules":   _state_modules(d),
        "triage":    _build_triage(d),

        "summary": {
            "hosts":     _count(os.path.join(d, "subdomains", "subs.txt")),
            "live":      _count(os.path.join(d, "http", "live_urls.txt")),
            "challenged":_count(os.path.join(d, "http", "challenged.txt")),
            "ports":     _count(os.path.join(d, "ports", "ports.txt")),
            "urls":      _count(os.path.join(d, "urls", "urls.txt")),
            "secrets":   _count(os.path.join(d, "js", "potential_secrets.txt")),
            "findings":  _count(os.path.join(d, "nuclei", "findings.txt")),
            "xss":       _count(os.path.join(d, "xss", "dalfox_results.txt")),
            "bypasses":  _count(os.path.join(d, "bypass403", "bypassed.txt")),
            "cors":      _count(os.path.join(d, "params", "cors_vuln.txt")),
            "takeovers": _count(os.path.join(d, "takeover", "takeovers.txt")),
            "buckets":   _count(os.path.join(d, "cloud", "open_buckets.txt")),
            "host_inj":  _count(os.path.join(d, "headers", "host_injection.txt")),
            "gql_eps":   _count(os.path.join(d, "graphql", "endpoints.txt")),
            "gql_intro": _count(os.path.join(d, "graphql", "introspection_enabled.txt")),
            "ssl_issues":_count(os.path.join(d, "ssl", "issues.txt")),
            "sev":       sev,
        },

        "alive":     _parse_alive(d),
        "findings":  _parse_findings(d),
        "ports":     _parse_ports(d),
        "challenges":_parse_challenges(d),
        "bypasses":  _parse_bypasses(d),
        "cors":      _parse_cors(d),
        "host_inj":  _parse_host_injection(d),
        "graphql":   _parse_graphql(d),
        "ssl":       _parse_ssl(d),

        "hosts":     _lines(os.path.join(d, "subdomains", "subs.txt")),
        "origins":   _lines(os.path.join(d, "origin", "confirmed_origins.txt")),
        "interesting":_lines(os.path.join(d, "http", "interesting.txt")),
        "secrets":   _lines(os.path.join(d, "js", "potential_secrets.txt")),
        "endpoints": _lines(os.path.join(d, "js", "endpoints.txt")),
        "xss":       _lines(os.path.join(d, "xss", "dalfox_results.txt")),
        "takeovers": _lines(os.path.join(d, "takeover", "takeovers.txt")),
        "methods":   _lines(os.path.join(d, "params", "methods_vuln.txt")),
        "open_buckets":_lines(os.path.join(d, "cloud", "open_buckets.txt")),
        "int_files": _lines(os.path.join(d, "urls", "interesting_files.txt")),

        "params": {
            "ssrf":     _lines(os.path.join(d, "params", "ssrf_params.txt")),
            "idor":     _lines(os.path.join(d, "params", "idor_params.txt")),
            "lfi":      _lines(os.path.join(d, "params", "lfi_params.txt")),
            "redirect": _lines(os.path.join(d, "params", "redirect_params.txt")),
        },
        "dorks": {
            "google": _lines(os.path.join(d, "dorks", "google_dorks.txt")),
            "github": _lines(os.path.join(d, "dorks", "github_dorks.txt")),
        },
    }
    data["graph"] = _build_graph(data)
    return data


# ── HTML template ─────────────────────────────────────────────────
_SHELL = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TANYA · __TARGET__</title>
<style>__CSS__</style>
</head>
<body>
<div id="app"></div>
<script type="application/json" id="D">__DATA__</script>
<script>__JS__</script>
</body>
</html>"""

_CSS = r"""
/* ── reset & variables ──────────────────────────────────────── */
:root {
  --bg:      #0d1117;
  --bg1:     #161b22;
  --bg2:     #1c2130;
  --bg3:     #21262d;
  --border:  #30363d;
  --ink:     #e6edf3;
  --ink2:    #8b949e;
  --ink3:    #484f58;

  --cyan:    #39c5cf;
  --cyan2:   #56d8e4;
  --green:   #3fb950;
  --yellow:  #d29922;
  --orange:  #f0883e;
  --red:     #f85149;
  --purple:  #bc8cff;
  --blue:    #388bfd;

  --crit:   #f85149;
  --high:   #f0883e;
  --med:    #d29922;
  --low:    #388bfd;
  --info:   #39c5cf;
  --cand:   #bc8cff;
  --notable:#56d8e4;

  --mono: ui-monospace,"Cascadia Code","JetBrains Mono","Fira Code",
          "SFMono-Regular",Menlo,Consolas,monospace;
  --r4: 4px; --r6: 6px; --r8: 8px; --r10: 10px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  background: var(--bg);
  color: var(--ink);
  font-family: var(--mono);
  font-size: 13px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--cyan); text-decoration: none; }
a:hover { text-decoration: underline; color: var(--cyan2); }
button { font-family: var(--mono); }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg1); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }

/* ── topbar ─────────────────────────────────────────────────── */
.topbar {
  position: sticky; top: 0; z-index: 50;
  background: rgba(13,17,23,.92);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}
.tb-inner {
  max-width: 1280px; margin: 0 auto;
  padding: 0 24px;
  height: 52px;
  display: flex; align-items: center; gap: 14px;
}
.brand {
  display: flex; align-items: baseline; gap: 8px;
  font-weight: 700; font-size: 15px; letter-spacing: .03em;
  color: var(--cyan); white-space: nowrap;
}
.brand .v { color: var(--ink3); font-size: 10px; font-weight: 400; }
.brand .cat { color: var(--ink2); font-size: 12px; }
.tb-sep { color: var(--border); }
.tb-target { font-weight: 700; color: var(--ink); }
.tb-pill {
  font-size: 10px; letter-spacing: .1em; text-transform: uppercase;
  border: 1px solid var(--border); border-radius: 99px;
  padding: 2px 9px; color: var(--ink2);
}
.tb-pill.passive { color: var(--orange); border-color: #3a2510; }
.tb-ts { color: var(--ink3); font-size: 11px; margin-left: auto; white-space: nowrap; }
.tb-search {
  display: flex; align-items: center; gap: 8px;
  background: var(--bg1); border: 1px solid var(--border);
  border-radius: var(--r6); padding: 5px 10px; min-width: 220px;
}
.tb-search:focus-within { border-color: var(--cyan); }
.tb-search input {
  background: none; border: none; color: var(--ink);
  font-family: var(--mono); font-size: 12px; outline: none; width: 100%;
}
.tb-search input::placeholder { color: var(--ink3); }
.kbd {
  color: var(--ink3); font-size: 10px;
  border: 1px solid var(--border); border-radius: var(--r4);
  padding: 1px 5px; flex: none;
}

/* ── page wrapper ───────────────────────────────────────────── */
.wrap { max-width: 1280px; margin: 0 auto; padding: 28px 24px 80px; }

/* ── hero (where to start) ──────────────────────────────────── */
.hero { margin-bottom: 24px; }
.hero-label {
  display: flex; align-items: center; gap: 8px;
  font-size: 10.5px; letter-spacing: .22em; text-transform: uppercase;
  color: var(--ink3); margin-bottom: 10px;
}
.hero-label::before {
  content: ''; display: block; width: 24px; height: 1px; background: var(--border);
}
.hero-label::after {
  content: ''; display: block; flex: 1; height: 1px; background: var(--border);
}
.hero-card {
  display: flex; gap: 0;
  border: 1px solid var(--border); border-radius: var(--r10);
  background: var(--bg1); overflow: hidden;
  transition: border-color .15s;
}
.hero-card:hover { border-color: var(--cyan); }
.hero-accent { width: 5px; flex: none; }
.hero-body { padding: 18px 22px; flex: 1; min-width: 0; }
.hero-tier {
  display: flex; align-items: center; gap: 8px;
  font-size: 10px; letter-spacing: .2em; text-transform: uppercase;
  color: var(--ink2); margin-bottom: 8px;
}
.pulse {
  display: inline-block; width: 7px; height: 7px;
  border-radius: 50%;
  animation: pulse 2s ease-in-out infinite;
}
@keyframes pulse {
  0%,100% { opacity: 1; transform: scale(1); }
  50%      { opacity: .3; transform: scale(.65); }
}
.hero-main {
  font-size: 22px; font-weight: 700; line-height: 1.2;
  letter-spacing: -.01em; margin-bottom: 6px;
}
.hero-path { color: var(--ink2); font-size: 12px; word-break: break-all; }
.hero-empty { color: var(--ink3); font-size: 14px; }

/* ── module pipeline ────────────────────────────────────────── */
.pipeline {
  display: flex; align-items: center;
  gap: 0; margin: 20px 0; overflow-x: auto;
  padding-bottom: 2px;
}
.pipe-node {
  display: flex; flex-direction: column; align-items: center;
  gap: 5px; flex: none;
}
.pipe-dot {
  width: 28px; height: 28px; border-radius: 50%;
  border: 2px solid var(--border);
  display: flex; align-items: center; justify-content: center;
  font-size: 10px; font-weight: 700;
  background: var(--bg); color: var(--ink3);
  transition: all .15s;
}
.pipe-node.done .pipe-dot {
  border-color: var(--cyan); color: var(--cyan);
  background: rgba(57,197,207,.1);
  box-shadow: 0 0 12px rgba(57,197,207,.25);
}
.pipe-lbl { font-size: 9.5px; color: var(--ink3); letter-spacing: .05em; }
.pipe-node.done .pipe-lbl { color: var(--ink2); }
.pipe-line {
  flex: 1; min-width: 14px; height: 2px;
  background: var(--border); margin-bottom: 17px;
}
.pipe-line.done { background: var(--cyan); opacity: .4; }

/* ── stat bar ───────────────────────────────────────────────── */
.statbar {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
  gap: 8px; margin: 20px 0;
}
.stat {
  background: var(--bg1); border: 1px solid var(--border);
  border-radius: var(--r8); padding: 12px 14px;
  transition: border-color .15s;
}
.stat:hover { border-color: var(--cyan); }
.stat .n {
  font-size: 22px; font-weight: 700;
  letter-spacing: -.02em; line-height: 1;
  color: var(--ink);
}
.stat .l {
  font-size: 10px; letter-spacing: .1em; text-transform: uppercase;
  color: var(--ink3); margin-top: 5px;
}
.stat.c-crit .n { color: var(--crit); }
.stat.c-high .n { color: var(--high); }
.stat.c-warn .n { color: var(--yellow); }
.stat.c-cyan .n { color: var(--cyan); }
.stat.c-ok   .n { color: var(--green); }

/* ── WSL bar ────────────────────────────────────────────────── */
.wslbar {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  background: var(--bg1); border: 1px solid var(--border);
  border-radius: var(--r8); padding: 9px 14px;
  font-size: 11.5px; color: var(--ink2); margin: 16px 0;
}
.wsl-badge {
  font-size: 9px; font-weight: 700; letter-spacing: .15em;
  text-transform: uppercase;
  background: rgba(57,197,207,.12); color: var(--cyan);
  border: 1px solid rgba(57,197,207,.3); border-radius: var(--r4);
  padding: 2px 7px; flex: none;
}
.wslbar code { color: var(--ink); word-break: break-all; }

/* ── section chrome ─────────────────────────────────────────── */
section {
  margin: 28px 0;
  scroll-margin-top: 62px;
}
.sec-head {
  display: flex; align-items: center; gap: 10px;
  margin-bottom: 10px; cursor: pointer; user-select: none;
}
.sec-icon { color: var(--cyan); font-size: 12px; }
.sec-title {
  font-size: 12px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; color: var(--ink);
}
.sec-cnt {
  font-size: 11px; color: var(--ink3);
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 99px; padding: 1px 8px;
}
.sec-chev {
  margin-left: auto; color: var(--ink3); font-size: 11px;
  transition: transform .15s;
}
.sec-head.closed .sec-chev { transform: rotate(-90deg); }
.sec-body {
  border: 1px solid var(--border); border-radius: var(--r10);
  background: var(--bg1); overflow: hidden;
}
.sec-head.closed + .sec-body { display: none; }
.empty-state {
  padding: 20px 18px; color: var(--ink3); font-size: 12px;
  display: flex; align-items: center; gap: 8px;
}
.empty-state::before { content: '—'; color: var(--border); }

/* ── severity pills (findings filter) ──────────────────────── */
.sev-pills {
  display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px;
}
.sev-pill {
  font-size: 10.5px; color: var(--ink2);
  background: var(--bg1); border: 1px solid var(--border);
  border-radius: 99px; padding: 3px 12px;
  cursor: pointer; letter-spacing: .04em; transition: all .12s;
}
.sev-pill:hover { color: var(--ink); border-color: var(--ink2); }
.sev-pill.on { color: var(--bg); font-weight: 700; }
.sev-pill[data-f="all"].on    { background: var(--ink);  border-color: var(--ink); }
.sev-pill[data-f="critical"].on { background: var(--crit); border-color: var(--crit); }
.sev-pill[data-f="high"].on   { background: var(--high); border-color: var(--high); }
.sev-pill[data-f="medium"].on { background: var(--med);  border-color: var(--med); }
.sev-pill[data-f="low"].on    { background: var(--low);  border-color: var(--low); }
.sev-pill[data-f="info"].on   { background: var(--info); border-color: var(--info); }

/* ── row: generic finding/item ──────────────────────────────── */
.row {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 10px 16px; border-top: 1px solid var(--border);
}
.row:first-child { border-top: none; }
.row-bar { width: 3px; align-self: stretch; border-radius: 99px; flex: none; }

.sev-badge {
  font-size: 9px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; border-radius: var(--r4);
  padding: 2px 7px; flex: none; white-space: nowrap;
}
.b-critical { background: rgba(248,81,73,.15);  color: var(--crit); }
.b-high     { background: rgba(240,136,62,.15); color: var(--high); }
.b-medium   { background: rgba(210,153,34,.15); color: var(--med);  }
.b-low      { background: rgba(56,139,253,.15); color: var(--low);  }
.b-info     { background: rgba(57,197,207,.12); color: var(--info); }
.b-notable  { background: rgba(86,216,228,.12); color: var(--notable); }
.b-candidate{ background: rgba(188,140,255,.12); color: var(--cand); }
.b-bypass   { background: rgba(240,136,62,.15); color: var(--high); }
.b-cors     { background: rgba(248,81,73,.15);  color: var(--crit); }
.b-xss      { background: rgba(248,81,73,.15);  color: var(--crit); }
.b-ssrf     { background: rgba(188,140,255,.12); color: var(--cand); }
.b-idor     { background: rgba(188,140,255,.12); color: var(--cand); }
.b-lfi      { background: rgba(188,140,255,.12); color: var(--cand); }
.b-redirect { background: rgba(188,140,255,.12); color: var(--cand); }

.row-body   { min-width: 0; flex: 1; }
.row-title  { font-weight: 700; word-break: break-all; }
.row-sub    { color: var(--ink2); font-size: 11.5px; margin-top: 2px; word-break: break-all; }
.row-meta   { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 5px; }

/* ── copy button ────────────────────────────────────────────── */
.cp {
  flex: none; margin-left: auto;
  background: none; border: 1px solid var(--border);
  color: var(--ink3); border-radius: var(--r4);
  font-size: 10px; padding: 3px 9px; cursor: pointer;
  transition: all .12s; white-space: nowrap;
}
.cp:hover { color: var(--ink); border-color: var(--cyan); }
.cp.ok    { color: var(--cyan); border-color: var(--cyan); }

/* ── table ──────────────────────────────────────────────────── */
.tbl { width: 100%; border-collapse: collapse; font-size: 12px; }
.tbl td {
  padding: 9px 16px; border-top: 1px solid var(--border);
  vertical-align: top; word-break: break-all;
}
.tbl tr:first-child td { border-top: none; }
.tbl tr:hover td { background: rgba(255,255,255,.015); }

/* ── chips / badges ─────────────────────────────────────────── */
.chip {
  display: inline-block; font-size: 10px;
  border: 1px solid var(--border); border-radius: var(--r4);
  padding: 1px 6px; color: var(--ink2);
  margin: 1px 2px 1px 0;
}
.chip.chal { color: var(--orange); border-color: rgba(240,136,62,.4); }
.chip.hot  { color: var(--crit);   border-color: rgba(248,81,73,.4);  }
.chip.ok   { color: var(--green);  border-color: rgba(63,185,80,.4);  }
.chip.c    { color: var(--cyan);   border-color: rgba(57,197,207,.3); }

.sc { font-weight: 700; }
.sc-2 { color: var(--green); }
.sc-3 { color: var(--cyan);  }
.sc-4 { color: var(--orange);}
.sc-5 { color: var(--crit);  }

/* ── mono list ──────────────────────────────────────────────── */
.mono-list { list-style: none; }
.mono-list li {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 16px; border-top: 1px solid var(--border);
  word-break: break-all;
}
.mono-list li:first-child { border-top: none; }
.mono-list li:hover { background: rgba(255,255,255,.015); }
.li-text { flex: 1; min-width: 0; }
.li-hot { color: var(--crit); font-weight: 700; }

/* ── dorks ──────────────────────────────────────────────────── */
.dork-header {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 16px; border-top: 1px solid var(--border);
  background: var(--bg2);
}
.dork-header:first-child { border-top: none; }
.dork-platform {
  font-size: 10px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; color: var(--cyan);
}
.dork-row {
  display: flex; align-items: center; gap: 10px;
  padding: 7px 16px; border-top: 1px solid var(--border);
}
.dork-row:hover { background: rgba(255,255,255,.015); }
.dork-row code { flex: 1; min-width: 0; color: var(--ink); word-break: break-all; }

/* ── footer ─────────────────────────────────────────────────── */
.footer {
  margin-top: 48px; padding-top: 18px;
  border-top: 1px solid var(--border);
  text-align: center; color: var(--ink3); font-size: 11px;
}
.footer .brand-f { color: var(--cyan); font-weight: 700; }
.footer .warn-f  { color: var(--orange); }

/* ── utilities ──────────────────────────────────────────────── */
.hide  { display: none !important; }
.hot   { color: var(--crit); font-weight: 700; }
.mt8   { margin-top: 8px; }
.gap6  { gap: 6px; }
.flex  { display: flex; }
.items-center { align-items: center; }

@media (max-width: 640px) {
  .tb-inner { padding: 0 14px; }
  .wrap     { padding: 18px 14px 60px; }
  .hero-main { font-size: 17px; }
  .pipeline  { gap: 0; }
  .pipe-lbl  { display: none; }
  .tb-ts    { display: none; }
}
@media (prefers-reduced-motion: reduce) {
  *, .pulse { animation: none !important; transition: none !important; }
}

/* ── attack surface map ─────────────────────────────────────── */
.graph-outer {
  border-radius: 0 0 var(--r10) var(--r10); overflow: hidden;
}
.graph-ctrl {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 8px 14px; background: var(--bg2);
  border-bottom: 1px solid var(--border);
}
.graph-ctrl-btn {
  background: var(--bg1); border: 1px solid var(--border);
  color: var(--ink2); font-family: var(--mono); font-size: 11px;
  border-radius: var(--r4); padding: 3px 10px; cursor: pointer;
  transition: all .12s;
}
.graph-ctrl-btn:hover { color: var(--cyan); border-color: var(--cyan); }
.graph-ctrl-btn.active { color: var(--cyan); border-color: var(--cyan); background: rgba(57,197,207,.08); }
.graph-ctrl-sep { flex: 1; }
.graph-hint { font-size: 10px; color: var(--ink3); }
.graph-wrap {
  position: relative; height: 560px;
  background: var(--bg); overflow: hidden;
}
.graph-canvas { width: 100%; height: 100%; cursor: grab; display: block; }
.graph-canvas:active { cursor: grabbing; }

.graph-legend {
  position: absolute; bottom: 10px; left: 12px;
  display: flex; flex-wrap: wrap; gap: 7px 12px;
  pointer-events: none; max-width: 340px;
}
.gl-item {
  display: flex; align-items: center; gap: 5px;
  font-size: 10px; color: var(--ink3); white-space: nowrap;
}
.gl-dot {
  width: 9px; height: 9px; border-radius: 50%;
  border: 1.5px solid; flex: none; opacity: .9;
}

.graph-detail {
  position: absolute; top: 0; right: 0; bottom: 0; width: 230px;
  background: rgba(13,17,23,.96); border-left: 1px solid var(--border);
  padding: 14px 14px 14px 16px; overflow-y: auto;
  transform: translateX(100%); transition: transform .18s ease;
  backdrop-filter: blur(10px);
}
.graph-detail.open { transform: translateX(0); }
.gd-close {
  position: absolute; top: 10px; right: 10px;
  background: none; border: none; color: var(--ink3);
  font-size: 16px; cursor: pointer; line-height: 1; font-family: var(--mono);
}
.gd-close:hover { color: var(--ink); }
.gd-type {
  font-size: 9px; font-weight: 700; letter-spacing: .2em;
  text-transform: uppercase; margin-bottom: 5px;
}
.gd-label {
  font-size: 13px; font-weight: 700; word-break: break-all;
  margin-bottom: 6px; line-height: 1.35; padding-right: 18px;
}
.gd-detail {
  font-size: 11px; color: var(--ink2); word-break: break-all;
  margin-bottom: 8px; line-height: 1.5;
}
.gd-sep { border: none; border-top: 1px solid var(--border); margin: 10px 0; }
.gd-sub {
  font-size: 9px; color: var(--ink3); letter-spacing: .12em;
  text-transform: uppercase; margin-bottom: 5px;
}
.gd-nbr {
  font-size: 11px; color: var(--ink2); padding: 3px 0;
  word-break: break-all; cursor: pointer;
}
.gd-nbr:hover { color: var(--cyan); }

@media (max-width: 640px) {
  .graph-wrap { height: 420px; }
  .graph-detail { width: 180px; }
  .graph-legend { display: none; }
}
"""

_JS = r"""
/* ── bootstrap ─────────────────────────────────────────────── */
const D = JSON.parse(document.getElementById('D').textContent);

const $ = (sel, ctx=document) => ctx.querySelector(sel);
const E = (tag, cls='', html='') => {
  const el = document.createElement(tag);
  if (cls)  el.className = cls;
  if (html) el.innerHTML = html;
  return el;
};
const esc = s => String(s ?? '').replace(/[&<>"]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

const SEV_COL = {
  critical:'var(--crit)', high:'var(--high)', medium:'var(--med)',
  low:'var(--low)', info:'var(--info)', notable:'var(--notable)',
  candidate:'var(--cand)',
};
const TIER_LBL = { critical:'CRITICAL', high:'HIGH', notable:'NOTABLE', candidate:'CANDIDATE' };

/* ── copy button ─────────────────────────────────────────────── */
function mkCopy(text) {
  const b = E('button', 'cp', 'copy');
  b.onclick = async ev => {
    ev.stopPropagation();
    try { await navigator.clipboard.writeText(text); }
    catch (_) {
      const t = document.createElement('textarea');
      t.value = text; document.body.appendChild(t); t.select();
      document.execCommand('copy'); t.remove();
    }
    b.textContent = 'copied ✓'; b.classList.add('ok');
    setTimeout(() => { b.textContent = 'copy'; b.classList.remove('ok'); }, 1200);
  };
  return b;
}

/* ── section builder ─────────────────────────────────────────── */
function mkSection(icon, title, count, id) {
  const sec  = E('section'); sec.id = 'sec-' + id;
  const head = E('div', 'sec-head');
  head.innerHTML = `
    <span class="sec-icon">${icon}</span>
    <span class="sec-title">${title}</span>
    <span class="sec-cnt">${count}</span>
    <span class="sec-chev">▾</span>`;
  head.onclick = () => head.classList.toggle('closed');
  const body = E('div', 'sec-body');
  sec.appendChild(head); sec.appendChild(body);
  wrap.appendChild(sec);
  return { sec, head, body };
}

function emptySection(s) {
  s.body.appendChild(E('div', 'empty-state', 'nothing here'));
  s.head.classList.add('closed');
}

function listSection(icon, title, items, id, extra='') {
  const s = mkSection(icon, title, items.length, id);
  if (!items.length) { emptySection(s); return s; }
  const ul = E('ul', 'mono-list');
  items.forEach(it => {
    const li = E('li');
    li.classList.add('sr');
    li.dataset.q = it.toLowerCase();
    const span = E('span', 'li-text ' + extra, esc(it));
    li.appendChild(span);
    li.appendChild(mkCopy(it));
    ul.appendChild(li);
  });
  s.body.appendChild(ul);
  return s;
}

/* ── app root ───────────────────────────────────────────────── */
const app  = document.getElementById('app');
const wrap = E('div', 'wrap');

/* ── topbar ─────────────────────────────────────────────────── */
const bar = E('div', 'topbar');
const sc  = D.passive ? 'tb-pill passive' : 'tb-pill';
bar.innerHTML = `
<div class="tb-inner">
  <div class="brand">
    ◆ TANYA<span class="v">v6.1</span>
    <span class="cat">≽ᴥ≼</span>
  </div>
  <span class="tb-sep">·</span>
  <span class="tb-target">${esc(D.target)}</span>
  <span class="${sc}">${esc(D.scope)}${D.passive ? ' · passive' : ''}</span>
  <span class="tb-ts">${esc(D.generated)}</span>
  <label class="tb-search">
    <input id="q" type="search" placeholder="search findings, hosts, urls…" autocomplete="off">
    <span class="kbd">/</span>
  </label>
</div>`;
app.appendChild(bar);
app.appendChild(wrap);

/* ── hero: WHERE TO START ────────────────────────────────────── */
{
  const top = D.triage[0];
  const hero = E('div', 'hero');
  if (top) {
    const col = SEV_COL[top.tier] || 'var(--cyan)';
    hero.innerHTML = `
      <div class="hero-label">◆ WHERE TO START — highest signal</div>
      <div class="hero-card">
        <div class="hero-accent" style="background:${col}"></div>
        <div class="hero-body">
          <div class="hero-tier">
            <span class="pulse" style="background:${col}"></span>
            ${TIER_LBL[top.tier] || top.tier.toUpperCase()} &nbsp;·&nbsp; ${D.triage.length} items in triage queue
          </div>
          <div class="hero-main" style="color:${col}">${top.n} ${esc(top.label)}</div>
          <div class="hero-path">◦ ${esc(D.out_dir)}/${esc(top.path)}</div>
        </div>
      </div>`;
  } else {
    hero.innerHTML = `
      <div class="hero-label">◆ WHERE TO START</div>
      <div class="hero-card">
        <div class="hero-accent" style="background:var(--ink3)"></div>
        <div class="hero-body">
          <div class="hero-tier"><span class="pulse" style="background:var(--ink3)"></span>no high-signal findings automatically flagged</div>
          <div class="hero-main hero-empty">Surface looks quiet</div>
          <div class="hero-path">Start from http/alive.txt and urls/urls.txt for manual review.</div>
        </div>
      </div>`;
  }
  wrap.appendChild(hero);
}

/* ── module pipeline ─────────────────────────────────────────── */
{
  const pipe = E('div', 'pipeline');
  D.modules.forEach((m, i) => {
    if (i > 0) {
      const line = E('div', 'pipe-line' + (m.done ? ' done' : ''));
      pipe.appendChild(line);
    }
    const node = E('div', 'pipe-node' + (m.done ? ' done' : ''));
    node.innerHTML = `
      <div class="pipe-dot">${m.done ? '✓' : (i+1)}</div>
      <div class="pipe-lbl">${esc(m.label)}</div>`;
    pipe.appendChild(node);
  });
  wrap.appendChild(pipe);
}

/* ── stat bar ────────────────────────────────────────────────── */
{
  const s    = D.summary;
  const crit = s.sev.critical, high = s.sev.high;
  const defs = [
    ['hosts',    'subdomains',    crit > 0 ? '' : high > 0 ? '' : 'c-cyan'],
    ['live',     'live services', ''],
    ['challenged','edge-blocked', s.challenged > 0 ? 'c-warn' : ''],
    ['findings', 'nuclei hits',   crit > 0 ? 'c-crit' : high > 0 ? 'c-high' : ''],
    ['secrets',  'js secrets',    s.secrets > 0 ? 'c-high' : ''],
    ['xss',      'xss hits',      s.xss > 0 ? 'c-crit' : ''],
    ['bypasses', '403 bypasses',  s.bypasses > 0 ? 'c-high' : ''],
    ['cors',     'cors misconfig',s.cors > 0 ? 'c-high' : ''],
    ['takeovers','takeovers',     s.takeovers > 0 ? 'c-crit' : ''],
    ['ports',    'open ports',    ''],
    ['urls',     'urls collected',''],
    ['buckets',  'public buckets',s.buckets > 0 ? 'c-crit' : ''],
    ['host_inj', 'host injection',s.host_inj > 0 ? 'c-high' : ''],
    ['gql_eps',  'graphql eps',   ''],
    ['gql_intro','gql introspect',s.gql_intro > 0 ? 'c-high' : ''],
    ['ssl_issues','ssl issues',   s.ssl_issues > 0 ? 'c-high' : ''],
  ];
  const bar = E('div', 'statbar');
  defs.forEach(([k, l, cls]) => {
    const card = E('div', 'stat ' + cls);
    card.innerHTML = `<div class="n">${s[k] ?? 0}</div><div class="l">${l}</div>`;
    bar.appendChild(card);
  });
  wrap.appendChild(bar);
}

/* ── WSL path bar ────────────────────────────────────────────── */
if (D.win_dir) {
  const wb = E('div', 'wslbar');
  const link = D.file_url
    ? ` &nbsp;·&nbsp; <a href="${esc(D.file_url)}">open in Windows browser ↗</a>` : '';
  wb.innerHTML = `<span class="wsl-badge">WSL</span>
    <code>${esc(D.win_dir)}</code>${link}`;
  wrap.appendChild(wb);
}

/* ── triage queue ────────────────────────────────────────────── */
{
  const s = mkSection('◆', 'Triage Queue', D.triage.length, 'triage');
  if (!D.triage.length) {
    emptySection(s);
  } else {
    D.triage.forEach(t => {
      const col = SEV_COL[t.tier] || 'var(--cyan)';
      const cls = { critical:'b-critical', high:'b-high', notable:'b-notable', candidate:'b-candidate' }[t.tier] || 'b-info';
      const row = E('div', 'row sr');
      row.dataset.q = (t.label + ' ' + t.path).toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:${col}"></div>
        <span class="sev-badge ${cls}">${TIER_LBL[t.tier]}</span>
        <div class="row-body">
          <div class="row-title">${t.n} ${esc(t.label)}</div>
          <div class="row-sub">◦ ${esc(t.path)}</div>
        </div>`;
      row.appendChild(mkCopy(D.out_dir + '/' + t.path));
      s.body.appendChild(row);
    });
  }
}

/* ── nuclei findings (severity filter) ──────────────────────── */
{
  const s = mkSection('⚡', 'Nuclei Findings', D.findings.length, 'findings');
  if (!D.findings.length) {
    emptySection(s);
  } else {
    const sv = D.summary.sev;
    const pills = E('div', 'sev-pills');
    [
      ['all',      `all  ${D.findings.length}`],
      ['critical', `critical  ${sv.critical}`],
      ['high',     `high  ${sv.high}`],
      ['medium',   `medium  ${sv.medium}`],
      ['low',      `low  ${sv.low}`],
      ['info',     `info  ${sv.info}`],
    ].forEach(([f, lbl]) => {
      const p = E('span', 'sev-pill' + (f === 'all' ? ' on' : ''));
      p.dataset.f = f; p.textContent = lbl;
      pills.appendChild(p);
    });
    s.head.after(pills);

    D.findings.forEach(f => {
      const col = SEV_COL[f.sev] || 'var(--info)';
      const cls = `b-${f.sev}`;
      const row = E('div', 'row sr finding');
      row.dataset.sev = f.sev;
      row.dataset.q   = f.raw.toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:${col}"></div>
        <span class="sev-badge ${cls}">${f.sev}</span>
        <div class="row-body">
          <div class="row-title">${esc(f.template || 'finding')}</div>
          <div class="row-sub">${f.url
            ? `<a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.url)}</a>`
            : esc(f.raw)}</div>
        </div>`;
      row.appendChild(mkCopy(f.raw));
      s.body.appendChild(row);
    });

    pills.addEventListener('click', e => {
      const p = e.target.closest('.sev-pill'); if (!p) return;
      pills.querySelectorAll('.sev-pill').forEach(x => x.classList.toggle('on', x === p));
      const f = p.dataset.f;
      s.body.querySelectorAll('.finding').forEach(r =>
        r.classList.toggle('hide', f !== 'all' && r.dataset.sev !== f));
    });
  }
}

/* ── live services ──────────────────────────────────────────── */
{
  const challenged = new Set(D.challenged || []);
  const s = mkSection('🌐', 'Live Services', D.alive.length, 'alive');
  if (!D.alive.length) {
    emptySection(s);
  } else {
    const tbl = E('table', 'tbl');
    D.alive.forEach(a => {
      const code = String(a.code);
      const cls  = { '2':'sc-2','3':'sc-3','4':'sc-4','5':'sc-5' }[code[0]] || '';
      const tech = a.tech.map(t => `<span class="chip">${esc(t)}</span>`).join('');
      const chl  = challenged.has(a.url)
        ? '<span class="chip chal">edge-challenged</span>' : '';
      const tr = E('tr', 'sr');
      tr.dataset.q = (a.url + ' ' + a.title + ' ' + a.tech.join(' ')).toLowerCase();
      tr.innerHTML = `
        <td style="width:55px"><span class="sc ${cls}">${esc(a.code)}</span></td>
        <td>
          <a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.url)}</a>
          ${a.title ? `<div class="row-sub">${esc(a.title)}</div>` : ''}
        </td>
        <td style="width:40%">${tech}${chl}</td>`;
      tbl.appendChild(tr);
    });
    s.body.appendChild(tbl);
  }
}

/* ── edge challenges ─────────────────────────────────────────── */
{
  const s = mkSection('🛡', 'Edge Challenges (CDN / WAF)', D.challenges.length, 'challenges');
  if (!D.challenges.length) {
    emptySection(s);
  } else {
    D.challenges.forEach(c => {
      const row = E('div', 'row sr');
      row.dataset.q = (c.url + ' ' + c.vendor).toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:var(--orange)"></div>
        <span class="sev-badge b-high">${esc(c.vendor || 'CDN')}</span>
        <div class="row-body">
          <div class="row-title">
            <a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.url)}</a>
          </div>
          <div class="row-sub">HTTP ${esc(c.code)} · active challenge page detected</div>
        </div>`;
      row.appendChild(mkCopy(c.url));
      s.body.appendChild(row);
    });
  }
}

/* ── confirmed origin IPs ────────────────────────────────────── */
listSection('🎯', 'Confirmed Origin IPs (CDN bypass)', D.origins, 'origins', 'li-hot');

/* ── interesting services ────────────────────────────────────── */
listSection('🔍', 'Interesting Services', D.interesting, 'interesting');

/* ── XSS findings ────────────────────────────────────────────── */
{
  const s = mkSection('💉', 'XSS Findings (dalfox)', D.xss.length, 'xss');
  if (!D.xss.length) {
    emptySection(s);
  } else {
    D.xss.forEach(ln => {
      const row = E('div', 'row sr');
      row.dataset.q = ln.toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:var(--crit)"></div>
        <span class="sev-badge b-xss">XSS</span>
        <div class="row-body"><div class="row-title">${esc(ln)}</div></div>`;
      row.appendChild(mkCopy(ln));
      s.body.appendChild(row);
    });
  }
}

/* ── 403 / 401 bypasses ──────────────────────────────────────── */
{
  const s = mkSection('🔓', '403 / 401 Bypasses', D.bypasses.length, 'bypass');
  if (!D.bypasses.length) {
    emptySection(s);
  } else {
    D.bypasses.forEach(b => {
      const row = E('div', 'row sr');
      row.dataset.q = (b.url + ' ' + b.method).toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:var(--high)"></div>
        <span class="sev-badge b-bypass">BYPASS</span>
        <div class="row-body">
          <div class="row-title">
            <a href="${esc(b.url)}" target="_blank" rel="noopener">${esc(b.url)}</a>
          </div>
          <div class="row-sub">${esc(b.method)}</div>
        </div>`;
      row.appendChild(mkCopy(b.url));
      s.body.appendChild(row);
    });
  }
}

/* ── CORS misconfigurations ──────────────────────────────────── */
{
  const s = mkSection('🌀', 'CORS Misconfigurations', D.cors.length, 'cors');
  if (!D.cors.length) {
    emptySection(s);
  } else {
    D.cors.forEach(c => {
      const row = E('div', 'row sr');
      row.dataset.q = c.url.toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:var(--crit)"></div>
        <span class="sev-badge b-cors">CORS</span>
        <div class="row-body">
          <div class="row-title">
            <a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.url)}</a>
          </div>
          <div class="row-sub">${esc(c.acao)} ${c.acac ? '· ' + esc(c.acac) : ''}</div>
        </div>`;
      row.appendChild(mkCopy(c.url));
      s.body.appendChild(row);
    });
  }
}

/* ── dangerous HTTP methods ──────────────────────────────────── */
listSection('⚠', 'Dangerous HTTP Methods', D.methods, 'methods', 'li-hot');

/* ── subdomain takeover ──────────────────────────────────────── */
listSection('🚩', 'Subdomain Takeover Candidates', D.takeovers, 'takeovers', 'li-hot');

/* ── open ports ──────────────────────────────────────────────── */
{
  const s = mkSection('🔌', 'Open Ports', D.ports.length, 'ports');
  if (!D.ports.length) {
    emptySection(s);
  } else {
    const tbl = E('table', 'tbl');
    D.ports.forEach(p => {
      const tr = E('tr', 'sr');
      tr.dataset.q = (p.host + ':' + p.port).toLowerCase();
      tr.innerHTML = `
        <td>${esc(p.host)}</td>
        <td style="width:80px">${p.high
          ? `<span class="hot">${esc(p.port)}</span>`
          : esc(p.port)}</td>
        <td style="width:130px">${p.high
          ? '<span class="chip hot">high-risk</span>' : ''}</td>`;
      tbl.appendChild(tr);
    });
    s.body.appendChild(tbl);
  }
}

/* ── JS secrets ──────────────────────────────────────────────── */
listSection('🔑', 'Potential JS Secrets', D.secrets, 'secrets', '');

/* ── JS endpoints ────────────────────────────────────────────── */
listSection('📡', 'JS Endpoints', D.endpoints, 'endpoints');

/* ── param candidates ────────────────────────────────────────── */
{
  const groups = [
    ['ssrf',     'SSRF',          'b-ssrf',    'var(--cand)'],
    ['idor',     'IDOR',          'b-idor',    'var(--cand)'],
    ['lfi',      'LFI',           'b-lfi',     'var(--cand)'],
    ['redirect', 'Open Redirect', 'b-redirect','var(--cand)'],
  ];
  const total = groups.reduce((a, [k]) => a + D.params[k].length, 0);
  const s = mkSection('🔎', 'Parameter Candidates', total, 'params');
  if (!total) {
    emptySection(s);
  } else {
    groups.forEach(([k, lbl, badge, col]) => {
      D.params[k].forEach(u => {
        const row = E('div', 'row sr');
        row.dataset.q = u.toLowerCase();
        row.innerHTML = `
          <div class="row-bar" style="background:${col}"></div>
          <span class="sev-badge ${badge}">${lbl}</span>
          <div class="row-body"><div class="row-title">${esc(u)}</div></div>`;
        row.appendChild(mkCopy(u));
        s.body.appendChild(row);
      });
    });
  }
}

/* ── interesting files ───────────────────────────────────────── */
listSection('📄', 'Interesting File URLs', D.int_files, 'intfiles');

/* ── public cloud buckets ────────────────────────────────────── */
listSection('☁', 'Public Cloud Buckets', D.open_buckets, 'buckets', 'li-hot');

/* ── dorks ───────────────────────────────────────────────────── */
{
  const total = D.dorks.google.length + D.dorks.github.length;
  const s = mkSection('🔬', 'Dorks', total, 'dorks');
  if (!total) {
    emptySection(s);
  } else {
    [['google', 'Google — paste into browser'],
     ['github', 'GitHub — paste into code search']].forEach(([k, lbl]) => {
      if (!D.dorks[k].length) return;
      const hdr = E('div', 'dork-header');
      hdr.innerHTML = `<span class="dork-platform">${lbl}</span>`;
      hdr.appendChild(mkCopy(D.dorks[k].join('\n')));
      s.body.appendChild(hdr);
      D.dorks[k].forEach(q => {
        const row = E('div', 'dork-row sr');
        row.dataset.q = q.toLowerCase();
        row.innerHTML = `<code>${esc(q)}</code>`;
        row.appendChild(mkCopy(q));
        s.body.appendChild(row);
      });
    });
  }
}

/* ── security headers / host injection ──────────────────────── */
{
  const total = D.host_inj.length;
  const s = mkSection('🛡', 'Security Header Audit', total, 'headers');
  if (!total) {
    emptySection(s);
  } else {
    D.host_inj.forEach(r => {
      const row = E('div', 'row sr');
      row.dataset.q = (r.url + ' ' + r.detail).toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:var(--high)"></div>
        <span class="sev-badge b-bypass">HOST-INJ</span>
        <div class="row-body">
          <div class="row-title">${esc(r.url)}</div>
          <div class="row-sub">${esc(r.detail)}</div>
        </div>`;
      row.appendChild(mkCopy(r.url));
      s.body.appendChild(row);
    });
  }
}

/* ── graphql recon ───────────────────────────────────────────── */
{
  const gql   = D.graphql;
  const total = gql.endpoints.length + gql.nuclei.length;
  const s = mkSection('⬡', 'GraphQL Recon', total, 'graphql');
  if (!total) {
    emptySection(s);
  } else {
    gql.endpoints.forEach(ep => {
      const row = E('div', 'row sr');
      row.dataset.q = ep.url.toLowerCase();
      const badge = ep.introspection
        ? '<span class="sev-badge b-bypass">INTROSPECT</span>'
        : '<span class="sev-badge b-info">ENDPOINT</span>';
      row.innerHTML = `
        <div class="row-bar" style="background:${ep.introspection ? 'var(--high)' : 'var(--info)'}"></div>
        ${badge}
        <div class="row-body"><div class="row-title">${esc(ep.url)}</div></div>`;
      row.appendChild(mkCopy(ep.url));
      s.body.appendChild(row);
    });
    if (gql.nuclei.length) {
      const hdr = E('div', 'dork-header');
      hdr.innerHTML = `<span class="dork-platform">Nuclei GraphQL findings</span>`;
      s.body.appendChild(hdr);
      gql.nuclei.forEach(ln => {
        const row = E('div', 'dork-row sr');
        row.dataset.q = ln.toLowerCase();
        row.innerHTML = `<code>${esc(ln)}</code>`;
        row.appendChild(mkCopy(ln));
        s.body.appendChild(row);
      });
    }
  }
}

/* ── ssl / tls analysis ──────────────────────────────────────── */
{
  const ssl   = D.ssl;
  const total = ssl.issues.length + ssl.nuclei.length;
  const s = mkSection('🔒', 'TLS / SSL Analysis', total, 'ssl');
  if (!total) {
    emptySection(s);
  } else {
    ssl.issues.forEach(r => {
      const row = E('div', 'row sr');
      row.dataset.q = (r.host + ' ' + r.issue).toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:var(--high)"></div>
        <span class="sev-badge b-bypass">TLS</span>
        <div class="row-body">
          <div class="row-title">${esc(r.host)}</div>
          <div class="row-sub">${esc(r.issue)}</div>
        </div>`;
      s.body.appendChild(row);
    });
    if (ssl.nuclei.length) {
      const hdr = E('div', 'dork-header');
      hdr.innerHTML = `<span class="dork-platform">Nuclei SSL/TLS findings</span>`;
      s.body.appendChild(hdr);
      ssl.nuclei.forEach(ln => {
        const row = E('div', 'dork-row sr');
        row.dataset.q = ln.toLowerCase();
        row.innerHTML = `<code>${esc(ln)}</code>`;
        row.appendChild(mkCopy(ln));
        s.body.appendChild(row);
      });
    }
  }
}

/* ── attack surface map ──────────────────────────────────────── */
{
  const GD = D.graph;
  if (GD && GD.nodes.length > 1) {

    const s = mkSection('🗺', 'Attack Surface Map',
      GD.nodes.length + ' nodes · ' + GD.edges.length + ' links', 'graph');
    s.head.querySelector('.sec-cnt').style.color = 'var(--cyan)';

    // Controls bar (inserted between head and body)
    const ctrl = E('div', 'graph-ctrl');
    ctrl.innerHTML = `
      <button class="graph-ctrl-btn" id="gc-recenter">⌖ recenter</button>
      <button class="graph-ctrl-btn" id="gc-heat">⚡ findings only</button>
      <span class="graph-ctrl-sep"></span>
      <span class="graph-hint">scroll=zoom  ·  drag=pan  ·  drag node=reposition  ·  click=inspect</span>`;
    s.body.before(ctrl);

    // Graph container
    const outer = E('div', 'graph-outer');
    const gwrap = E('div', 'graph-wrap');
    const canvas = E('canvas', 'graph-canvas');
    canvas.id = 'graph-canvas';

    // Legend
    const legend = E('div', 'graph-legend');
    [
      ['#39c5cf', '#39c5cf', 'target'],
      ['#388bfd', '#388bfd', 'subdomain'],
      ['#3fb950', '#3fb950', 'service'],
      ['#f0883e', '#f0883e', 'svc w/ findings'],
      ['#f85149', '#f85149', 'vuln / crit'],
      ['#d29922', '#d29922', 'medium'],
      ['#f85149', '#f85149', 'origin IP'],
      ['#8b949e', '#8b949e', 'CDN/WAF block'],
      ['#bc8cff', '#bc8cff', 'bypass / xss'],
    ].forEach(([stroke, fill, label]) => {
      const item = E('div', 'gl-item');
      item.innerHTML =
        `<div class="gl-dot" style="border-color:${stroke};background:${fill}22"></div>` +
        `<span>${label}</span>`;
      legend.appendChild(item);
    });

    // Detail panel
    const detailEl = E('div', 'graph-detail');
    detailEl.id = 'gd-panel';

    gwrap.appendChild(canvas);
    gwrap.appendChild(legend);
    gwrap.appendChild(detailEl);
    outer.appendChild(gwrap);
    s.body.appendChild(outer);

    /* ── ForceGraph ─────────────────────────────────────────── */
    class ForceGraph {
      constructor(canvas, detailEl, rawNodes, rawEdges) {
        this.canvas   = canvas;
        this.detailEl = detailEl;
        this.ctx      = canvas.getContext('2d');
        this.dpr      = Math.min(window.devicePixelRatio || 1, 2);

        this.nodes = rawNodes.map(n => ({...n, x:0,y:0,vx:0,vy:0}));
        this.edges = rawEdges;
        this.nById = Object.fromEntries(this.nodes.map(n => [n.id, n]));
        this.nbrs  = {};
        this.nodes.forEach(n => { this.nbrs[n.id] = new Set(); });
        this.edges.forEach(e => {
          this.nbrs[e.s]?.add(e.t);
          this.nbrs[e.t]?.add(e.s);
        });

        this.panX = 0; this.panY = 0; this.zoom = 1;
        this.drag = null; this.hover = null; this.sel = null;
        this.heat = false; this.ticks = 0;

        this._resize();
        this._scatter();
        this._bind();
        new ResizeObserver(() => { this._resize(); }).observe(canvas.parentElement);
        this._loop();
      }

      // ── layout ─────────────────────────────────────────────
      _scatter() {
        const W = this.cW, H = this.cH;
        const r = Math.min(W, H) * 0.37;
        const n = this.nodes.length || 1;
        this.nodes.forEach((nd, i) => {
          if (nd.t === 'target') { nd.x = W/2; nd.y = H/2; nd.vx=0;nd.vy=0; return; }
          const a = (i / n) * Math.PI * 2 + (Math.random()-.5)*.8;
          const d = r * (.35 + Math.random() * .65);
          nd.x = W/2 + d*Math.cos(a); nd.y = H/2 + d*Math.sin(a);
          nd.vx = 0; nd.vy = 0;
        });
        this.panX = 0; this.panY = 0; this.zoom = 1; this.ticks = 0;
      }

      _resize() {
        const rect = this.canvas.parentElement?.getBoundingClientRect();
        if (!rect || rect.width < 10) return;
        this.cW = rect.width; this.cH = rect.height;
        this.canvas.width  = this.cW * this.dpr;
        this.canvas.height = this.cH * this.dpr;
        this.canvas.style.width  = this.cW + 'px';
        this.canvas.style.height = this.cH + 'px';
      }

      // ── physics ────────────────────────────────────────────
      _step() {
        const ns = this.nodes;
        const KR = 5400, KS = 0.042, RL = 92, GR = 0.0025;
        const cx = this.cW/2, cy = this.cH/2;
        ns.forEach(n => { n.fx = 0; n.fy = 0; });

        // Coulomb repulsion (O(n²), capped n≤150)
        for (let i = 0; i < ns.length; i++) {
          for (let j = i+1; j < ns.length; j++) {
            const a = ns[i], b = ns[j];
            let dx = a.x-b.x, dy = a.y-b.y;
            const d2 = dx*dx + dy*dy + .5;
            const id = 1 / Math.sqrt(d2);
            const f  = KR / d2;
            dx *= id; dy *= id;
            a.fx += dx*f; a.fy += dy*f;
            b.fx -= dx*f; b.fy -= dy*f;
          }
        }

        // Hooke spring along edges
        this.edges.forEach(e => {
          const a = this.nById[e.s], b = this.nById[e.t];
          if (!a||!b) return;
          let dx = b.x-a.x, dy = b.y-a.y;
          const d = Math.sqrt(dx*dx+dy*dy) + .01;
          const f = (d-RL) * KS;
          dx/=d; dy/=d;
          a.fx += dx*f; a.fy += dy*f;
          b.fx -= dx*f; b.fy -= dy*f;
        });

        // Centre gravity + integrate
        const damp = this.ticks > 200 ? 0.78 : 0.88;
        ns.forEach(n => {
          if (n === this.drag) return;
          n.fx += (cx-n.x)*GR; n.fy += (cy-n.y)*GR;
          n.vx = (n.vx + n.fx) * damp;
          n.vy = (n.vy + n.fy) * damp;
          n.x  = Math.max(22, Math.min(this.cW-22, n.x + n.vx));
          n.y  = Math.max(22, Math.min(this.cH-22, n.y + n.vy));
        });
        this.ticks++;
      }

      // ── draw ───────────────────────────────────────────────
      _draw() {
        const ctx = this.ctx;
        const W = this.canvas.width, H = this.canvas.height;
        const d = this.dpr, z = this.zoom;
        ctx.setTransform(1,0,0,1,0,0);
        ctx.clearRect(0, 0, W, H);

        // Dot-grid background
        ctx.fillStyle = '#484f58';
        ctx.globalAlpha = .25;
        const gs = 28*d;
        for (let x=0; x<W; x+=gs) for (let y=0; y<H; y+=gs)
          ctx.fillRect(x, y, d, d);
        ctx.globalAlpha = 1;

        // Pan/zoom transform
        ctx.setTransform(z*d, 0, 0, z*d, this.panX*d, this.panY*d);

        const hasSel = !!this.sel;
        const heatSet = this.heat
          ? new Set(this.nodes.filter(n =>
              n.t==='finding'||n.t==='xss'||n.t==='takeover'||
              n.t==='bucket'||n.t==='bypass'||n.t==='origin').map(n=>n.id))
          : null;

        // ── Edges ─────────────────────────────────────────────
        this.edges.forEach(e => {
          const a = this.nById[e.s], b = this.nById[e.t];
          if (!a||!b) return;
          if (heatSet && !heatSet.has(e.s) && !heatSet.has(e.t)) return;
          const conn = hasSel && (e.s===this.sel?.id || e.t===this.sel?.id);
          const dim  = (hasSel && !conn) || (heatSet && !heatSet.has(e.s) && !heatSet.has(e.t));
          const [ec, edash] = this._edgeStyle(e.r);

          ctx.beginPath();
          ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = conn ? ec : ec;
          ctx.lineWidth   = conn ? 1.8 : 0.75;
          ctx.setLineDash(edash);
          ctx.globalAlpha = dim ? 0.06 : conn ? 0.85 : 0.28;
          ctx.stroke();

          // arrowhead for connected edges
          if (conn) {
            const dx=b.x-a.x, dy=b.y-a.y, dl=Math.sqrt(dx*dx+dy*dy)||1;
            const r2 = this._nr(b)+2;
            const tx=b.x-(dx/dl)*r2, ty=b.y-(dy/dl)*r2;
            const nx=-dy/dl*5, ny=dx/dl*5;
            ctx.beginPath();
            ctx.moveTo(tx,ty);
            ctx.lineTo(tx-(dx/dl)*9+nx, ty-(dy/dl)*9+ny);
            ctx.lineTo(tx-(dx/dl)*9-nx, ty-(dy/dl)*9-ny);
            ctx.closePath();
            ctx.fillStyle = ec; ctx.globalAlpha = .8; ctx.fill();
          }
          ctx.setLineDash([]); ctx.globalAlpha = 1;
        });

        // ── Nodes ─────────────────────────────────────────────
        this.nodes.forEach(n => {
          if (heatSet && !heatSet.has(n.id) && n.t!=='target') return;
          const r    = this._nr(n);
          const col  = this._nc(n);
          const isHv = n===this.hover;
          const isSl = n===this.sel;
          const isNb = hasSel && this.nbrs[this.sel?.id]?.has(n.id);
          const dim  = hasSel && !isSl && !isNb;

          ctx.globalAlpha = dim ? .12 : 1;

          // Outer glow ring
          if (isSl || isHv) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, r+5, 0, Math.PI*2);
            ctx.strokeStyle = col; ctx.lineWidth = 1.5;
            ctx.globalAlpha = dim ? .04 : .35;
            ctx.stroke();
            ctx.globalAlpha = dim ? .12 : 1;
          }

          // Fill (radial gradient)
          const grad = ctx.createRadialGradient(n.x,n.y-r*.25,0, n.x,n.y,r);
          grad.addColorStop(0, col+'44');
          grad.addColorStop(1, col+'10');
          ctx.beginPath();
          ctx.arc(n.x, n.y, r, 0, Math.PI*2);
          ctx.fillStyle   = grad;
          ctx.strokeStyle = col;
          ctx.lineWidth   = isSl ? 2.2 : 1.3;
          ctx.fill(); ctx.stroke();

          // Icon inside node
          const icons = {target:'◆', origin:'●', takeover:'⚠',
                         xss:'✕', bucket:'☁', bypass:'↻'};
          const ic = icons[n.t];
          if (ic) {
            ctx.font = `bold ${Math.round(r*.75)}px ui-monospace,monospace`;
            ctx.fillStyle = col; ctx.textAlign='center'; ctx.textBaseline='middle';
            ctx.globalAlpha = dim ? .12 : .88;
            ctx.fillText(ic, n.x, n.y);
          }
          ctx.globalAlpha = dim ? .12 : 1;

          // Label
          if (!dim || isHv || isSl) {
            const lbl = n.lb || '';
            const txt = lbl.length>23 ? lbl.slice(0,22)+'…' : lbl;
            const fs  = Math.max(9, Math.min(11, r+1));
            ctx.font  = `${isSl?'bold ':''}${fs}px ui-monospace,monospace`;
            ctx.textAlign='center'; ctx.textBaseline='top';
            const tw = ctx.measureText(txt).width;
            // bg rect for readability
            ctx.fillStyle = 'rgba(13,17,23,.82)';
            ctx.fillRect(n.x-tw/2-2, n.y+r+4, tw+4, fs+2);
            ctx.fillStyle = isHv||isSl ? '#e6edf3' : this._labelCol(n);
            ctx.fillText(txt, n.x, n.y+r+5);
          }
          ctx.globalAlpha = 1;
        });
      }

      // ── styling helpers ─────────────────────────────────────
      _nr(n) {
        if (n.t==='target')    return 21;
        if (n.t==='origin')    return 14;
        if (n.t==='takeover')  return 12;
        if (n.t==='xss')       return 11;
        if (n.t==='bucket')    return 11;
        if (n.t==='bypass')    return 10;
        if (n.t==='svc-vuln')  return 10;
        if (n.t==='service')   return 9;
        if (n.t==='challenge') return 8;
        if (n.t==='finding')
          return {critical:13,high:11,medium:9,low:8,info:7}[n.s]||8;
        return 7;
      }

      _nc(n) {
        const m = {
          target:'#39c5cf', subdomain:'#388bfd', service:'#3fb950',
          'svc-vuln':'#f0883e', origin:'#f85149', challenge:'#8b949e',
          xss:'#f85149', takeover:'#f85149', bypass:'#f0883e',
          graphql:'#56d8e4', 'ssl-issue':'#f0883e',
          bucket:'#f85149',
        };
        if (n.t==='finding')
          return {critical:'#f85149',high:'#f0883e',medium:'#d29922',
                  low:'#388bfd',info:'#39c5cf'}[n.s]||'#8b949e';
        return m[n.t]||'#8b949e';
      }

      _labelCol(n) {
        if (['origin','xss','takeover','bucket'].includes(n.t)) return '#f85149';
        if (n.t==='target')    return '#39c5cf';
        if (n.t==='svc-vuln')  return '#f0883e';
        if (n.t==='finding'&&n.s==='critical') return '#f85149';
        if (n.t==='finding'&&n.s==='high')     return '#f0883e';
        return '#8b949e';
      }

      _edgeStyle(rel) {
        const cols = {
          vuln:'#f85149',xss:'#f85149',takeover:'#f85149',bucket:'#f85149',
          bypass:'#f0883e',origin:'#f0883e',waf:'#484f58',http:'#388bfd',
        };
        const dash = {vuln:[5,4],origin:[6,4],waf:[3,5],bypass:[4,4]};
        return [cols[rel]||'#484f58', dash[rel]||[]];
      }

      // ── interaction ─────────────────────────────────────────
      _cvPos(ev) {
        const r = this.canvas.getBoundingClientRect();
        return [ev.clientX-r.left, ev.clientY-r.top];
      }

      _world(sx, sy) {
        return [(sx-this.panX)/this.zoom, (sy-this.panY)/this.zoom];
      }

      _hit(sx, sy) {
        const [wx,wy] = this._world(sx,sy);
        let best=null, bestD=22;
        this.nodes.forEach(n => {
          const d = Math.hypot(n.x-wx, n.y-wy);
          if (d < this._nr(n)+8 && d < bestD+this._nr(n)) { best=n; bestD=d; }
        });
        return best;
      }

      _bind() {
        const c = this.canvas;
        let lastP=null, panning=false, startP=null;

        c.addEventListener('mousemove', ev => {
          const [cx,cy] = this._cvPos(ev);
          if (this.drag) {
            const [wx,wy] = this._world(cx,cy);
            this.drag.x=wx; this.drag.y=wy; this.drag.vx=0; this.drag.vy=0;
          } else if (panning && lastP) {
            this.panX += cx-lastP[0]; this.panY += cy-lastP[1];
          } else {
            this.hover = this._hit(cx,cy);
            c.style.cursor = this.hover ? 'pointer' : 'grab';
          }
          lastP = [cx,cy];
        });

        c.addEventListener('mousedown', ev => {
          const [cx,cy] = this._cvPos(ev);
          const n = this._hit(cx,cy);
          if (n) { this.drag=n; c.style.cursor='grabbing'; }
          else   { panning=true; c.style.cursor='grabbing'; }
          startP=[cx,cy]; lastP=[cx,cy];
        });

        c.addEventListener('mouseup', ev => {
          const [cx,cy] = this._cvPos(ev);
          if (this.drag && startP && Math.hypot(cx-startP[0],cy-startP[1])<6) {
            this._select(this.drag);
          }
          this.drag=null; panning=false;
          c.style.cursor = this.hover ? 'pointer' : 'grab';
        });

        c.addEventListener('click', ev => {
          if (!this.drag) {
            const [cx,cy] = this._cvPos(ev);
            const n = this._hit(cx,cy);
            if (!n) { this.sel=null; this.detailEl.classList.remove('open'); }
          }
        });

        c.addEventListener('wheel', ev => {
          ev.preventDefault();
          const [cx,cy] = this._cvPos(ev);
          const f = ev.deltaY<0 ? 1.12 : 0.89;
          const nz = Math.max(.12, Math.min(5, this.zoom*f));
          // zoom toward cursor point
          const [wx,wy] = this._world(cx,cy);
          this.zoom = nz;
          this.panX = cx - wx*nz; this.panY = cy - wy*nz;
        }, {passive:false});

        c.addEventListener('mouseleave', () => {
          this.hover=null; this.drag=null; panning=false;
        });

        // Touch (basic pinch-pan)
        let t0=null;
        c.addEventListener('touchstart', ev => {
          ev.preventDefault();
          if (ev.touches.length===1) {
            const t=ev.touches[0];
            const [cx,cy] = this._cvPos(t);
            const n = this._hit(cx,cy);
            if (n) { this.drag=n; } else { panning=true; }
            t0=[cx,cy]; lastP=[cx,cy];
          }
        },{passive:false});

        c.addEventListener('touchmove', ev => {
          ev.preventDefault();
          if (ev.touches.length===1) {
            const t=ev.touches[0];
            const [cx,cy] = this._cvPos(t);
            if (this.drag) {
              const [wx,wy]=this._world(cx,cy);
              this.drag.x=wx; this.drag.y=wy;
            } else if (panning&&lastP) {
              this.panX+=cx-lastP[0]; this.panY+=cy-lastP[1];
            }
            lastP=[cx,cy];
          }
        },{passive:false});

        c.addEventListener('touchend', ev => {
          if (this.drag&&t0) {
            const t=ev.changedTouches[0];
            const [cx,cy]=this._cvPos(t);
            if (Math.hypot(cx-t0[0],cy-t0[1])<8) this._select(this.drag);
          }
          this.drag=null; panning=false;
        });
      }

      _select(n) {
        this.sel = n;
        const d = this.detailEl;
        const col = this._nc(n);
        const TYPE_LBL = {
          target:'TARGET', subdomain:'SUBDOMAIN', service:'SERVICE',
          'svc-vuln':'SERVICE  w/  VULN', finding:'FINDING',
          origin:'ORIGIN IP', challenge:'CDN / WAF BLOCK',
          xss:'XSS', takeover:'TAKEOVER', bypass:'403 BYPASS', bucket:'OPEN BUCKET',
          graphql:'GRAPHQL ENDPOINT', 'ssl-issue':'TLS / SSL ISSUE',
        };
        const connIds = [...(this.nbrs[n.id]||[])];
        const nbrsHtml = connIds.slice(0,12).map(id => {
          const nb = this.nById[id];
          if (!nb) return '';
          return `<div class="gd-nbr" data-nid="${esc(id)}">${esc(nb.lb||id)}</div>`;
        }).join('');

        d.innerHTML = `
          <button class="gd-close" id="gd-x">×</button>
          <div class="gd-type" style="color:${col}">${TYPE_LBL[n.t]||n.t}</div>
          <div class="gd-label" style="color:${col}">${esc(n.lb||n.id)}</div>
          ${n.d ? `<div class="gd-detail">${esc(n.d)}</div>` : ''}
          ${n.s ? `<div class="gd-detail"><span class="sev-badge b-${esc(n.s)}">${n.s}</span></div>` : ''}
          <hr class="gd-sep">
          <div class="gd-sub">connected nodes (${connIds.length})</div>
          ${nbrsHtml||'<div class="gd-nbr" style="color:var(--ink3)">none</div>'}`;

        d.querySelector('#gd-x').onclick = () => {
          d.classList.remove('open'); this.sel=null;
        };
        d.querySelectorAll('.gd-nbr[data-nid]').forEach(el => {
          el.onclick = () => {
            const nb = this.nById[el.dataset.nid];
            if (nb) this._select(nb);
          };
        });
        d.classList.add('open');
      }

      // ── public ──────────────────────────────────────────────
      recenter() { this._scatter(); }

      toggleHeat() {
        this.heat = !this.heat;
        return this.heat;
      }

      // ── loop ────────────────────────────────────────────────
      _loop() {
        if (this.ticks < 500) this._step();
        this._draw();
        requestAnimationFrame(() => this._loop());
      }
    }

    /* kick off */
    const fg = new ForceGraph(canvas, detailEl, GD.nodes, GD.edges);

    document.getElementById('gc-recenter').onclick = () => fg.recenter();
    document.getElementById('gc-heat').onclick = function() {
      const on = fg.toggleHeat();
      this.classList.toggle('active', on);
      this.textContent = on ? '⚡ show all' : '⚡ findings only';
    };
  }
}

/* ── footer ──────────────────────────────────────────────────── */
{
  const wslLine = D.win_dir
    ? `<br>${esc(D.win_dir)}${D.file_url
        ? ` · <a href="${esc(D.file_url)}">open in Windows browser</a>` : ''}` : '';
  wrap.appendChild(E('div', 'footer', `
    <span class="brand-f">TANYA</span>  v6.1  ·  ${esc(D.generated)}
    <br>${esc(D.out_dir)}${wslLine}
    <br><span class="warn-f">authorized targets only</span>
     — this report is signal, not proof. verify every finding manually before reporting.
  `));
}

/* ── global search ────────────────────────────────────────────── */
const qEl = document.getElementById('q');
qEl.addEventListener('input', () => {
  const v = qEl.value.trim().toLowerCase();
  document.querySelectorAll('.sr').forEach(el => {
    el.classList.toggle('hide', !!v && !(el.dataset.q || '').includes(v));
  });
  document.querySelectorAll('section').forEach(sec => {
    const items = sec.querySelectorAll('.sr');
    if (!items.length) return;
    const any = [...items].some(i => !i.classList.contains('hide'));
    sec.classList.toggle('hide', !!v && !any);
  });
});
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement !== qEl) {
    e.preventDefault(); qEl.focus();
  }
  if (e.key === 'Escape' && document.activeElement === qEl) {
    qEl.value = ''; qEl.dispatchEvent(new Event('input')); qEl.blur();
  }
});
"""

# ── render ────────────────────────────────────────────────────────
def render(data):
    payload = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    return (_SHELL
            .replace("__CSS__",    _CSS)
            .replace("__JS__",     _JS)
            .replace("__DATA__",   payload)
            .replace("__TARGET__", _html.escape(data["target"])))

# ── CLI ───────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Generate an HTML recon report from a tanya.sh output directory"
    )
    ap.add_argument("out_dir")
    ap.add_argument("--out",     default=None)
    ap.add_argument("--target",  default=None)
    ap.add_argument("--scope",   default="apex")
    ap.add_argument("--passive", action="store_true")
    ap.add_argument("--win-dir", default=None)
    a = ap.parse_args()

    d = a.out_dir.rstrip("/")
    if not os.path.isdir(d):
        sys.stderr.write(f"not a directory: {d}\n")
        sys.exit(2)

    target = a.target or re.sub(r"_\d{8}_\d{6}$", "", os.path.basename(d)) or d

    data    = collect(d, target, a.scope, a.passive, win_dir=a.win_dir)
    out     = a.out or os.path.join(d, "report", "report.html")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(render(data))
    print(out)

if __name__ == "__main__":
    main()
