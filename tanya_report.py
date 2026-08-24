#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ================================================================
#  tanya_report.py  v3.3  —  HTML report for tanya
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
    for ln in _lines(os.path.join(d, "http", "challenged.txt")):
        rows.append({"url": ln, "code": "", "vendor": "CDN/WAF"})
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
    for ln in _lines(os.path.join(d, "headers", "cors_issues.txt")):
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

def _parse_page_js_map(d):
    path = os.path.join(d, "js", "page_js_map.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f) or []
    except Exception:
        return []

def _read_site_tree(d):
    path = os.path.join(d, "urls", "site_tree.txt")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().rstrip()
    except Exception:
        return ""

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
        ("high",     n("headers/cors_issues.txt"),   "CORS misconfiguration(s)",          "headers/cors_issues.txt"),
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
        ("high",     n("js/sinks.txt"),               "DOM XSS sink(s) in JS",            "js/sinks.txt"),
        ("high",     n("js/sourcemaps.txt"),          "source map(s) exposed",            "js/sourcemaps.txt"),
        ("notable",  n("js/admin_routes.txt"),        "admin/internal route(s) in JS",    "js/admin_routes.txt"),
        ("notable",  n("js/cloud_assets.txt"),        "cloud asset(s) found in JS",       "js/cloud_assets.txt"),
        ("notable",  n("js/subdomains.txt"),          "subdomain(s) discovered via JS",   "js/subdomains.txt"),
        ("candidate",n("js/html_comments.txt"),       "HTML comment(s) w/ sensitive info","js/html_comments.txt"),
        ("candidate",n("js/graphql.txt"),             "GraphQL pattern(s) in JS",         "js/graphql.txt"),
    ]
    return [{"tier": t, "n": c, "label": l, "path": p} for t, c, l, p in rows if c > 0]

def _build_graph(data):
    """Build attack surface map graph payload."""
    nodes = {}
    edges = []
    _edge_set = set()

    def add_node(key, label, ntype, sev=None, detail="", url="", meta=None):
        if key not in nodes:
            nodes[key] = {
                "id": key, "lb": label[:50], "t": ntype,
                "s": sev, "d": detail[:140], "u": url[:200],
                "m": meta or {}, "deg": 0,
            }
        return key

    def add_edge(src, tgt, rel=""):
        if src in nodes and tgt in nodes and src != tgt:
            k = src + "→" + tgt
            if k not in _edge_set:
                _edge_set.add(k)
                edges.append({"s": src, "t": tgt, "r": rel})
                nodes[src]["deg"] += 1
                nodes[tgt]["deg"] += 1

    add_node("root", data["target"], "target",
             url=f"https://{data['target']}",
             detail=f"Scan target · scope: {data.get('scope','apex')}")

    # subdomains — track live ones with metadata
    alive_info = {}
    for a in data.get("alive", []):
        m = re.search(r"https?://([^/:]+)", a["url"])
        if m:
            h = m.group(1)
            if h not in alive_info:
                alive_info[h] = {
                    "url": a["url"], "code": str(a.get("code", "")),
                    "title": a.get("title", ""), "tech": a.get("tech", []),
                }

    finding_hosts = set()
    for f in data.get("findings", []):
        m = re.search(r"https?://([^/:]+)", f.get("url", ""))
        if m: finding_hosts.add(m.group(1))

    host_map = {}
    alive_subs = [s for s in data.get("hosts", []) if s in alive_info]
    other_subs = [s for s in data.get("hosts", []) if s not in alive_info]

    for host in (alive_subs + other_subs)[:80]:
        k    = "h:" + host
        info = alive_info.get(host)
        tech = ", ".join((info["tech"] or [])[:4]) if info else ""
        if info:
            detail = f"HTTP {info['code']}"
            if info["title"]: detail += f" · {info['title'][:60]}"
            if tech: detail += f" · {tech}"
        else:
            detail = "not seen as live"
        add_node(k, host, "subdomain",
                 url=f"https://{host}" if info else "",
                 detail=detail,
                 meta={"live": bool(info), "vulns": host in finding_hosts,
                       "code": info["code"] if info else ""})
        host_map[host] = k
        add_edge("root", k)

    # services (live URLs)
    svc_map = {}
    for a in data.get("alive", [])[:60]:
        url  = a["url"]
        m    = re.search(r"https?://([^/:]+)", url)
        host = m.group(1) if m else None
        k    = "s:" + url[:64]
        lbl  = url.replace("https://", "").replace("http://", "")[:42]
        code = str(a.get("code", "?"))
        tech = ", ".join((a.get("tech") or [])[:4])
        detail = f"HTTP {code}"
        if a.get("title"): detail += f" · {a['title'][:70]}"
        if tech: detail += f" · {tech}"
        nt   = "svc-vuln" if (host in finding_hosts) else "service"
        add_node(k, lbl, nt, url=url, detail=detail,
                 meta={"code": code, "tech": tech, "title": a.get("title","")})
        svc_map[url] = k
        add_edge(host_map.get(host, "root"), k, "http")

    # nuclei findings
    caps = {"critical": 22, "high": 18, "medium": 12, "low": 6, "info": 4}
    seen = {k: 0 for k in caps}
    for f in data.get("findings", []):
        sev = f.get("sev", "info")
        if seen.get(sev, 0) >= caps.get(sev, 4): continue
        seen[sev] += 1
        tmpl = f.get("template", "finding")[:42]
        url  = f.get("url", "")
        k    = f"fn:{sev}:{tmpl}:{seen[sev]}"
        detail = f"[{sev.upper()}] {tmpl}"
        if url: detail += f" → {url[:80]}"
        add_node(k, tmpl, "finding", sev=sev, url=url, detail=detail)
        m    = re.search(r"https?://([^/:]+)", url)
        host = m.group(1) if m else None
        parent = svc_map.get(url) or host_map.get(host) or "root"
        add_edge(parent, k, "vuln")

    # origin IPs
    for o in data.get("origins", [])[:10]:
        k = "ip:" + o
        add_node(k, o, "origin",
                 url=f"http://{o}",
                 detail="Confirmed real-backend IP — CDN bypassed")
        add_edge("root", k, "origin")

    # CDN/WAF challenges
    seen_chal = set()
    for c in data.get("challenges", [])[:20]:
        m    = re.search(r"https?://([^/:]+)", c["url"])
        host = m.group(1) if m else c["url"][:36]
        if host in seen_chal: continue
        seen_chal.add(host)
        k = "chal:" + host
        vendor = c.get("vendor", "CDN/WAF")
        add_node(k, host[:40], "challenge",
                 url=c["url"],
                 detail=f"Challenge page · {vendor} · not directly scannable")
        add_edge(host_map.get(host, "root"), k, "waf")

    # XSS findings
    for i, x in enumerate(data.get("xss", [])[:12]):
        m    = re.search(r"https?://([^/:]+)", x)
        host = m.group(1) if m else None
        um   = re.search(r"(https?://\S+)", x)
        url  = um.group(1) if um else ""
        k    = f"xss:{i}"
        add_node(k, f"XSS #{i+1}", "xss", sev="critical",
                 url=url, detail=x[:120])
        add_edge(host_map.get(host, "root"), k, "xss")

    # Subdomain takeovers
    for i, t in enumerate(data.get("takeovers", [])[:10]):
        host = t.split("/")[0].split(":")[0]
        k    = f"to:{i}"
        add_node(k, t[:40], "takeover",
                 url=f"https://{host}",
                 detail=f"Subdomain takeover candidate — CNAME points to unclaimed service")
        add_edge(host_map.get(host, "root"), k, "takeover")

    # 403 bypasses
    for i, b in enumerate(data.get("bypasses", [])[:10]):
        m    = re.search(r"https?://([^/:]+)", b["url"])
        host = m.group(1) if m else None
        k    = f"bp:{i}"
        lbl  = b["url"].replace("https://","").replace("http://","")[:38]
        add_node(k, lbl, "bypass", sev="high",
                 url=b["url"],
                 detail=f"403/401 bypass confirmed · technique: {b.get('method','?')[:80]}")
        parent = svc_map.get(b["url"]) or host_map.get(host) or "root"
        add_edge(parent, k, "bypass")

    # Open cloud buckets
    for i, bk in enumerate(data.get("open_buckets", [])[:8]):
        k = f"bk:{i}"
        add_node(k, bk[:40], "bucket", sev="critical",
                 url=bk,
                 detail="Publicly accessible cloud storage bucket")
        add_edge("root", k, "bucket")

    # GraphQL endpoints
    gql = data.get("graphql", {})
    for i, ep in enumerate(gql.get("endpoints", [])[:10]):
        url  = ep.get("url", "")
        sev  = "high" if ep.get("introspection") else None
        lbl  = url.replace("https://","").replace("http://","")[:40]
        k    = f"gql:{i}"
        intro = " · introspection ENABLED (schema exposed)" if ep.get("introspection") else ""
        add_node(k, lbl, "graphql", sev=sev,
                 url=url, detail=f"GraphQL endpoint{intro}")
        m    = re.search(r"https?://([^/:]+)", url)
        host = m.group(1) if m else None
        add_edge(host_map.get(host, "root"), k, "graphql")

    # SSL/TLS issues
    ssl = data.get("ssl", {})
    for i, iss in enumerate(ssl.get("issues", [])[:8]):
        host = iss.get("host", "")
        k    = f"ssl:{i}"
        add_node(k, host[:40], "ssl-issue", sev="high",
                 url=f"https://{host}",
                 detail=f"TLS/SSL issue · {iss.get('issue','')[:100]}")
        bare = host.split(":")[0]
        add_edge(host_map.get(bare, "root"), k, "ssl")

    # DOM sinks (group by JS file, up to 12 unique files)
    sink_files = {}
    for ln in data.get("sinks", []):
        m = re.match(r"\[[^\]]+\]\s+([^:]+):", ln)
        if m:
            fpath = m.group(1).strip()
            sink_files.setdefault(fpath, []).append(ln)
    for i, (fpath, lns) in enumerate(list(sink_files.items())[:12]):
        k = f"sink:{i}"
        add_node(k, fpath[:42], "sink", sev="high",
                 detail=f"{len(lns)} DOM sink(s) — potential XSS · {lns[0][:80]}")
        add_edge("root", k, "sink")

    # Source maps exposed (up to 6)
    for i, sm in enumerate(data.get("source_maps", [])[:6]):
        if not sm.startswith("[EXPOSED"): continue
        k = f"smap:{i}"
        add_node(k, f"source-map #{i+1}", "sourcemap", sev="high",
                 detail=sm[:120])
        add_edge("root", k, "sourcemap")

    # Admin routes from JS (up to 8 unique routes)
    ar_seen = set()
    for i, ln in enumerate(data.get("admin_routes", [])[:8]):
        route = re.search(r"['\"/](admin[^'\")\s]*)", ln, re.I)
        label = route.group(0)[:38] if route else ln[:38]
        if label in ar_seen: continue
        ar_seen.add(label)
        k = f"ar:{i}"
        add_node(k, label, "admin-route", sev="high",
                 detail=f"Admin/internal route in JS · {ln[:100]}")
        add_edge("root", k, "admin")

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
            "cors":      _count(os.path.join(d, "headers", "cors_issues.txt")),
            "takeovers": _count(os.path.join(d, "takeover", "takeovers.txt")),
            "buckets":   _count(os.path.join(d, "cloud", "open_buckets.txt")),
            "host_inj":  _count(os.path.join(d, "headers", "host_injection.txt")),
            "gql_eps":   _count(os.path.join(d, "graphql", "endpoints.txt")),
            "gql_intro": _count(os.path.join(d, "graphql", "introspection_enabled.txt")),
            "ssl_issues":_count(os.path.join(d, "ssl", "issues.txt")),
            "sev":       sev,
            # JS analysis (new)
            "js_files":    _count(os.path.join(d, "js", "js_urls.txt")),
            "js_endpoints":_count(os.path.join(d, "js", "endpoints.txt")),
            "js_params":   _count(os.path.join(d, "js", "js_params.txt")),
            "js_sinks":    _count(os.path.join(d, "js", "sinks.txt")),
            "js_tech":     _count(os.path.join(d, "js", "technologies.txt")),
            "js_admin":    _count(os.path.join(d, "js", "admin_routes.txt")),
            "js_subs":     _count(os.path.join(d, "js", "subdomains.txt")),
            "source_maps": _count(os.path.join(d, "js", "sourcemaps.txt")),
            "cloud_in_js": _count(os.path.join(d, "js", "cloud_assets.txt")),
            "gospider_urls":_count(os.path.join(d, "urls", "gospider.txt")),
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

        # JS analysis (new)
        "sinks":       _lines(os.path.join(d, "js", "sinks.txt")),
        "admin_routes":_lines(os.path.join(d, "js", "admin_routes.txt")),
        "technologies":_lines(os.path.join(d, "js", "technologies.txt")),
        "source_maps": _lines(os.path.join(d, "js", "sourcemaps.txt")),
        "cloud_assets":_lines(os.path.join(d, "js", "cloud_assets.txt")),
        "js_subs":     _lines(os.path.join(d, "js", "subdomains.txt")),
        "js_params":   _lines(os.path.join(d, "js", "js_params.txt")),
        "js_comments": _lines(os.path.join(d, "js", "comments.txt")),
        "html_comments":_lines(os.path.join(d, "js", "html_comments.txt")),
        "gql_in_js":   _lines(os.path.join(d, "js", "graphql.txt")),

        "page_js_map": _parse_page_js_map(d),
        "site_tree":   _read_site_tree(d),

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
  --bg:      #09090b;
  --bg1:     #111113;
  --bg2:     #18181b;
  --bg3:     #1f1f22;
  --border:  rgba(255,255,255,0.07);
  --ink:     #fafafa;
  --ink2:    #a1a1aa;
  --ink3:    #52525b;

  --cyan:    #818cf8;
  --cyan2:   #a5b4fc;
  --green:   #4ade80;
  --yellow:  #facc15;
  --orange:  #fb923c;
  --red:     #f87171;
  --purple:  #c084fc;
  --blue:    #60a5fa;

  --crit:   #f87171;
  --high:   #fb923c;
  --med:    #facc15;
  --low:    #60a5fa;
  --info:   #818cf8;
  --cand:   #c084fc;
  --notable:#4ade80;

  --mono: ui-monospace,"Cascadia Code","JetBrains Mono","Fira Code",
          "SFMono-Regular",Menlo,Consolas,monospace;
  --sans: ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --r4: 4px; --r6: 6px; --r8: 8px; --r10: 12px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  background: var(--bg);
  color: var(--ink);
  font-family: var(--sans);
  font-size: 13px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
code, pre, .mono-list, .dork-row code, .tb-search input, .tbl, .row-title, .row-sub, .sec-icon { font-family: var(--mono); }
a { color: var(--cyan); text-decoration: none; }
a:hover { text-decoration: underline; color: var(--cyan2); }
button { font-family: var(--mono); }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg1); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }

/* ── topbar ─────────────────────────────────────────────────── */
.topbar {
  position: sticky; top: 0; z-index: 50;
  background: rgba(9,9,11,.94);
  backdrop-filter: blur(16px);
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
  font-weight: 700; font-size: 15px; letter-spacing: .01em;
  color: var(--cyan); white-space: nowrap; font-family: var(--sans);
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
  font-size: 10px; letter-spacing: .14em; text-transform: uppercase;
  color: var(--ink3); margin-bottom: 10px; font-family: var(--sans);
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
  background: rgba(129,140,248,.08);
  box-shadow: 0 0 10px rgba(129,140,248,.2);
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
  font-size: 10px; letter-spacing: .06em; text-transform: uppercase;
  color: var(--ink3); margin-top: 5px; font-family: var(--sans);
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
  font-size: 9px; font-weight: 700; letter-spacing: .12em;
  text-transform: uppercase;
  background: rgba(129,140,248,.1); color: var(--cyan);
  border: 1px solid rgba(129,140,248,.25); border-radius: var(--r4);
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
.sec-icon { color: var(--cyan); font-size: 11px; letter-spacing: -.01em; }
.sec-title {
  font-size: 12px; font-weight: 600; letter-spacing: .04em;
  text-transform: uppercase; color: var(--ink); font-family: var(--sans);
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
.sec-head.closed ~ .sec-body { display: none; }
.sec-head.closed ~ .sev-pills { display: none; }
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
.b-critical { background: rgba(248,113,113,.12); color: var(--crit); }
.b-high     { background: rgba(251,146,60,.12);  color: var(--high); }
.b-medium   { background: rgba(250,204,21,.10);  color: var(--med);  }
.b-low      { background: rgba(96,165,250,.12);  color: var(--low);  }
.b-info     { background: rgba(129,140,248,.12); color: var(--info); }
.b-notable  { background: rgba(74,222,128,.10);  color: var(--notable); }
.b-candidate{ background: rgba(192,132,252,.12); color: var(--cand); }
.b-bypass   { background: rgba(251,146,60,.12);  color: var(--high); }
.b-cors     { background: rgba(248,113,113,.12); color: var(--crit); }
.b-xss      { background: rgba(248,113,113,.12); color: var(--crit); }
.b-ssrf     { background: rgba(192,132,252,.12); color: var(--cand); }
.b-idor     { background: rgba(192,132,252,.12); color: var(--cand); }
.b-lfi      { background: rgba(192,132,252,.12); color: var(--cand); }
.b-redirect { background: rgba(192,132,252,.12); color: var(--cand); }

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
  display: flex; align-items: center; gap: 5px; flex-wrap: wrap;
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
.graph-ctrl-btn.active { color: var(--cyan); border-color: var(--cyan); background: rgba(129,140,248,.08); }
.graph-ctrl-grp { display: flex; gap: 4px; align-items: center; }
.graph-ctrl-div {
  width: 1px; height: 16px; background: var(--border); margin: 0 4px;
}
.graph-ctrl-sep { flex: 1; }
.graph-count { font-size: 10px; color: var(--ink3); white-space: nowrap; }
.graph-wrap {
  position: relative; height: 650px;
  background: var(--bg); overflow: hidden;
}
.graph-canvas { width: 100%; height: 100%; cursor: grab; display: block; }
.graph-canvas:active { cursor: grabbing; }

/* floating tooltip */
.graph-tooltip {
  position: absolute; pointer-events: none; z-index: 20;
  background: rgba(9,9,11,.97); border: 1px solid var(--border);
  border-radius: var(--r6); padding: 9px 13px;
  font-size: 11px; color: var(--ink); max-width: 300px;
  backdrop-filter: blur(12px);
  opacity: 0; transition: opacity .08s; word-break: break-all; line-height: 1.5;
}
.graph-tooltip.show { opacity: 1; }
.gt-type { font-size: 9px; text-transform: uppercase; letter-spacing: .12em;
           color: var(--ink3); margin-bottom: 3px; }
.gt-label { font-weight: 700; margin-bottom: 4px; }
.gt-detail { color: var(--ink2); font-size: 10.5px; margin-bottom: 4px; }
.gt-deg { font-size: 10px; color: var(--ink3); }

/* legend — complete, 2-column grid */
.graph-legend {
  position: absolute; bottom: 10px; left: 12px;
  display: grid; grid-template-columns: 1fr 1fr; gap: 4px 20px;
  pointer-events: none;
  background: rgba(9,9,11,.82); border: 1px solid rgba(255,255,255,.07);
  border-radius: var(--r8); padding: 9px 12px;
  backdrop-filter: blur(10px);
}
.gl-item {
  display: flex; align-items: center; gap: 5px;
  font-size: 10px; color: var(--ink3); white-space: nowrap;
}
.gl-dot {
  width: 9px; height: 9px; border-radius: 50%;
  border: 1.5px solid; flex: none;
}
.gl-dot.diamond {
  border-radius: 1px; transform: rotate(45deg);
  width: 8px; height: 8px;
}
.gl-dot.hex { border-radius: 3px; }

/* detail panel — wider, scrollable neighbours */
.graph-detail {
  position: absolute; top: 0; right: 0; bottom: 0; width: 275px;
  background: rgba(9,9,11,.97); border-left: 1px solid var(--border);
  padding: 14px 16px 20px; overflow-y: auto;
  transform: translateX(100%); transition: transform .18s ease;
  backdrop-filter: blur(16px);
}
.graph-detail.open { transform: translateX(0); }
.gd-close {
  position: absolute; top: 10px; right: 12px;
  background: none; border: none; color: var(--ink3);
  font-size: 17px; cursor: pointer; line-height: 1; font-family: var(--mono);
}
.gd-close:hover { color: var(--ink); }
.gd-type {
  font-size: 9px; font-weight: 700; letter-spacing: .2em;
  text-transform: uppercase; margin-bottom: 5px;
}
.gd-label {
  font-size: 13px; font-weight: 700; word-break: break-all;
  margin-bottom: 6px; line-height: 1.4; padding-right: 20px;
}
.gd-url {
  display: block; font-size: 11px; color: var(--cyan);
  word-break: break-all; margin-bottom: 8px; line-height: 1.4;
}
.gd-url:hover { text-decoration: underline; }
.gd-detail {
  font-size: 11px; color: var(--ink2); word-break: break-all;
  margin-bottom: 8px; line-height: 1.5;
}
.gd-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
.gd-cp {
  background: none; border: 1px solid var(--border);
  color: var(--ink3); border-radius: var(--r4);
  font-size: 9px; padding: 2px 8px; cursor: pointer;
  font-family: var(--mono); transition: all .12s;
}
.gd-cp:hover { color: var(--cyan); border-color: var(--cyan); }
.gd-sep { border: none; border-top: 1px solid var(--border); margin: 10px 0; }
.gd-sub {
  font-size: 9px; color: var(--ink3); letter-spacing: .12em;
  text-transform: uppercase; margin-bottom: 5px;
}
.gd-nbrs { max-height: 260px; overflow-y: auto; }
.gd-nbr {
  display: flex; align-items: center; gap: 6px;
  font-size: 11px; color: var(--ink2); padding: 3px 0;
  word-break: break-all; cursor: pointer;
}
.gd-nbr:hover { color: var(--cyan); }
.gd-nbr-dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }

@media (max-width: 640px) {
  .graph-wrap { height: 460px; }
  .graph-detail { width: 210px; }
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
    ◆ TANYA<span class="v">v6.2</span>
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
      <div class="hero-label">◆ WHERE TO START</div>
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
          <div class="hero-tier"><span class="pulse" style="background:var(--ink3)"></span>nothing auto-flagged</div>
          <div class="hero-main hero-empty">clean scan</div>
          <div class="hero-path">check http/alive.txt and urls/urls.txt</div>
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
    ['js_files',    'js files',      ''],
    ['js_sinks',    'dom sinks',     s.js_sinks > 0 ? 'c-high' : ''],
    ['source_maps', 'source maps',   s.source_maps > 0 ? 'c-warn' : ''],
    ['js_admin',    'admin routes',  s.js_admin > 0 ? 'c-warn' : ''],
    ['js_tech',     'technologies',  ''],
    ['cloud_in_js', 'cloud in js',   s.cloud_in_js > 0 ? 'c-warn' : ''],
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
  const s = mkSection('[!]', 'Nuclei Findings', D.findings.length, 'findings');
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
  const s = mkSection('[~]', 'Live Services', D.alive.length, 'alive');
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
  const s = mkSection('[#]', 'Edge Challenges (CDN / WAF)', D.challenges.length, 'challenges');
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
listSection('[*]', 'Confirmed Origin IPs (CDN bypass)', D.origins, 'origins', 'li-hot');

/* ── interesting services ────────────────────────────────────── */
listSection('[?]', 'Interesting Services', D.interesting, 'interesting');

/* ── XSS findings ────────────────────────────────────────────── */
{
  const s = mkSection('[x]', 'XSS Findings (dalfox)', D.xss.length, 'xss');
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
  const s = mkSection('[!]', '403 / 401 Bypasses', D.bypasses.length, 'bypass');
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
  const s = mkSection('[~]', 'CORS Misconfigurations', D.cors.length, 'cors');
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
listSection('[!]', 'Dangerous HTTP Methods', D.methods, 'methods', 'li-hot');

/* ── subdomain takeover ──────────────────────────────────────── */
listSection('[^]', 'Subdomain Takeover Candidates', D.takeovers, 'takeovers', 'li-hot');

/* ── open ports ──────────────────────────────────────────────── */
{
  const s = mkSection('[:]', 'Open Ports', D.ports.length, 'ports');
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

/* ── JS secrets (trufflehog / gitleaks / jsluice / regex) ──── */
listSection('[$]', 'Potential Secrets in JS', D.secrets, 'secrets', '');

/* ── JS endpoints ────────────────────────────────────────────── */
listSection('[/]', 'JS Endpoints', D.endpoints, 'endpoints');

/* ── page → JS map ───────────────────────────────────────────── */
{
  const map = D.page_js_map || [];
  const total = map.reduce((a, e) => a + e.scripts.length, 0);
  const s = mkSection('[js]', 'Page → JS Files', map.length + ' pages · ' + total + ' scripts', 'pagejs');
  s.head.querySelector('.sec-cnt').style.color = 'var(--cyan)';
  if (!map.length) {
    emptySection(s);
  } else {
    map.forEach(entry => {
      const grp = E('div', 'dork-header');
      grp.style.cssText = 'cursor:pointer;user-select:none';
      const hdr = E('span', 'dork-platform');
      hdr.textContent = entry.page;
      grp.appendChild(hdr);
      const badge = E('span', '');
      badge.style.cssText = 'margin-left:8px;color:var(--ink3);font-size:0.8em';
      badge.textContent = entry.scripts.length + ' script(s)';
      grp.appendChild(badge);
      grp.appendChild(mkCopy(entry.scripts.join('\\n')));
      const ul = E('ul', 'mono-list');
      ul.style.display = 'none';
      grp.onclick = ev => { if (ev.target.tagName === 'BUTTON') return; ul.style.display = ul.style.display === 'none' ? '' : 'none'; };
      entry.scripts.forEach(src => {
        const li = E('li', '');
        li.style.cssText = 'padding:2px 0 2px 12px;color:var(--ink2)';
        li.innerHTML = `<span style="color:var(--ink3)">↳</span> ${esc(src)}`;
        li.appendChild(mkCopy(src));
        ul.appendChild(li);
      });
      s.body.appendChild(grp);
      s.body.appendChild(ul);
    });
  }
}

/* ── DOM XSS sinks ───────────────────────────────────────────── */
{
  const s = mkSection('[!]', 'DOM XSS Sinks', D.sinks.length, 'sinks');
  if (!D.sinks.length) {
    emptySection(s);
  } else {
    D.sinks.forEach(ln => {
      const m = ln.match(/^\[([^\]]+)\]/);
      const sink = m ? m[1] : 'sink';
      const row  = E('div', 'row sr');
      row.dataset.q = ln.toLowerCase();
      row.innerHTML = `
        <div class="row-bar" style="background:var(--high)"></div>
        <span class="sev-badge b-high">${esc(sink)}</span>
        <div class="row-body"><div class="row-title">${esc(ln)}</div></div>`;
      row.appendChild(mkCopy(ln));
      s.body.appendChild(row);
    });
  }
}

/* ── JS analysis (admin routes, source maps, cloud, techs, subs, GQL) ── */
{
  const total = D.admin_routes.length + D.source_maps.length + D.cloud_assets.length
              + D.technologies.length + D.js_subs.length + D.gql_in_js.length;
  const s = mkSection('[js]', 'JavaScript Analysis', total, 'jsanalysis');
  if (!total) {
    emptySection(s);
  } else {
    const grps = [
      ['admin_routes', 'Admin / Internal Routes',  'b-high',      'var(--high)'],
      ['source_maps',  'Source Maps Detected',      'b-bypass',    'var(--yellow)'],
      ['cloud_assets', 'Cloud Assets in JS',        'b-candidate', 'var(--cand)'],
      ['js_subs',      'Subdomains Discovered',     'b-notable',   'var(--notable)'],
      ['gql_in_js',    'GraphQL Patterns in JS',    'b-info',      'var(--info)'],
      ['technologies', 'Technologies Fingerprinted','b-info',      'var(--info)'],
    ];
    grps.forEach(([k, lbl, badge, col]) => {
      if (!D[k].length) return;
      const hdr = E('div', 'dork-header');
      hdr.innerHTML = `<span class="dork-platform">${lbl}  <span style="color:var(--ink3)">(${D[k].length})</span></span>`;
      hdr.appendChild(mkCopy(D[k].join('\n')));
      s.body.appendChild(hdr);
      D[k].forEach(ln => {
        const row = E('div', 'row sr');
        row.dataset.q = ln.toLowerCase();
        row.innerHTML = `
          <div class="row-bar" style="background:${col}"></div>
          <div class="row-body"><div class="row-title">${esc(ln)}</div></div>`;
        row.appendChild(mkCopy(ln));
        s.body.appendChild(row);
      });
    });
  }
}

/* ── code comments (JS + HTML) ──────────────────────────────── */
{
  const total = D.js_comments.length + D.html_comments.length;
  const s = mkSection('[//]', 'Code Comments', total, 'comments');
  if (!total) {
    emptySection(s);
  } else {
    [['js_comments', 'Interesting JS Comments'], ['html_comments', 'HTML Page Comments']].forEach(([k, lbl]) => {
      if (!D[k].length) return;
      const hdr = E('div', 'dork-header');
      hdr.innerHTML = `<span class="dork-platform">${lbl}  <span style="color:var(--ink3)">(${D[k].length})</span></span>`;
      hdr.appendChild(mkCopy(D[k].join('\n')));
      s.body.appendChild(hdr);
      D[k].slice(0, 300).forEach(ln => {
        const row = E('div', 'dork-row sr');
        row.dataset.q = ln.toLowerCase();
        row.innerHTML = `<code>${esc(ln)}</code>`;
        row.appendChild(mkCopy(ln));
        s.body.appendChild(row);
      });
    });
  }
}

/* ── JS parameters ───────────────────────────────────────────── */
listSection('[?]', 'JS Parameters', D.js_params, 'jsparams');

/* ── param candidates ────────────────────────────────────────── */
{
  const groups = [
    ['ssrf',     'SSRF',          'b-ssrf',    'var(--cand)'],
    ['idor',     'IDOR',          'b-idor',    'var(--cand)'],
    ['lfi',      'LFI',           'b-lfi',     'var(--cand)'],
    ['redirect', 'Open Redirect', 'b-redirect','var(--cand)'],
  ];
  const total = groups.reduce((a, [k]) => a + D.params[k].length, 0);
  const s = mkSection('[?]', 'Parameter Candidates', total, 'params');
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
listSection('[-]', 'Interesting File URLs', D.int_files, 'intfiles');

/* ── site tree ───────────────────────────────────────────────── */
{
  const tree = D.site_tree || '';
  const lines = tree ? tree.split('\\n') : [];
  const s = mkSection('[t]', 'Site URL Tree', lines.length ? lines.filter(l => l.trim()).length + ' lines' : '0', 'sitetree');
  if (!tree) {
    emptySection(s);
  } else {
    const pre = E('pre', '');
    pre.style.cssText = 'margin:8px 12px;padding:12px;background:var(--bg2);border-radius:6px;overflow-x:auto;font-size:0.82em;line-height:1.5;color:var(--ink1);white-space:pre';
    pre.textContent = tree;
    const copyBtn = mkCopy(tree);
    copyBtn.style.cssText = 'float:right;margin:8px 12px 0 0';
    s.body.appendChild(copyBtn);
    s.body.appendChild(pre);
  }
}

/* ── public cloud buckets ────────────────────────────────────── */
listSection('[^]', 'Public Cloud Buckets', D.open_buckets, 'buckets', 'li-hot');

/* ── dorks ───────────────────────────────────────────────────── */
{
  const total = D.dorks.google.length + D.dorks.github.length;
  const s = mkSection('[d]', 'Dorks', total, 'dorks');
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
  const s = mkSection('[#]', 'Security Header Audit', total, 'headers');
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
  const s = mkSection('[g]', 'GraphQL Recon', total, 'graphql');
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
  const s = mkSection('[s]', 'TLS / SSL Analysis', total, 'ssl');
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

    const s = mkSection('[m]', 'Attack Surface Map',
      GD.nodes.length + ' nodes · ' + GD.edges.length + ' edges', 'graph');
    s.head.querySelector('.sec-cnt').style.color = 'var(--cyan)';

    // Controls bar
    const ctrl = E('div', 'graph-ctrl');
    ctrl.innerHTML = `
      <div class="graph-ctrl-grp">
        <button class="graph-ctrl-btn" id="gc-recenter">⌖ reset layout</button>
        <button class="graph-ctrl-btn" id="gc-heat">⚡ vulns only</button>
        <button class="graph-ctrl-btn" id="gc-png">↓ save PNG</button>
      </div>
      <div class="graph-ctrl-div"></div>
      <div class="graph-ctrl-grp">
        <button class="graph-ctrl-btn active" data-tf="all">all</button>
        <button class="graph-ctrl-btn" data-tf="infra">infra</button>
        <button class="graph-ctrl-btn" data-tf="attack">findings</button>
        <button class="graph-ctrl-btn" data-tf="waf">waf</button>
      </div>
      <div class="graph-ctrl-div"></div>
      <div class="graph-ctrl-grp">
        <button class="graph-ctrl-btn" id="gc-zi">zoom +</button>
        <button class="graph-ctrl-btn" id="gc-zo">zoom −</button>
      </div>
      <span class="graph-ctrl-sep"></span>
      <span class="graph-count" id="gc-count">${GD.nodes.length} nodes · ${GD.edges.length} edges  ·  scroll=zoom  drag=pan  click=inspect</span>`;
    s.body.before(ctrl);

    // Graph container
    const outer = E('div', 'graph-outer');
    const gwrap = E('div', 'graph-wrap');
    const canvas = E('canvas', 'graph-canvas');
    canvas.id = 'graph-canvas';

    // Hover tooltip
    const tipEl = E('div', 'graph-tooltip');

    // Legend — complete, 2-column
    const legend = E('div', 'graph-legend');
    [
      ['#39c5cf','diamond','target'],
      ['#388bfd','',       'subdomain'],
      ['#3fb950','',       'live service'],
      ['#f0883e','',       'service w/ vuln'],
      ['#f85149','hex',    'critical finding'],
      ['#f0883e','hex',    'high finding'],
      ['#d29922','hex',    'medium finding'],
      ['#388bfd','hex',    'low / info'],
      ['#ff6bff','',       'origin IP (CDN bypass)'],
      ['#8b949e','',       'CDN / WAF block'],
      ['#56d8e4','',       'GraphQL endpoint'],
      ['#bc8cff','',       'bypass / XSS'],
      ['#ffb700','hex',    'DOM sink / source map'],
      ['#ff6b35','',       'admin route in JS'],
    ].forEach(([col, shape, label]) => {
      const item = E('div', 'gl-item');
      const cls  = shape === 'diamond' ? 'gl-dot diamond' : shape === 'hex' ? 'gl-dot hex' : 'gl-dot';
      item.innerHTML =
        `<div class="${cls}" style="border-color:${col};background:${col}22"></div>` +
        `<span>${label}</span>`;
      legend.appendChild(item);
    });

    // Detail panel
    const detailEl = E('div', 'graph-detail');
    detailEl.id = 'gd-panel';

    gwrap.appendChild(canvas);
    gwrap.appendChild(tipEl);
    gwrap.appendChild(legend);
    gwrap.appendChild(detailEl);
    outer.appendChild(gwrap);
    s.body.appendChild(outer);

    /* ── ForceGraph ─────────────────────────────────────────── */
    class ForceGraph {
      constructor(canvas, detailEl, tipEl, rawNodes, rawEdges) {
        this.canvas   = canvas;
        this.detailEl = detailEl;
        this.tipEl    = tipEl;
        this.ctx      = canvas.getContext('2d');
        this.dpr      = Math.min(window.devicePixelRatio || 1, 2);

        this.nodes = rawNodes.map(n => ({...n, x:0, y:0, vx:0, vy:0}));
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
        this._vis = new Set(this.nodes.map(n => n.id));

        this._resize();
        this._scatter();
        this._bind();
        new ResizeObserver(() => { this._resize(); }).observe(canvas.parentElement);
        this._loop();
      }

      // ── concentric ring layout ──────────────────────────────
      _scatter() {
        const W = this.cW, H = this.cH;
        const cx = W/2, cy = H/2;
        const D  = Math.min(W, H);
        const R  = [0, D*0.18, D*0.34, D*0.46];

        const ring = {
          target:0, origin:1, subdomain:1,
          service:2, 'svc-vuln':2, challenge:2,
          finding:3, xss:3, takeover:3, bypass:3,
          bucket:3, graphql:3, 'ssl-issue':3,
          sink:3, sourcemap:3, 'admin-route':3,
        };
        const byRing = [[],[],[],[]];
        this.nodes.forEach(n => { byRing[ring[n.t]??2].push(n); });

        // ring 0 — target at center
        byRing[0].forEach(n => { n.x=cx; n.y=cy; n._a=0; });

        // ring 1 — subdomains + origins
        byRing[1].forEach((n,i,arr) => {
          n._a = (i/Math.max(arr.length,1))*Math.PI*2 - Math.PI/2;
          n.x = cx + R[1]*Math.cos(n._a);
          n.y = cy + R[1]*Math.sin(n._a);
        });

        // parent angle lookup for ring 2
        const pa2 = {};
        this.edges.forEach(e => {
          const s=this.nById[e.s], t=this.nById[e.t];
          if (!s||!t) return;
          if ((ring[s.t]??2)<2 && (ring[t.t]??2)===2 && pa2[t.id]===undefined)
            pa2[t.id] = s._a??0;
        });
        byRing[2].forEach((n,i,arr) => {
          const base = pa2[n.id] ?? (i/Math.max(arr.length,1))*Math.PI*2 - Math.PI/2;
          n._a = base + (Math.random()-.5)*.35;
          n.x = cx + R[2]*Math.cos(n._a);
          n.y = cy + R[2]*Math.sin(n._a);
        });

        // parent angle lookup for ring 3
        const pa3 = {};
        this.edges.forEach(e => {
          const s=this.nById[e.s], t=this.nById[e.t];
          if (!s||!t) return;
          if ((ring[s.t]??2)<3 && (ring[t.t]??2)===3 && pa3[t.id]===undefined)
            pa3[t.id] = s._a??0;
        });
        byRing[3].forEach((n,i,arr) => {
          const base = pa3[n.id] ?? (i/Math.max(arr.length,1))*Math.PI*2 - Math.PI/2;
          n._a = base + (Math.random()-.5)*.5;
          n.x = cx + R[3]*Math.cos(n._a);
          n.y = cy + R[3]*Math.sin(n._a);
        });

        this.nodes.forEach(n => { n.vx=0; n.vy=0; });
        this.panX=0; this.panY=0; this.zoom=1; this.ticks=0;
      }

      _resize() {
        const rect = this.canvas.parentElement?.getBoundingClientRect();
        if (!rect||rect.width<10) return;
        this.cW=rect.width; this.cH=rect.height;
        this.canvas.width  = this.cW*this.dpr;
        this.canvas.height = this.cH*this.dpr;
        this.canvas.style.width  = this.cW+'px';
        this.canvas.style.height = this.cH+'px';
      }

      // ── physics ────────────────────────────────────────────
      _step() {
        const ns = this.nodes;
        const KR=6200, KS=0.038, RL=96, GR=0.002;
        const cx=this.cW/2, cy=this.cH/2;
        ns.forEach(n => { n.fx=0; n.fy=0; });

        for (let i=0;i<ns.length;i++) for (let j=i+1;j<ns.length;j++) {
          const a=ns[i], b=ns[j];
          let dx=a.x-b.x, dy=a.y-b.y;
          const d2=dx*dx+dy*dy+.5, id=1/Math.sqrt(d2), f=KR/d2;
          dx*=id; dy*=id;
          a.fx+=dx*f; a.fy+=dy*f; b.fx-=dx*f; b.fy-=dy*f;
        }

        this.edges.forEach(e => {
          const a=this.nById[e.s], b=this.nById[e.t];
          if (!a||!b) return;
          let dx=b.x-a.x, dy=b.y-a.y;
          const d=Math.sqrt(dx*dx+dy*dy)+.01, f=(d-RL)*KS;
          dx/=d; dy/=d;
          a.fx+=dx*f; a.fy+=dy*f; b.fx-=dx*f; b.fy-=dy*f;
        });

        const damp=this.ticks>200?0.76:0.87;
        ns.forEach(n => {
          if (n===this.drag) return;
          n.fx+=(cx-n.x)*GR; n.fy+=(cy-n.y)*GR;
          n.vx=(n.vx+n.fx)*damp; n.vy=(n.vy+n.fy)*damp;
          n.x=Math.max(28,Math.min(this.cW-28,n.x+n.vx));
          n.y=Math.max(28,Math.min(this.cH-28,n.y+n.vy));
        });
        this.ticks++;
      }

      // ── draw ───────────────────────────────────────────────
      _draw() {
        const ctx=this.ctx, W=this.canvas.width, H=this.canvas.height;
        const d=this.dpr, z=this.zoom;
        ctx.setTransform(1,0,0,1,0,0);
        ctx.clearRect(0,0,W,H);

        // dot grid background
        ctx.fillStyle='#1e3040'; ctx.globalAlpha=.2;
        const gs=30*d;
        for (let x=0;x<W;x+=gs) for (let y=0;y<H;y+=gs)
          ctx.fillRect(x,y,d,d);
        ctx.globalAlpha=1;

        ctx.setTransform(z*d,0,0,z*d,this.panX*d,this.panY*d);

        const hasSel=!!this.sel;
        const heatSet=this.heat
          ? new Set(this.nodes.filter(n=>
              n.t==='finding'||n.t==='xss'||n.t==='takeover'||n.t==='bucket'||
              n.t==='bypass'||n.t==='origin'||n.t==='ssl-issue'||n.t==='graphql'||
          n.t==='sink'||n.t==='sourcemap'||n.t==='admin-route'
            ).map(n=>n.id))
          : null;
        const vis=this._vis;

        // edges
        this.edges.forEach(e => {
          const a=this.nById[e.s], b=this.nById[e.t];
          if (!a||!b||!vis.has(e.s)||!vis.has(e.t)) return;
          if (heatSet&&!heatSet.has(e.s)&&!heatSet.has(e.t)) return;
          const conn=hasSel&&(e.s===this.sel?.id||e.t===this.sel?.id);
          const dim =hasSel&&!conn;
          const [ec,edash,ew]=this._edgeStyle(e.r);
          ctx.beginPath();
          ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y);
          ctx.strokeStyle=ec; ctx.lineWidth=conn?ew*2.2:ew;
          ctx.setLineDash(edash);
          ctx.globalAlpha=dim?.04:conn?.88:.2;
          ctx.stroke();
          if (conn) {
            const dx=b.x-a.x, dy=b.y-a.y, dl=Math.sqrt(dx*dx+dy*dy)||1;
            const r2=this._nr(b)+3;
            const tx=b.x-(dx/dl)*r2, ty=b.y-(dy/dl)*r2;
            const nx=-dy/dl*5, ny=dx/dl*5;
            ctx.beginPath();
            ctx.moveTo(tx,ty);
            ctx.lineTo(tx-(dx/dl)*9+nx, ty-(dy/dl)*9+ny);
            ctx.lineTo(tx-(dx/dl)*9-nx, ty-(dy/dl)*9-ny);
            ctx.closePath();
            ctx.fillStyle=ec; ctx.globalAlpha=.85; ctx.fill();
          }
          ctx.setLineDash([]); ctx.globalAlpha=1;
        });

        // nodes
        this.nodes.forEach(n => {
          if (!vis.has(n.id)) return;
          if (heatSet&&!heatSet.has(n.id)&&n.t!=='target') return;
          const r=this._nr(n), col=this._nc(n);
          const isHv=n===this.hover, isSl=n===this.sel;
          const isNb=hasSel&&this.nbrs[this.sel?.id]?.has(n.id);
          const dim=hasSel&&!isSl&&!isNb;
          ctx.globalAlpha=dim?.09:1;

          if (isSl||isHv) {
            ctx.beginPath(); ctx.arc(n.x,n.y,r+6,0,Math.PI*2);
            ctx.strokeStyle=col; ctx.lineWidth=1.5;
            ctx.globalAlpha=dim?.02:.38; ctx.stroke();
            ctx.globalAlpha=dim?.09:1;
          }

          this._drawShape(ctx,n,r,col,isSl);
          this._drawIcon(ctx,n,r,col,dim);
          ctx.globalAlpha=dim?.09:1;
          if (!dim||isHv||isSl) this._drawLabel(ctx,n,r,col,isHv||isSl,isSl);
          ctx.globalAlpha=1;
        });
      }

      _drawShape(ctx,n,r,col,sel) {
        const lw=sel?2.4:1.4;
        const grad=ctx.createRadialGradient(n.x,n.y-r*.2,0,n.x,n.y,r*1.2);
        grad.addColorStop(0,col+'55'); grad.addColorStop(1,col+'0d');

        if (n.t==='target') {
          // diamond
          ctx.beginPath();
          ctx.moveTo(n.x,n.y-r*1.35); ctx.lineTo(n.x+r*1.1,n.y);
          ctx.lineTo(n.x,n.y+r*1.35); ctx.lineTo(n.x-r*1.1,n.y);
          ctx.closePath();
        } else if (['finding','xss','takeover','bucket'].includes(n.t)) {
          // hexagon
          ctx.beginPath();
          for (let i=0;i<6;i++) {
            const a=(i/6)*Math.PI*2-Math.PI/6;
            const method=i===0?'moveTo':'lineTo';
            ctx[method](n.x+r*Math.cos(a), n.y+r*Math.sin(a));
          }
          ctx.closePath();
        } else if (n.t==='origin') {
          // rotated square
          ctx.beginPath();
          ctx.moveTo(n.x,n.y-r*1.1); ctx.lineTo(n.x+r*1.1,n.y);
          ctx.lineTo(n.x,n.y+r*1.1); ctx.lineTo(n.x-r*1.1,n.y);
          ctx.closePath();
        } else {
          ctx.beginPath(); ctx.arc(n.x,n.y,r,0,Math.PI*2);
          if (n.t==='challenge') {
            ctx.setLineDash([3,3]);
          }
        }
        ctx.fillStyle=grad; ctx.strokeStyle=col; ctx.lineWidth=lw;
        ctx.fill(); ctx.stroke(); ctx.setLineDash([]);
      }

      _drawIcon(ctx,n,r,col,dim) {
        const icons={
          target:'◆', origin:'⊕', takeover:'⚠', xss:'✕',
          bucket:'☁', bypass:'↻', graphql:'⬡', 'ssl-issue':'⊘',
          finding:'!', 'svc-vuln':'!', challenge:'⊗',
          sink:'⚡', sourcemap:'◎', 'admin-route':'⚙',
        };
        const ic=icons[n.t];
        if (!ic) return;
        const fs=Math.round(r*(n.t==='target'?.62:.68));
        ctx.font=`bold ${fs}px ui-monospace,monospace`;
        ctx.fillStyle=col; ctx.textAlign='center'; ctx.textBaseline='middle';
        ctx.globalAlpha=dim?.09:.92;
        ctx.fillText(ic,n.x,n.y);
      }

      _drawLabel(ctx,n,r,col,bright,bold) {
        const lbl=n.lb||'';
        const txt=lbl.length>27?lbl.slice(0,26)+'…':lbl;
        const fs=Math.max(9,Math.min(11,r+1));
        ctx.font=`${bold?'bold ':''}${fs}px ui-monospace,monospace`;
        ctx.textAlign='center'; ctx.textBaseline='top';
        const tw=ctx.measureText(txt).width;
        const offY=n.t==='target'?r*1.35+4:r+4;
        const ty=n.y+offY;
        ctx.fillStyle='rgba(6,11,18,.88)';
        ctx.fillRect(n.x-tw/2-3,ty-1,tw+6,fs+3);
        ctx.fillStyle=bright?'#e6edf3':this._labelCol(n);
        ctx.globalAlpha=1;
        ctx.fillText(txt,n.x,ty);
        // HTTP status code second line for services
        if ((n.t==='service'||n.t==='svc-vuln')&&n.m?.code) {
          const code=n.m.code;
          const cc={'2':'#3fb950','3':'#56d8e4','4':'#d29922','5':'#f85149'}[code[0]]||'#8b949e';
          ctx.font=`${fs-1}px ui-monospace,monospace`;
          ctx.fillStyle='rgba(6,11,18,.88)';
          ctx.fillRect(n.x-20,ty+fs+2,40,fs+1);
          ctx.fillStyle=cc;
          ctx.fillText(code,n.x,ty+fs+3);
        }
      }

      // ── style helpers ───────────────────────────────────────
      _nr(n) {
        if (n.t==='target')    return 22;
        if (n.t==='origin')    return 15;
        if (n.t==='takeover')  return 13;
        if (n.t==='xss')       return 13;
        if (n.t==='bucket')    return 13;
        if (n.t==='bypass')    return 11;
        if (n.t==='svc-vuln')  return 11;
        if (n.t==='graphql')     return 10;
        if (n.t==='ssl-issue')   return 11;
        if (n.t==='sink')        return 12;
        if (n.t==='sourcemap')   return 10;
        if (n.t==='admin-route') return 11;
        if (n.t==='service')     return 9;
        if (n.t==='challenge') return 9;
        if (n.t==='finding')
          return {critical:14,high:12,medium:10,low:8,info:7}[n.s]||8;
        if (n.t==='subdomain') return Math.min(15,Math.max(8,8+(n.deg||0)));
        return 8;
      }

      _nc(n) {
        const m={
          target:'#39c5cf', subdomain:'#388bfd', service:'#3fb950',
          'svc-vuln':'#f0883e', origin:'#ff6bff', challenge:'#8b949e',
          xss:'#f85149', takeover:'#f85149', bypass:'#bc8cff',
          graphql:'#56d8e4', 'ssl-issue':'#f0883e', bucket:'#f85149',
          sink:'#ffb700', sourcemap:'#ffb700', 'admin-route':'#ff6b35',
        };
        if (n.t==='finding')
          return {critical:'#f85149',high:'#f0883e',medium:'#d29922',
                  low:'#388bfd',info:'#56d8e4'}[n.s]||'#8b949e';
        return m[n.t]||'#8b949e';
      }

      _labelCol(n) {
        if (['origin','xss','takeover','bucket'].includes(n.t)) return '#f85149';
        if (n.t==='target')   return '#39c5cf';
        if (n.t==='svc-vuln') return '#f0883e';
        if (n.t==='bypass')   return '#bc8cff';
        if (n.t==='finding')
          return {critical:'#f85149',high:'#f0883e',medium:'#d29922',
                  low:'#388bfd',info:'#56d8e4'}[n.s]||'#8b949e';
        if (n.t==='subdomain') return '#388bfd';
        return '#8b949e';
      }

      _edgeStyle(rel) {
        const s={
          vuln:    ['#f85149',[5,4],1.2],
          xss:     ['#f85149',[4,3],1.2],
          takeover:['#f85149',[6,4],1.2],
          bucket:  ['#f85149',[5,4],1.2],
          bypass:  ['#bc8cff',[4,4],1.0],
          origin:  ['#ff6bff',[6,4],1.0],
          waf:     ['#484f58',[3,5],0.8],
          http:    ['#388bfd',[],   0.7],
          graphql: ['#56d8e4',[4,3],1.0],
          ssl:     ['#f0883e',[4,3],1.0],
        };
        return s[rel]||['#2e4a60',[],0.55];
      }

      // ── tooltip ─────────────────────────────────────────────
      _showTip(n,sx,sy) {
        const t=this.tipEl, col=this._nc(n);
        const TYPE={
          target:'TARGET', subdomain:'SUBDOMAIN', service:'SERVICE',
          'svc-vuln':'SERVICE (has vulns)', finding:'NUCLEI FINDING',
          origin:'ORIGIN IP', challenge:'CDN / WAF BLOCK',
          xss:'XSS', takeover:'SUBDOMAIN TAKEOVER',
          bypass:'403 BYPASS', bucket:'OPEN BUCKET',
          graphql:'GRAPHQL ENDPOINT', 'ssl-issue':'TLS / SSL ISSUE',
          sink:'DOM XSS SINK', sourcemap:'EXPOSED SOURCE MAP', 'admin-route':'ADMIN ROUTE',
        };
        const sevHtml=n.s?`<span class="sev-badge b-${n.s}" style="margin-top:4px;display:inline-block">${n.s.toUpperCase()}</span>`:'';
        t.innerHTML=`
          <div class="gt-type" style="color:${col}">${TYPE[n.t]||n.t}</div>
          <div class="gt-label">${esc(n.lb||n.id)}</div>
          ${n.d?`<div class="gt-detail">${esc(n.d)}</div>`:''}
          ${sevHtml}
          <div class="gt-deg">${n.deg||0} connection${(n.deg||0)!==1?'s':''}</div>`;
        const cw=this.cW, ch=this.cH;
        t.style.left=t.style.right=t.style.top=t.style.bottom='';
        if (sx+310>cw) t.style.right=(cw-sx+8)+'px';
        else           t.style.left=(sx+14)+'px';
        if (sy+130>ch) t.style.bottom=(ch-sy+6)+'px';
        else           t.style.top=(sy-8)+'px';
        t.classList.add('show');
      }
      _hideTip() { this.tipEl.classList.remove('show'); }

      // ── type filter ─────────────────────────────────────────
      setFilter(f) {
        const infra =new Set(['target','subdomain','service','svc-vuln','origin','challenge']);
        const attack=new Set(['finding','xss','takeover','bypass','bucket','ssl-issue','graphql',
                              'sink','sourcemap','admin-route','target']);
        const waf   =new Set(['challenge','subdomain','target']);
        this._vis=new Set(this.nodes.filter(n=>{
          if (f==='all')    return true;
          if (f==='infra')  return infra.has(n.t);
          if (f==='attack') return attack.has(n.t);
          if (f==='waf')    return waf.has(n.t);
          return true;
        }).map(n=>n.id));
        const vn=this._vis.size;
        const ve=this.edges.filter(e=>this._vis.has(e.s)&&this._vis.has(e.t)).length;
        const el=document.getElementById('gc-count');
        if (el) el.textContent=`${vn} nodes · ${ve} edges  ·  scroll=zoom  drag=pan  click=inspect`;
      }

      // ── interaction ─────────────────────────────────────────
      _cvPos(ev) {
        const r=this.canvas.getBoundingClientRect();
        return [ev.clientX-r.left, ev.clientY-r.top];
      }
      _world(sx,sy) { return [(sx-this.panX)/this.zoom,(sy-this.panY)/this.zoom]; }
      _hit(sx,sy) {
        const [wx,wy]=this._world(sx,sy);
        let best=null, bestD=28;
        this.nodes.forEach(n=>{
          if (!this._vis.has(n.id)) return;
          const d=Math.hypot(n.x-wx,n.y-wy);
          if (d<this._nr(n)+10&&d<bestD+this._nr(n)){best=n;bestD=d;}
        });
        return best;
      }

      _bind() {
        const c=this.canvas;
        let lastP=null, panning=false, startP=null;

        c.addEventListener('mousemove', ev=>{
          const [cx,cy]=this._cvPos(ev);
          if (this.drag) {
            const [wx,wy]=this._world(cx,cy);
            this.drag.x=wx; this.drag.y=wy; this.drag.vx=0; this.drag.vy=0;
            this._hideTip();
          } else if (panning&&lastP) {
            this.panX+=cx-lastP[0]; this.panY+=cy-lastP[1];
            this._hideTip();
          } else {
            const n=this._hit(cx,cy);
            this.hover=n; c.style.cursor=n?'pointer':'grab';
            n ? this._showTip(n,cx,cy) : this._hideTip();
          }
          lastP=[cx,cy];
        });

        c.addEventListener('mousedown', ev=>{
          const [cx,cy]=this._cvPos(ev);
          const n=this._hit(cx,cy);
          if (n){this.drag=n;c.style.cursor='grabbing';}
          else  {panning=true;c.style.cursor='grabbing';}
          startP=[cx,cy]; lastP=[cx,cy]; this._hideTip();
        });

        c.addEventListener('mouseup', ev=>{
          const [cx,cy]=this._cvPos(ev);
          if (this.drag&&startP&&Math.hypot(cx-startP[0],cy-startP[1])<6)
            this._select(this.drag);
          this.drag=null; panning=false;
          c.style.cursor=this.hover?'pointer':'grab';
        });

        c.addEventListener('click', ev=>{
          const [cx,cy]=this._cvPos(ev);
          if (!this._hit(cx,cy)){this.sel=null;this.detailEl.classList.remove('open');}
        });

        c.addEventListener('wheel', ev=>{
          ev.preventDefault();
          const [cx,cy]=this._cvPos(ev);
          const f=ev.deltaY<0?1.12:.89;
          const nz=Math.max(.08,Math.min(7,this.zoom*f));
          const [wx,wy]=this._world(cx,cy);
          this.zoom=nz; this.panX=cx-wx*nz; this.panY=cy-wy*nz;
        },{passive:false});

        c.addEventListener('mouseleave',()=>{
          this.hover=null; this.drag=null; panning=false; this._hideTip();
        });

        let t0=null;
        c.addEventListener('touchstart',ev=>{
          ev.preventDefault();
          if (ev.touches.length===1){
            const t=ev.touches[0], [cx,cy]=this._cvPos(t);
            const n=this._hit(cx,cy);
            if (n){this.drag=n;}else{panning=true;}
            t0=[cx,cy]; lastP=[cx,cy];
          }
        },{passive:false});
        c.addEventListener('touchmove',ev=>{
          ev.preventDefault();
          if (ev.touches.length===1){
            const t=ev.touches[0], [cx,cy]=this._cvPos(t);
            if (this.drag){const [wx,wy]=this._world(cx,cy);this.drag.x=wx;this.drag.y=wy;}
            else if (panning&&lastP){this.panX+=cx-lastP[0];this.panY+=cy-lastP[1];}
            lastP=[cx,cy];
          }
        },{passive:false});
        c.addEventListener('touchend',ev=>{
          if (this.drag&&t0){
            const t=ev.changedTouches[0],[cx,cy]=this._cvPos(t);
            if (Math.hypot(cx-t0[0],cy-t0[1])<8) this._select(this.drag);
          }
          this.drag=null; panning=false;
        });
      }

      // ── detail panel ────────────────────────────────────────
      _select(n) {
        this.sel=n;
        const d=this.detailEl, col=this._nc(n);
        const TYPE={
          target:'TARGET', subdomain:'SUBDOMAIN', service:'SERVICE',
          'svc-vuln':'SERVICE  (has vulns)', finding:'NUCLEI FINDING',
          origin:'ORIGIN IP  —  CDN bypassed', challenge:'CDN / WAF BLOCK',
          xss:'XSS CONFIRMED', takeover:'SUBDOMAIN TAKEOVER',
          bypass:'403 / 401 BYPASS', bucket:'OPEN CLOUD BUCKET',
          graphql:'GRAPHQL ENDPOINT', 'ssl-issue':'TLS / SSL ISSUE',
          sink:'DOM XSS SINK', sourcemap:'EXPOSED SOURCE MAP', 'admin-route':'ADMIN ROUTE IN JS',
        };
        const connIds=[...(this.nbrs[n.id]||[])];
        const nbrsHtml=connIds.map(id=>{
          const nb=this.nById[id]; if (!nb) return '';
          const nc=this._nc(nb);
          return `<div class="gd-nbr" data-nid="${esc(id)}">
            <span class="gd-nbr-dot" style="background:${nc}"></span>
            ${esc(nb.lb||id)}
          </div>`;
        }).join('');

        const urlHtml=n.u
          ?`<a class="gd-url" href="${esc(n.u)}" target="_blank" rel="noopener">${esc(n.u)}</a>`:'';

        const metaHtml=(()=>{
          const m=n.m||{};
          const parts=[];
          if (m.code) parts.push(`HTTP ${m.code}`);
          if (m.tech) parts.push(m.tech);
          if (m.title) parts.push(m.title);
          return parts.length?`<div class="gd-detail">${esc(parts.join(' · '))}</div>`:'';
        })();

        d.innerHTML=`
          <button class="gd-close" id="gd-x">×</button>
          <div class="gd-type" style="color:${col}">${TYPE[n.t]||n.t.toUpperCase()}</div>
          <div class="gd-label" style="color:${col}">${esc(n.lb||n.id)}</div>
          ${urlHtml}
          ${n.d?`<div class="gd-detail">${esc(n.d)}</div>`:''}
          ${metaHtml}
          ${n.s?`<div style="margin-bottom:8px"><span class="sev-badge b-${esc(n.s)}">${n.s.toUpperCase()}</span></div>`:''}
          <div class="gd-actions">
            ${n.u?`<button class="gd-cp" data-v="${esc(n.u)}" data-lbl="copy url">copy url</button>`:''}
            <button class="gd-cp" data-v="${esc(n.lb||n.id)}" data-lbl="copy label">copy label</button>
          </div>
          <hr class="gd-sep">
          <div class="gd-sub">connections  (${connIds.length})</div>
          <div class="gd-nbrs">${nbrsHtml||'<div class="gd-nbr" style="color:var(--ink3)">—  none</div>'}</div>`;

        d.querySelector('#gd-x').onclick=()=>{d.classList.remove('open');this.sel=null;};
        d.querySelectorAll('.gd-nbr[data-nid]').forEach(el=>{
          el.onclick=()=>{const nb=this.nById[el.dataset.nid];if(nb)this._select(nb);};
        });
        d.querySelectorAll('.gd-cp').forEach(el=>{
          el.onclick=async()=>{
            const txt=el.dataset.v;
            try{await navigator.clipboard.writeText(txt);}
            catch(_){const ta=document.createElement('textarea');ta.value=txt;
              document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();}
            const orig=el.dataset.lbl; el.textContent='copied ✓';
            setTimeout(()=>{el.textContent=orig;},1300);
          };
        });
        d.classList.add('open');
      }

      // ── public ──────────────────────────────────────────────
      recenter() { this._scatter(); }
      toggleHeat() { this.heat=!this.heat; return this.heat; }
      zoomBy(dir) {
        const f=dir>0?1.25:.8, cx=this.cW/2, cy=this.cH/2;
        const nz=Math.max(.08,Math.min(7,this.zoom*f));
        const [wx,wy]=this._world(cx,cy);
        this.zoom=nz; this.panX=cx-wx*nz; this.panY=cy-wy*nz;
      }
      exportPNG() {
        this._draw();
        const a=document.createElement('a');
        a.download=`attack-surface-${D.target}.png`;
        a.href=this.canvas.toDataURL('image/png');
        a.click();
      }

      _loop() {
        if (this.ticks<600) this._step();
        this._draw();
        requestAnimationFrame(()=>this._loop());
      }
    }

    /* kick off */
    const fg=new ForceGraph(canvas, detailEl, tipEl, GD.nodes, GD.edges);

    document.getElementById('gc-recenter').onclick=()=>fg.recenter();
    document.getElementById('gc-heat').onclick=function(){
      const on=fg.toggleHeat();
      this.classList.toggle('active',on);
      this.textContent=on?'⚡ show all':'⚡ vulns only';
    };
    document.getElementById('gc-zi').onclick=()=>fg.zoomBy(1);
    document.getElementById('gc-zo').onclick=()=>fg.zoomBy(-1);
    document.getElementById('gc-png').onclick=()=>fg.exportPNG();

    ctrl.querySelectorAll('[data-tf]').forEach(btn=>{
      btn.onclick=function(){
        ctrl.querySelectorAll('[data-tf]').forEach(b=>b.classList.remove('active'));
        this.classList.add('active');
        fg.setFilter(this.dataset.tf);
      };
    });
  }
}

/* ── footer ──────────────────────────────────────────────────── */
{
  const wslLine = D.win_dir
    ? `<br>${esc(D.win_dir)}${D.file_url
        ? ` · <a href="${esc(D.file_url)}">open in Windows browser</a>` : ''}` : '';
  wrap.appendChild(E('div', 'footer', `
    <span class="brand-f">TANYA</span>  v6.2  ·  ${esc(D.generated)}
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
        description="Generate an HTML recon report from a tanya output directory"
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
