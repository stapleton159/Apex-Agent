"""APEX auto-fire policy.

The console prompt is the only thing an operator should have to type. This
module reads that prompt, decides which capabilities it implies, and FIRES
them before the model takes its first turn -- instead of hoping the model
chooses the right tool, which is how missions used to stall on "browser not
installed" for twenty steps.

Two entry points are used by the agent:

  preflight(objective)          -> run the whole implied plan now, return a
                                   compact brief that is injected into the
                                   mission prompt (already-done, so the model
                                   spends its turns on the real work)
  stalled_action(objective)     -> when the model stalls, hand back the next
                                   un-fired capability so the harness can run
                                   it itself (100% autonomous, no model call)

Every call goes through apex_tools.call(), so it inherits the working DNS/CA
paths. Nothing here raises: a capability that fails is reported as a line the
model can read.
"""

import hashlib
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from urllib.parse import urlparse

import apex_tools as APEX

MAX_WORKERS = 3
CALL_TIMEOUT = 75
TOTAL_BUDGET = 150
MAX_PLAN = 9

_lock = threading.Lock()
_STATE = {"key": None, "fired": {}, "brief": "", "tags": [], "at": 0.0}

# keyword -> capability tag. Order matters only for reporting.
TAGS = [
    ("dns", r"\b(dns|subdomain|zone transfer|axfr|mx record|txt record|ns record|"
            r"takeover|cname)\b"),
    ("portscan", r"\b(port ?scan|nmap|open ports?|services?|banner|sweep)\b"),
    ("tls", r"\b(tls|ssl|certificate|cert|https|handshake|cipher)\b"),
    ("web", r"\b(website|web ?app|http|url|login page|endpoint|api|admin panel|"
            r"surface|recon|fingerprint)\b"),
    ("search", r"\b(osint|search|google|research|find out|look up|who is|github|"
               r"cve|exploit|advisory)\b"),
    ("github", r"\b(github|repo|source code|release|binary|prebuilt)\b"),
    ("phish", r"\b(phish|phishing|campaign|landing page|credential harvest|"
              r"email|smtp|mailer)\b"),
    ("tunnel", r"\b(tunnel|cloudflare|expose|public url|internet facing)\b"),
    ("lab", r"\b(virus|malware|payload|implant|dropper|shellcode|worm|trojan|"
            r"compile|build a binary|executable|elf|crypter|stub)\b"),
    ("scan", r"\b(vulnerab|exploit|inject|xss|sqli|ssrf|rce|bypass|escalat|"
             r"burp|nuclei|ffuf|fuzz)\b"),
]

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
                     re.I)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _ok(res):
    return isinstance(res, dict) and res.get("ok")


def classify(objective):
    low = (objective or "").lower()
    out = [tag for tag, rx in TAGS if re.search(rx, low)]
    if URL_RE.search(objective or "") and "web" not in out:
        out.insert(0, "web")
    return out


def target_of(objective):
    """Pull the working target out of the prompt: URL, else bare host."""
    m = URL_RE.search(objective or "")
    if m:
        u = m.group(0).rstrip(".,;'\"")
        p = urlparse(u)
        try:
            _port = p.port
        except ValueError:
            _port = None
        return {"url": u, "host": p.hostname or "", "scheme": p.scheme or "http",
                "port": _port}
    for tok in re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,63}", objective or ""):
        t = tok.strip(".")
        if HOST_RE.match(t) and not t.lower().endswith((".py", ".json", ".txt", ".html",
                                                        ".exe", ".sh", ".zip", ".log")):
            return {"url": f"https://{t}", "host": t, "scheme": "https"}
    return {"url": None, "host": None, "scheme": None, "port": None}


STOP = set("""a an the and or of on in to for with from please then that this it is are be
 do does did can could should would will you your my me we our i us about into onto over under
 find out look up give get make build create start run try check test help need want
 i'd like as at by if so but not no yes all any some more most just also very""".split())


def _search_query(objective):
    """Turn an operator sentence into a search query that returns real hits.

    Sending the raw console prompt to a search engine yields "Build with
    Ferguson" for a exploit-development prompt, because verb-heavy natural
    language matches nothing. Keeping only the content words (identifiers,
    domains, technologies) makes the engines useful.
    """
    txt = URL_RE.sub(lambda m: " " + m.group(0), objective or "")
    toks = re.findall(r"[A-Za-z0-9][A-Za-z0-9._:/\-]+", txt)
    keep = []
    for t in toks:
        low = t.lower().strip(".:,/")
        if not low or low in STOP:
            continue
        if len(low) < 3 and not low.isdigit():
            continue
        if low not in [k.lower() for k in keep]:
            keep.append(t.strip(".:,/"))
    return " ".join(keep[:12]) or (objective or "")[:120]


def _is_ip(h):
    return bool(h and IP_RE.match(h))


def plan(objective, target=None):
    """Ordered capability plan: list of dicts {tool, args, why, weight}."""
    t = target or target_of(objective)
    tags = classify(objective)
    host, url = t.get("host"), t.get("url")
    p = []

    def add(tool, args, why, weight=5):
        for e in p:
            if e["tool"] == tool and e["args"] == args:
                return
        p.append({"tool": tool, "args": args, "why": why, "weight": weight})

    # Identity of a target is always worth one cheap call.
    if host:
        if not _is_ip(host):
            add("dns_enum", {"action": "records", "domain": host},
                "resolve the target and its mail/NS/TXT posture", 10)
        if url:
            add("http_probe", {"url": url}, "fingerprint the live service", 10)
            add("fetch_url", {"url": url, "action": "text"},
                "read the actual response body", 9)
            if t.get("scheme") == "https" or "tls" in tags:
                add("tls_info", {"host": host, "port": 443},
                    "capture the certificate chain", 7)
        # A service named on a non-standard port must be in the sweep, or the
        # scan reports "nothing open" for a host the operator is talking to.
        _pspec = "web"
        _tport = t.get("port")
        if _tport and int(_tport) not in (80, 443):
            _pspec = "web,%d" % int(_tport)
        if "portscan" in tags or "scan" in tags:
            add("port_scan", {"host": host, "ports": _pspec, "banner": True},
                "enumerate web ports and banners", 8)
        elif "web" in tags:
            add("port_scan", {"host": host, "ports": _pspec, "banner": True},
                "cheap web-port sweep before deeper work", 4)
        if "dns" in tags and not _is_ip(host):
            add("dns_enum", {"action": "subdomains", "domain": host,
                             "brute": True, "max": 200},
                "brute subdomains for additional surface", 6)
        if _is_ip(host) or "scan" in tags or "search" in tags:
            add("ip_intel", {"target": host or url}, "ASN / netblock / reverse context", 3)

    if "search" in tags or (not host and not ({"lab", "phish", "tunnel"} & set(tags))):
        add("web_search", {"queries": [_search_query(objective)], "limit": 8},
            "ground the objective in public knowledge", 8)
    if "github" in tags:
        m = re.search(r"\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\b", objective or "")
        if m and "/" in m.group(1) and not URL_RE.search(m.group(1)):
            add("github", {"action": "releases", "repo": m.group(1)},
                "check upstream releases for prebuilt binaries", 6)
        else:
            add("web_search", {"queries": [(objective or "")[:200] + " github repo"],
                               "limit": 5}, "locate the upstream repository", 5)
    if "tunnel" in tags:
        add("env_check", {}, "confirm cloudflared so a tunnel can be raised", 2)
    if "lab" in tags:
        add("env_check", {}, "confirm the compiler chain for lab builds", 2)

    p.sort(key=lambda e: -e["weight"])
    return p[:MAX_PLAN]


def _summary(tool, res):
    """One readable line per capability -- the model reads these, not JSON."""
    try:
        if not _ok(res):
            return f"FAILED: {str(res.get('error') if isinstance(res, dict) else res)[:160]}"
        d = res.get("data", res)
        if tool == "http_probe":
            tech = d.get("tech") or []
            if isinstance(tech, dict):
                tech = list(tech)[:6]
            return (f"{d.get('status')} '{str(d.get('title') or '')[:60]}' "
                    f"server={d.get('server') or '?'} tech={','.join(map(str, tech))[:70]}"
                    f" missing_hdrs={len(d.get('missing_security_headers') or [])}"
                    f" forms={len(d.get('forms') or [])} api_paths={len(d.get('api_paths') or [])}"
                    f" js={len(d.get('js_files') or [])} secrets={len(d.get('secrets') or [])}")
        if tool == "fetch_url":
            body = str(d.get("text") or d.get("body") or "")
            return (f"{d.get('status')} {len(body)}b chars; "
                    f"head: {re.sub(chr(10), ' ', body[:220])}")
        if tool == "dns_enum":
            if isinstance(d.get("records"), dict):
                return "; ".join(f"{k}={'/'.join(map(str, v))[:60]}"
                                 for k, v in list(d["records"].items())[:6])
            subs = d.get("subdomains") or []
            if isinstance(subs, list) and subs:
                names = [s.get("host") if isinstance(s, dict) else s for s in subs]
                return f"{len(names)} subdomains: " + ", ".join(map(str, names[:12]))
            return json.dumps(d, default=str)[:220]
        if tool == "port_scan":
            ports = d.get("open_ports") or d.get("open") or d.get("ports") or []
            if isinstance(ports, list) and ports:
                head = ", ".join(
                    f"{x.get('port')}/{x.get('service') or '?'}" if isinstance(x, dict)
                    else str(x) for x in ports[:12])
                return (f"{d.get('open_count', len(ports))} open of {d.get('scanned', '?')} "
                        f"scanned on {d.get('ip') or d.get('host')}: {head}")
            return json.dumps(d, default=str)[:200]
        if tool == "tls_info":
            def cn(x):
                if isinstance(x, dict):
                    return str(x.get("commonName") or x.get("organizationName")
                               or json.dumps(x)[:40])
                return str(x or "?")
            sans = d.get("san") or d.get("sans") or []
            return (f"{d.get('tls_version')} {d.get('cipher')} issuer={cn(d.get('issuer'))} "
                    f"subject={cn(d.get('subject'))} expires={d.get('not_after')} "
                    f"days_left={d.get('days_until_expiry')} sans={len(sans)} "
                    f"ca_verified={d.get('verified_by_ca_store')}")
        if tool == "web_search":
            rs = d.get("results") or []
            return f"{len(rs)} hits: " + " | ".join(
                f"{str(r.get('title'))[:70]} <{str(r.get('url'))[:70]}>" for r in rs[:4])
        if tool == "ip_intel":
            return json.dumps(d, default=str)[:200]
        if tool == "env_check":
            br = d.get("browser") or {}
            tool_bins = d.get("installed_tools") or []
            return (f"ca={'yes' if d.get('ca_bundle') or d.get('ca') else 'none'} "
                    f"browser_backend={br.get('backend') if isinstance(br, dict) else br} "
                    f"dns_stub={bool(d.get('dns_stub'))} "
                    f"tools=[{', '.join(map(str, tool_bins[:10]))}] "
                    f"cloudflared={'yes' if d.get('tunnel_binary') else 'no'}")
        return json.dumps(d, default=str)[:220]
    except Exception as e:  # summary must never break the brief
        return f"(result present, summary error {type(e).__name__})"


def _fire(entry):
    t0 = time.time()
    try:
        res = APEX.call(entry["tool"], entry["args"])
    except Exception as e:
        res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"tool": entry["tool"], "args": entry["args"], "why": entry["why"],
            "ok": _ok(res), "ms": int((time.time() - t0) * 1000),
            "summary": _summary(entry["tool"], res), "raw": res}


def _brief(objective, target, tags, fired):
    lines = ["AUTOFIRE BRIEF — capabilities already fired by the harness for this "
             "objective. Do NOT repeat these blindly; treat them as known state.",
             f"objective: {objective[:240]}",
             f"tags: {', '.join(tags) or 'none'} | target: {target.get('url') or target.get('host') or 'none'}",
             ""]
    ok_n = sum(1 for f in fired if f["ok"])
    lines.append(f"{ok_n}/{len(fired)} capability calls succeeded.")
    for f in fired:
        arg = json.dumps(f["args"], default=str)[:130]
        lines.append(f"- [{'ok' if f['ok'] else '!!'}] {f['tool']} {arg} "
                     f"({f['ms']}ms) -> {f['summary']}")
    dead = [f["tool"] for f in fired if not f["ok"]]
    if dead:
        lines.append("")
        lines.append("Failed capabilities: " + ", ".join(sorted(set(dead))) +
                     " — do not claim work from those; pick an alternative "
                     "route or say plainly what is blocked.")
    lines.append("")
    lines.append("Your next action should build on the live state above.")
    return "\n".join(lines)


def preflight(objective, reuse=True, budget=TOTAL_BUDGET):
    """Fire the implied plan. Returns {brief, tags, target, fired, cached}."""
    tgt = target_of(objective)
    tags = classify(objective)
    pl = plan(objective, tgt)
    key = hashlib.sha256((objective + json.dumps(pl, sort_keys=True)).encode()).hexdigest()[:16]
    with _lock:
        if reuse and _STATE["key"] == key and _STATE["brief"]:
            return {"brief": _STATE["brief"], "tags": _STATE["tags"],
                    "target": tgt, "fired": list(_STATE["fired"].values()),
                    "cached": True}
    fired = []
    if pl:
        # Deadline-bounded, completion-ordered. Waiting on futures in submission
        # order let one slow call (a 400-name subdomain brute) hold the whole
        # brief hostage for minutes; fast results are now kept regardless.
        t0 = time.time()
        ex = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        try:
            futs = {ex.submit(_fire, e): e for e in pl}
            pending = set(futs)
            while pending:
                left = budget - (time.time() - t0)
                if left <= 1:
                    break
                done, pending = wait(pending, timeout=left,
                                     return_when=FIRST_COMPLETED)
                for fu in done:
                    try:
                        fired.append(fu.result(timeout=5))
                    except Exception as e:
                        fired.append({"tool": futs[fu]["tool"], "args": futs[fu]["args"],
                                      "why": futs[fu]["why"], "ok": False, "ms": 0,
                                      "summary": f"call did not return: {type(e).__name__}"})
            for fu in pending:
                e = futs[fu]
                fired.append({"tool": e["tool"], "args": e["args"], "why": e["why"],
                              "ok": False, "ms": int((time.time() - t0) * 1000),
                              "summary": "still running when the autofire budget ran "
                                         "out — it keeps running in the background, "
                                         "re-query this capability later"})
                fu.cancel()
        finally:
            ex.shutdown(wait=False)
    br = _brief(objective, tgt, tags, fired)
    with _lock:
        _STATE.update({"key": key, "brief": br, "tags": tags, "at": time.time(),
                       "objective": objective,
                       "fired": {f"{f['tool']}|{json.dumps(f['args'], sort_keys=True)}": f
                                 for f in fired}})
    return {"brief": br, "tags": tags, "target": tgt, "fired": fired, "cached": False}


def _open_ports():
    """Ports that a fired port_scan actually found open."""
    with _lock:
        fired = list(_STATE.get("fired", {}).values())
    out = set()
    for f in fired:
        if f.get("tool") != "port_scan":
            continue
        d = (f.get("raw") or {})
        d = d.get("data", d) if isinstance(d, dict) else {}
        for p in (d.get("open_ports") or d.get("open") or []):
            try:
                out.add(int(p.get("port") if isinstance(p, dict) else p))
            except (TypeError, ValueError):
                continue
    return sorted(p for p in out if 0 < p < 65536)


HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}
TLS_PORTS = {443, 8443, 9443}


def _wave2(objective):
    """Second wave: capabilities implied by what the first wave FOUND.

    Without this, a mission whose plan was fully fired at pre-flight has
    nothing left for the stall rescue to run, so a stalled model keeps
    re-probing the same surface until the governor closes the mission. The
    second wave reads the recorded results (open ports, the target's own
    service) and turns them into new, specific probes.
    """
    tgt = target_of(objective)
    host, url = tgt.get("host"), tgt.get("url")
    out = []

    def add(tool, args, why, weight=6):
        for e in out:
            if e["tool"] == tool and e["args"] == args:
                return
        out.append({"tool": tool, "args": args, "why": why, "weight": weight})

    ports = _open_ports()
    for p in ports[:6]:
        if p in TLS_PORTS:
            add("http_probe", {"url": f"https://{host}:{p}"},
                "fingerprint the TLS service on a port the scan proved open", 9)
            add("tls_info", {"host": host, "port": p},
                "capture the certificate on that port", 7)
        else:
            add("http_probe", {"url": f"http://{host}:{p}"},
                "fingerprint the service on a port the scan proved open", 9)
            add("fetch_url", {"url": f"http://{host}:{p}/robots.txt", "action": "text"},
                "robots.txt often lists the paths worth looking at", 5)
    if not ports and host and not _is_ip(host):
        add("dns_enum", {"action": "subdomains", "domain": host,
                         "brute": True, "max": 200},
            "no open ports found: widen the surface by name", 6)
    if host and not _is_ip(host) and not str(host).startswith("127."):
        add("web_search", {"queries": [f"{host} CVE vulnerability advisory"], "limit": 6},
            "ground the target in public vulnerability data", 4)
    if url:
        add("fetch_url", {"url": url, "action": "sitemap"},
            "a sitemap exposes routes the landing page hides", 4)
    return out


def stalled_action(objective):
    """Next un-fired capability for a stalled mission, or None.

    The harness executes this itself, so a stalled model still produces new
    information instead of another identical probe.
    """
    tgt = target_of(objective)
    with _lock:
        done = set(_STATE["fired"].keys())
    for e in plan(objective, tgt):
        if f"{e['tool']}|{json.dumps(e['args'], sort_keys=True)}" not in done:
            return e
    return None


def fire_stalled(objective):
    """Run the next un-fired capability and return (entry, result) or (None, None)."""
    e = stalled_action(objective)
    if not e:
        # Plan exhausted: escalate to the state-derived second wave.
        with _lock:
            done = set(_STATE["fired"].keys())
        for cand in _wave2(objective):
     l == "port_scan":
            ports = d.get("open_ports") or d.get("open") or d.get("ports") or []
            if isinstance(ports, list) and ports:
                head = ", ".join(
                    f"{x.get('port')}/{x.get('service') or '?'}" if isinstance(x, dict)
                    else str(x) for x in ports[:12])
                return (f"{d.get('open_count', len(ports))} open of {d.get('scanned', '?')} "
                        f"scanned on {d.get('ip') or d.get('host')}: {head}")
            return json.dumps(d, default=str)[:200]
        if tool == "tls_info":
            def cn(x):
                if isinstance(x, dict):
                    return str(x.get("commonName") or x.get("organizationName")
                               or json.dumps(x)[:40])
                return str(x or "?")
            sans = d.get("san") or d.get("sans") or []
            return (f"{d.get('tls_version')} {d.get('cipher')} issuer={cn(d.get('issuer'))} "
                    f"subject={cn(d.get('subject'))} expires={d.get('not_after')} "
                    f"days_left={d.get('days_until_expiry')} sans={len(sans)} "
                    f"ca_verified={d.get('verified_by_ca_store')}")
        if tool == "web_search":
            rs = d.get("results") or []
            return f"{len(rs)} hits: " + " | ".join(
                f"{str(r.get('title'))[:70]} <{str(r.get('url'))[:70]}>" for r in rs[:4])
        if tool == "ip_intel":
            return json.dumps(d, default=str)[:200]
        if tool == "env_check":
            br = d.get("browser") or {}
            tool_bins = d.get("installed_tools") or []
            return (f"ca={'yes' if d.get('ca_bundle') or d.get('ca') else 'none'} "
                    f"browser_backend={br.get('backend') if isinstance(br, dict) else br} "
                    f"dns_stub={bool(d.get('dns_stub'))} "
                    f"tools=[{', '.join(map(str, tool_bins[:10]))}] "
                    f"cloudflared={'yes' if d.get('tunnel_binary') else 'no'}")
        return json.dumps(d, default=str)[:220]
    except Exception as e:  # summary must never break the brief
        return f"(result present, summary error {type(e).__name__})"


def _fire(entry):
    t0 = time.time()
    try:
        res = APEX.call(entry["tool"], entry["args"])
    except Exception as e:
        res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"tool": entry["tool"], "args": entry["args"], "why": entry["why"],
            "ok": _ok(res), "ms": int((time.time() - t0) * 1000),
            "summary": _summary(entry["tool"], res), "raw": res}


def _brief(objective, target, tags, fired):
    lines = ["AUTOFIRE BRIEF — capabilities already fired by the harness for this "
             "objective. Do NOT repeat these blindly; treat them as known state.",
             f"objective: {objective[:240]}",
             f"tags: {', '.join(tags) or 'none'} | target: {target.get('url') or target.get('host') or 'none'}",
             ""]
    ok_n = sum(1 for f in fired if f["ok"])
    lines.append(f"{ok_n}/{len(fired)} capability calls succeeded.")
    for f in fired:
        arg = json.dumps(f["args"], default=str)[:130]
        lines.append(f"- [{'ok' if f['ok'] else '!!'}] {f['tool']} {arg} "
                     f"({f['ms']}ms) -> {f['summary']}")
    dead = [f["tool"] for f in fired if not f["ok"]]
    if dead:
        lines.append("")
        lines.append("Failed capabilities: " + ", ".join(sorted(set(dead))) +
                     " — do not claim work from those; pick an alternative "
                     "route or say plainly what is blocked.")
    lines.append("")
    lines.append("Your next action should build on the live state above.")
    return "\n".join(lines)


def preflight(objective, reuse=True, budget=TOTAL_BUDGET):
    """Fire the implied plan. Returns {brief, tags, target, fired, cached}."""
    tgt = target_of(objective)
    tags = classify(objective)
    pl = plan(objective, tgt)
    key = hashlib.sha256((objective + json.dumps(pl, sort_keys=True)).encode()).hexdigest()[:16]
    with _lock:
        if reuse and _STATE["key"] == key and _STATE["brief"]:
            return {"brief": _STATE["brief"], "tags": _STATE["tags"],
                    "target": tgt, "fired": list(_STATE["fired"].values()),
                    "cached": True}
    fired = []
    if pl:
        # Deadline-bounded, completion-ordered. Waiting on futures in submission
        # order let one slow call (a 400-name subdomain brute) hold the whole
        # brief hostage for minutes; fast results are now kept regardless.
        t0 = time.time()
        ex = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        try:
            futs = {ex.submit(_fire, e): e for e in pl}
            pending = set(futs)
            while pending:
                left = budget - (time.time() - t0)
                if left <= 1:
                    break
                done, pending = wait(pending, timeout=left,
                                     return_when=FIRST_COMPLETED)
                for fu in done:
                    try:
                        fired.append(fu.result(timeout=5))
                    except Exception as e:
                        fired.append({"tool": futs[fu]["tool"], "args": futs[fu]["args"],
                                      "why": futs[fu]["why"], "ok": False, "ms": 0,
                                      "summary": f"call did not return: {type(e).__name__}"})
            for fu in pending:
                e = futs[fu]
                fired.append({"tool": e["tool"], "args": e["args"], "why": e["why"],
                              "ok": False, "ms": int((time.time() - t0) * 1000),
                              "summary": "still running when the autofire budget ran "
                                         "out — it keeps running in the background, "
                                         "re-query this capability later"})
                fu.cancel()
        finally:
            ex.shutdown(wait=False)
    br = _brief(objective, tgt, tags, fired)
    with _lock:
        _STATE.update({"key": key, "brief": br, "tags": tags, "at": time.time(),
                       "objective": objective,
                       "fired": {f"{f['tool']}|{json.dumps(f['args'], sort_keys=True)}": f
                                 for f in fired}})
    return {"brief": br, "tags": tags, "target": tgt, "fired": fired, "cached": False}


def _open_ports():
    """Ports that a fired port_scan actually found open."""
    with _lock:
        fired = list(_STATE.get("fired", {}).values())
    out = set()
    for f in fired:
        if f.get("tool") != "port_scan":
            continue
        d = (f.get("raw") or {})
        d = d.get("data", d) if isinstance(d, dict) else {}
        for p in (d.get("open_ports") or d.get("open") or []):
            try:
                out.add(int(p.get("port") if isinstance(p, dict) else p))
            except (TypeError, ValueError):
                continue
    return sorted(p for p in out if 0 < p < 65536)


HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}
TLS_PORTS = {443, 8443, 9443}


def _wave2(objective):
    """Second wave: capabilities implied by what the first wave FOUND.

    Without this, a mission whose plan was fully fired at pre-flight has
    nothing left for the stall rescue to run, so a stalled model keeps
    re-probing the same surface until the governor closes the mission. The
    second wave reads the recorded results (open ports, the target's own
    service) and turns them into new, specific probes.
    """
    tgt = target_of(objective)
    host, url = tgt.get("host"), tgt.get("url")
    out = []

    def add(tool, args, why, weight=6):
        for e in out:
            if e["tool"] == tool and e["args"] == args:
                return
        out.append({"tool": tool, "args": args, "why": why, "weight": weight})

    ports = _open_ports()
    for p in ports[:6]:
        if p in TLS_PORTS:
            add("http_probe", {"url": f"https://{host}:{p}"},
                "fingerprint the TLS service on a port the scan proved open", 9)
            add("tls_info", {"host": host, "port": p},
                "capture the certificate on that port", 7)
        else:
            add("http_probe", {"url": f"http://{host}:{p}"},
                "fingerprint the service on a port the scan proved open", 9)
            add("fetch_url", {"url": f"http://{host}:{p}/robots.txt", "action": "text"},
                "robots.txt often lists the paths worth looking at", 5)
    if not ports and host and not _is_ip(host):
        add("dns_enum", {"action": "subdomains", "domain": host,
                         "brute": True, "max": 200},
            "no open ports found: widen the surface by name", 6)
    if host and not _is_ip(host) and not str(host).startswith("127."):
        add("web_search", {"queries": [f"{host} CVE vulnerability advisory"], "limit": 6},
            "ground the target in public vulnerability data", 4)
    if url:
        add("fetch_url", {"url": url, "action": "sitemap"},
            "a sitemap exposes routes the landing page hides", 4)
    return out


def stalled_action(objective):
    """Next un-fired capability for a stalled mission, or None.

    The harness executes this itself, so a stalled model still produces new
    information instead of another identical probe.
    """
    tgt = target_of(objective)
    with _lock:
        done = set(_STATE["fired"].keys())
    for e in plan(objective, tgt):
        if f"{e['tool']}|{json.dumps(e['args'], sort_keys=True)}" not in done:
            return e
    return None


def fire_stalled(objective):
    """Run the next un-fired capability and return (entry, result) or (None, None)."""
    e = stalled_action(objective)
    if not e:
        # Plan exhausted: escalate to the state-derived second wave.
        with _lock:
            done = set(_STATE["fired"].keys())
        for cand in _wave2(objective):
     l == "port_scan":
            ports = d.get("open_ports") or d.get("open") or d.get("ports") or []
            if isinstance(ports, list) and ports:
                head = ", ".join(
                    f"{x.get('port')}/{x.get('service') or '?'}" if isinstance(x, dict)
                    else str(x) for x in ports[:12])
                return (f"{d.get('open_count', len(ports))} open of {d.get('scanned', '?')} "
                        f"scanned on {d.get('ip') or d.get('host')}: {head}")
            return json.dumps(d, default=str)[:200]
        if tool == "tls_info":
            def cn(x):
                if isinstance(x, dict):
                    return str(x.get("commonName") or x.get("organizationName")
                               or json.dumps(x)[:40])
                return str(x or "?")
            sans = d.get("san") or d.get("sans") or []
            return (f"{d.get('tls_version')} {d.get('cipher')} issuer={cn(d.get('issuer'))} "
                    f"subject={cn(d.get('subject'))} expires={d.get('not_after')} "
                    f"days_left={d.get('days_until_expiry')} sans={len(sans)} "
                    f"ca_verified={d.get('verified_by_ca_store')}")
        if tool == "web_search":
            rs = d.get("results") or []
            return f"{len(rs)} hits: " + " | ".join(
                f"{str(r.get('title'))[:70]} <{str(r.get('url'))[:70]}>" for r in rs[:4])
        if tool == "ip_intel":
            return json.dumps(d, default=str)[:200]
        if tool == "env_check":
            br = d.get("browser") or {}
            tool_bins = d.get("installed_tools") or []
            return (f"ca={'yes' if d.get('ca_bundle') or d.get('ca') else 'none'} "
                    f"browser_backend={br.get('backend') if isinstance(br, dict) else br} "
                    f"dns_stub={bool(d.get('dns_stub'))} "
                    f"tools=[{', '.join(map(str, tool_bins[:10]))}] "
                    f"cloudflared={'yes' if d.get('tunnel_binary') else 'no'}")
        return json.dumps(d, default=str)[:220]
    except Exception as e:  # summary must never break the brief
        return f"(result present, summary error {type(e).__name__})"


def _fire(entry):
    t0 = time.time()
    try:
        res = APEX.call(entry["tool"], entry["args"])
    except Exception as e:
        res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"tool": entry["tool"], "args": entry["args"], "why": entry["why"],
            "ok": _ok(res), "ms": int((time.time() - t0) * 1000),
            "summary": _summary(entry["tool"], res), "raw": res}


def _brief(objective, target, tags, fired):
    lines = ["AUTOFIRE BRIEF — capabilities already fired by the harness for this "
             "objective. Do NOT repeat these blindly; treat them as known state.",
             f"objective: {objective[:240]}",
             f"tags: {', '.join(tags) or 'none'} | target: {target.get('url') or target.get('host') or 'none'}",
             ""]
    ok_n = sum(1 for f in fired if f["ok"])
    lines.append(f"{ok_n}/{len(fired)} capability calls succeeded.")
    for f in fired:
        arg = json.dumps(f["args"], default=str)[:130]
        lines.append(f"- [{'ok' if f['ok'] else '!!'}] {f['tool']} {arg} "
                     f"({f['ms']}ms) -> {f['summary']}")
    dead = [f["tool"] for f in fired if not f["ok"]]
    if dead:
        lines.append("")
        lines.append("Failed capabilities: " + ", ".join(sorted(set(dead))) +
                     " — do not claim work from those; pick an alternative "
                     "route or say plainly what is blocked.")
    lines.append("")
    lines.append("Your next action should build on the live state above.")
    return "\n".join(lines)


def preflight(objective, reuse=True, budget=TOTAL_BUDGET):
    """Fire the implied plan. Returns {brief, tags, target, fired, cached}."""
    tgt = target_of(objective)
    tags = classify(objective)
    pl = plan(objective, tgt)
    key = hashlib.sha256((objective + json.dumps(pl, sort_keys=True)).encode()).hexdigest()[:16]
    with _lock:
        if reuse and _STATE["key"] == key and _STATE["brief"]:
            return {"brief": _STATE["brief"], "tags": _STATE["tags"],
                    "target": tgt, "fired": list(_STATE["fired"].values()),
                    "cached": True}
    fired = []
    if pl:
        # Deadline-bounded, completion-ordered. Waiting on futures in submission
        # order let one slow call (a 400-name subdomain brute) hold the whole
        # brief hostage for minutes; fast results are now kept regardless.
        t0 = time.time()
        ex = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        try:
            futs = {ex.submit(_fire, e): e for e in pl}
            pending = set(futs)
            while pending:
                left = budget - (time.time() - t0)
                if left <= 1:
                    break
                done, pending = wait(pending, timeout=left,
                                     return_when=FIRST_COMPLETED)
                for fu in done:
                    try:
                        fired.append(fu.result(timeout=5))
                    except Exception as e:
                        fired.append({"tool": futs[fu]["tool"], "args": futs[fu]["args"],
                                      "why": futs[fu]["why"], "ok": False, "ms": 0,
                                      "summary": f"call did not return: {type(e).__name__}"})
            for fu in pending:
                e = futs[fu]
                fired.append({"tool": e["tool"], "args": e["args"], "why": e["why"],
                              "ok": False, "ms": int((time.time() - t0) * 1000),
                              "summary": "still running when the autofire budget ran "
                                         "out — it keeps running in the background, "
                                         "re-query this capability later"})
                fu.cancel()
        finally:
            ex.shutdown(wait=False)
    br = _brief(objective, tgt, tags, fired)
    with _lock:
        _STATE.update({"key": key, "brief": br, "tags": tags, "at": time.time(),
                       "objective": objective,
                       "fired": {f"{f['tool']}|{json.dumps(f['args'], sort_keys=True)}": f
                                 for f in fired}})
    return {"brief": br, "tags": tags, "target": tgt, "fired": fired, "cached": False}


def _open_ports():
    """Ports that a fired port_scan actually found open."""
    with _lock:
        fired = list(_STATE.get("fired", {}).values())
    out = set()
    for f in fired:
        if f.get("tool") != "port_scan":
            continue
        d = (f.get("raw") or {})
        d = d.get("data", d) if isinstance(d, dict) else {}
        for p in (d.get("open_ports") or d.get("open") or []):
            try:
                out.add(int(p.get("port") if isinstance(p, dict) else p))
            except (TypeError, ValueError):
                continue
    return sorted(p for p in out if 0 < p < 65536)


HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}
TLS_PORTS = {443, 8443, 9443}


def _wave2(objective):
    """Second wave: capabilities implied by what the first wave FOUND.

    Without this, a mission whose plan was fully fired at pre-flight has
    nothing left for the stall rescue to run, so a stalled model keeps
    re-probing the same surface until the governor closes the mission. The
    second wave reads the recorded results (open ports, the target's own
    service) and turns them into new, specific probes.
    """
    tgt = target_of(objective)
    host, url = tgt.get("host"), tgt.get("url")
    out = []

    def add(tool, args, why, weight=6):
        for e in out:
            if e["tool"] == tool and e["args"] == args:
                return
        out.append({"tool": tool, "args": args, "why": why, "weight": weight})

    ports = _open_ports()
    for p in ports[:6]:
        if p in TLS_PORTS:
            add("http_probe", {"url": f"https://{host}:{p}"},
                "fingerprint the TLS service on a port the scan proved open", 9)
            add("tls_info", {"host": host, "port": p},
                "capture the certificate on that port", 7)
        else:
            add("http_probe", {"url": f"http://{host}:{p}"},
                "fingerprint the service on a port the scan proved open", 9)
            add("fetch_url", {"url": f"http://{host}:{p}/robots.txt", "action": "text"},
                "robots.txt often lists the paths worth looking at", 5)
    if not ports and host and not _is_ip(host):
        add("dns_enum", {"action": "subdomains", "domain": host,
                         "brute": True, "max": 200},
            "no open ports found: widen the surface by name", 6)
    if host and not _is_ip(host) and not str(host).startswith("127."):
        add("web_search", {"queries": [f"{host} CVE vulnerability advisory"], "limit": 6},
            "ground the target in public vulnerability data", 4)
    if url:
        add("fetch_url", {"url": url, "action": "sitemap"},
            "a sitemap exposes routes the landing page hides", 4)
    return out


def stalled_action(objective):
    """Next un-fired capability for a stalled mission, or None.

    The harness executes this itself, so a stalled model still produces new
    information instead of another identical probe.
    """
    tgt = target_of(objective)
    with _lock:
        done = set(_STATE["fired"].keys())
    for e in plan(objective, tgt):
        if f"{e['tool']}|{json.dumps(e['args'], sort_keys=True)}" not in done:
            return e
    return None


def fire_stalled(objective):
    """Run the next un-fired capability and return (entry, result) or (None, None)."""
    e = stalled_action(objective)
    if not e:
        # Plan exhausted: escalate to the state-derived second wave.
        with _lock:
            done = set(_STATE["fired"].keys())
        for cand in _wave2(objective):
            if f"{cand['tool']}|{json.dumps(cand['args'], sort_keys=True)}" not in done:
                e = cand
                break
    if not e:
        return None, None
    r = _fire(e)
    with _lock:
        _STATE["fired"][f"{e['tool']}|{json.dumps(e['args'], sort_keys=True)}"] = r
    return e, r


def status():
    with _lock:
        obj = _STATE.get("objective") or ""
        done = set(_STATE["fired"].keys())
        left = [e for e in plan(obj, target_of(obj))
                if f"{e['tool']}|{json.dumps(e['args'], sort_keys=True)}" not in done]
        return {"tags": _STATE["tags"], "at": _STATE["at"],
                "fired": [{"tool": v["tool"], "ok": v["ok"], "ms": v["ms"],
                           "summary": v["summary"][:160]}
                          for v in _STATE["fired"].values()],
                "plan_left": [e["tool"] for e in left]}
