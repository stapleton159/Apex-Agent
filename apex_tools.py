#!/usr/bin/env python3
"""
apex_tools — the capability layer for the APEX agent.

Why this module exists
----------------------
The agent kept "trying something and failing". Nearly every one of those
failures traced back to one of five environment facts, not to the model:

  1. There is no /etc/resolv.conf on this host, so every Go/musl binary
     (cloudflared, nuclei, httpx, ffuf …) and dnspython itself fails with
     "NoResolverConfiguration / lookup … connection refused". Python's
     requests works because it uses libc.
  2. There is no CA bundle at the path Go expects, so any Go binary that
     does HTTPS dies with "x509: certificate signed by unknown authority".
  3. The host resolver sometimes returns NXDOMAIN (negative cache / local
     filtering) for names that do exist. Anything that trusts libc silently
     loses whole domains.
  4. Almost no security binaries are installed (no nmap, dig, whois, openssl,
     chromium, hashcat …), and "pip install tool" never yields a CLI.
  5. Tools that exist took a narrow argument shape, so a plausible call was
     silently a no-op.

Each of those is handled here rather than worked around in the prompt:

  * Resolver      DNS over HTTPS (no /etc/resolv.conf needed), with a
                  localhost DNS stub so *binary* tools resolve too, plus a
                  getaddrinfo pin so HTTPS to a DoH-resolved address still
                  validates the certificate against the real hostname.
  * env_for_child() gives every subprocess a CA bundle and a sane locale.
  * provision     installs real release binaries (ffuf, nuclei, subfinder,
                  httpx, katana, naabu, dnsx, cloudflared, …) from GitHub
                  for this CPU/OS, verifies they run, and puts them on PATH.
  * github        repo/code search, trees, files, releases, asset download,
                  shallow clone — the "download anything from GitHub" layer.
  * download      streaming download with resume, hashing, sniffing and
                  automatic archive extraction.
  * web           multi-engine search, readability extraction, link/form/
                  endpoint/secret harvesting, sitemap, robots, wayback.
  * net           port scan with banners, TLS inspection without openssl,
                  IP/ASN intel, HTTP probe with tech fingerprinting.
  * tunnel        cloudflared quick tunnels: a public HTTPS URL for any
                  local port in seconds, with health verification that does
                  not depend on the broken local resolver.
  * browser       one interface over playwright → CDP → agent-browser CLI →
                  static fetch, so the tool degrades instead of failing.

Public entry point:

    import apex_tools
    apex_tools.call("github", {"action": "releases", "repo": "ffuf/ffuf"})
    apex_tools.call("port_scan", {"host": "example.com", "ports": "1-1000"})

Every call returns a JSON-able dict with "ok" plus either payload fields or
"error". Nothing raises.
"""
from __future__ import annotations

import base64
import contextlib
import fnmatch
import hashlib
import html as _htmlmod
import io
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from concurrent import futures
from urllib.parse import (urljoin, urlparse, urlencode, quote, unquote,
                          parse_qsl, urlsplit, urlunsplit)

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================================================
# PATHS / CONSTANTS
# ==========================================================================

IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "")
ROOT = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.environ.get("APEX_WORKSPACE") or (
    os.path.join(os.path.expanduser("~"), "apex_workspace") if IS_TERMUX
    else os.path.join(ROOT, "workspace"))
BIN_DIR = os.path.join(ROOT, "bin")
DL_DIR = os.path.join(WORKSPACE, "downloads")
TUNNEL_STATE = os.path.join(WORKSPACE, "tunnels.json")
for d in (WORKSPACE, DL_DIR, BIN_DIR):
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass

UA = ("Mozilla/5.0 (Linux; Android 14; arm64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
BOT_UA = "APEX-Recon/2.0 (+authorized-assessment)"
TIMEOUT = int(os.environ.get("APEX_HTTP_TIMEOUT", "30"))
MAX_BODY = int(os.environ.get("APEX_MAX_BODY", "4000000"))
MAX_OUT = int(os.environ.get("MAX_OUTPUT", "8000"))

ARCH = (platform.machine() or "").lower()
OSNAME = "linux"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})


def _arch_tokens():
    """Release-asset arch tokens this CPU answers to."""
    if ARCH in ("aarch64", "arm64", "armv8", "armv8l"):
        return ["arm64", "aarch64"]
    if ARCH.startswith("armv7") or ARCH.startswith("arm"):
        return ["armv7", "armhf", "arm"]
    if ARCH in ("x86_64", "amd64"):
        return ["x86_64", "amd64", "64bit"]
    if ARCH in ("i386", "i686", "x86"):
        return ["386", "i386", "32bit"]
    return [ARCH] if ARCH else []


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _ca_bundle():
    try:
        import certifi
        p = certifi.where()
        if os.path.isfile(p):
            return p
    except Exception:
        pass
    for p in ("/system/etc/security/cacerts", "/etc/ssl/certs/ca-certificates.crt",
              "/etc/pki/tls/certs/ca-bundle.crt"):
        if os.path.exists(p):
            return p
    return None


def env_for_child():
    """Environment for subprocesses: CA bundle, PATH with our bin dir, locale.

    Without SSL_CERT_FILE every Go binary fails TLS on this host, and without
    our bin dir on PATH a freshly provisioned tool looks 'not found'.
    """
    env = dict(os.environ)
    ca = _ca_bundle()
    if ca:
        env.setdefault("SSL_CERT_FILE", ca)
        if os.path.isdir(ca):
            env.setdefault("SSL_CERT_DIR", ca)
    env["PATH"] = BIN_DIR + os.pathsep + env.get("PATH", "")
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("LC_ALL", "C.UTF-8")
    env.setdefault("HOME", os.path.expanduser("~"))
    # Termux/Android: keep Go and friends from looking for a resolver config
    env.setdefault("GODEBUG", "netdns=go")
    env.setdefault("GOTOOLCHAIN", "local")
    return env


def which(binary):
    """Locate a binary including our managed bin dir."""
    if not binary:
        return None
    if os.path.isabs(binary) and os.access(binary, os.X_OK):
        return binary
    return shutil.which(binary, path=env_for_child()["PATH"])


def run(cmd, timeout=120, input_text=None, cwd=None):
    """Run a command with the child env; never raises."""
    if isinstance(cmd, (list, tuple)):
        argv, shell = list(cmd), False
    else:
        argv, shell = cmd, True
    try:
        p = subprocess.run(argv, shell=shell, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd or WORKSPACE,
                           env=env_for_child(), input=input_text,
                           errors="replace")
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
        return {"ok": p.returncode == 0, "rc": p.returncode,
                "out": out.strip()[:MAX_OUT * 4], "stdout": (p.stdout or "")[:MAX_OUT * 4],
                "stderr": (p.stderr or "")[:MAX_OUT]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": None, "out": "",
                "error": f"timed out after {timeout}s"}
    except FileNotFoundError:
        return {"ok": False, "rc": None, "out": "", "error": "binary not found"}
    except Exception as e:
        return {"ok": False, "rc": None, "out": "", "error": f"{type(e).__name__}: {e}"}


# ==========================================================================
# 1. RESOLVER — DoH first, localhost stub for binaries, getaddrinfo pinning
# ==========================================================================

DOH_ENDPOINTS = [
    ("https://dns.google/resolve", {"Accept": "application/dns-json"}, "google"),
    ("https://cloudflare-dns.com/dns-query",
     {"Accept": "application/dns-json"}, "cloudflare"),
    ("https://dns.quad9.net:5053/dns-query", {"Accept": "application/dns-json"}, "quad9"),
]

_RR_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
             "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257, "DS": 43,
             "DNSKEY": 48, "NSEC": 47, "NAPTR": 35, "TLSA": 52, "ANY": 255}
_codes = {v: k for k, v in _RR_TYPES.items()}

_cache = {}
_cache_lock = threading.Lock()
CACHE_TTL = 300


class Resolver:
    """DNS over HTTPS with cache and multi-provider fallback."""

    def __init__(self):
        self.last_provider = None
        self.stats = {"hits": 0, "queries": 0}

    def query(self, name, rtype="A", doh_only=True):
        rtype = rtype.upper().strip()
        if rtype not in _RR_TYPES:
            return {"ok": False, "error": f"unsupported record type {rtype!r}",
                    "supported": sorted(_RR_TYPES)}
        name = name.strip().rstrip(".")
        key = (name.lower(), rtype)
        now = time.time()
        with _cache_lock:
            hit = _cache.get(key)
            if hit and hit[0] > now:
                self.stats["hits"] += 1
                return {"ok": True, "name": name, "type": rtype,
                        "records": hit[1], "cached": True,
                        "provider": self.last_provider}
        self.stats["queries"] += 1
        errors = []
        for url, hdrs, label in DOH_ENDPOINTS:
            try:
                r = SESSION.get(url, params={"name": name, "type": rtype},
                                headers=hdrs, timeout=12, verify=False)
                if r.status_code != 200:
                    errors.append(f"{label}: HTTP {r.status_code}")
                    continue
                j = r.json()
                status = j.get("Status", 0)
                if status == 3:           # NXDOMAIN — authoritative, stop here
                    return {"ok": False, "name": name, "type": rtype,
                            "error": "NXDOMAIN (name does not exist)",
                            "provider": label, "nxdomain": True}
                if status != 0:
                    errors.append(f"{label}: rcode {status}")
                    continue
                recs = []
                for ans in j.get("Answer", []) or []:
                    if ans.get("type") == _RR_TYPES.get("CNAME") and rtype != "CNAME":
                        recs.append({"type": "CNAME", "ttl": ans.get("TTL"),
                                     "value": ans.get("data", "").rstrip(".")})
                        continue
                    if _codes.get(ans.get("type")) != rtype and rtype != "ANY":
                        continue
                    val = str(ans.get("data", ""))
                    if rtype == "TXT":
                        val = val.strip('"')
                    recs.append({"type": rtype, "ttl": ans.get("TTL"),
                                 "value": val.rstrip(".") if rtype != "TXT" else val})
                if rtype == "MX":
                    parsed = []
                    for rec in recs:
                        m = re.match(r"(\d+)\s+(\S+)", rec["value"])
                        parsed.append({"preference": int(m.group(1)) if m else None,
                                       "exchange": (m.group(2) if m else rec["value"]).rstrip(".")})
                    recs = parsed
                if rtype == "SOA":
                    parsed = []
                    for rec in recs:
                        f = rec["value"].split()
                        if len(f) >= 7:
                            parsed.append({"mname": f[0], "rname": f[1], "serial": f[2],
                                           "refresh": f[3], "retry": f[4],
                                           "expire": f[5], "minimum": f[6]})
                        else:
                            parsed.append({"raw": rec["value"]})
                    recs = parsed
                ttl = min([r_["ttl"] for r_ in j.get("Answer", [])
                           if isinstance(r_.get("ttl"), int)] or [CACHE_TTL])
                ttl = max(30, min(int(ttl or CACHE_TTL), 3600))
                with _cache_lock:
                    _cache[key] = (now + ttl, recs)
                self.last_provider = label
                return {"ok": True, "name": name, "type": rtype, "records": recs,
                        "provider": label, "ttl": ttl}
            except Exception as e:
                errors.append(f"{label}: {type(e).__name__}: {str(e)[:80]}")
                continue
        return {"ok": False, "name": name, "type": rtype,
                "error": "all DoH providers failed", "detail": errors}

    def ips(self, host, want="A"):
        """Return IP strings for a host, falling back to libc and literals."""
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        out = []
        for rt in ([want] if want else ["A", "AAAA"]):
            res = self.query(host, rt)
            if res.get("ok"):
                for rec in res.get("records", []):
                    v = rec.get("value") if isinstance(rec, dict) else rec
                    if v and _is_ip(v):
                        out.append(v)
        if not out:
            try:
                out = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
            except Exception:
                out = []
        seen, uniq = set(), []
        for ip in out:
            if ip not in seen:
                seen.add(ip)
                uniq.append(ip)
        return uniq

    def reverse(self, ip):
        try:
            rev = ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return {"ok": False, "error": "not an IP address"}
        res = self.query(rev, "PTR")
        if res.get("ok"):
            return {"ok": True, "ip": ip,
                    "ptr": [r["value"] for r in res["records"] if isinstance(r, dict)]}
        return {"ok": False, "ip": ip, "error": res.get("error")}


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


RESOLVER = Resolver()


def _fmt_addrs(ips):
    return ", ".join(ips[:6])


class LocalDNSStub:
    """Forwarder on 127.0.0.1:53 (+ ::1) so binaries without resolver config work.

    This host has no /etc/resolv.conf. Go binaries fall back to 127.0.0.1:53,
    which refuses connections, so cloudflared/nuclei/ffuf cannot resolve
    anything. Running a tiny forwarder on that address fixes every binary at
    once instead of patching each tool.
    """

    def __init__(self):
        self.udp = None
        self.tcp = None
        self.running = False
        self.error = None
        self.upstreams = [("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 53)]
        self._threads = []

    def _udp_loop(self, sock):
        while self.running:
            try:
                data, peer = sock.recvfrom(4096)
            except OSError:
                if not self.running:
                    return
                continue
            except Exception:
                continue

            def fwd(data=data, peer=peer):
                up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up.settimeout(4)
                try:
                    for u in self.upstreams:
                        try:
                            up.sendto(data, u)
                            resp, _ = up.recvfrom(65535)
                            sock.sendto(resp, peer)
                            return
                        except Exception:
                            continue
                finally:
                    up.close()

            threading.Thread(target=fwd, daemon=True).start()

    def _tcp_loop(self, sock):
        while self.running:
            try:
                conn, _ = sock.accept()
            except OSError:
                if not self.running:
                    return
                continue
            except Exception:
                continue

            def handle(conn=conn):
                try:
                    conn.settimeout(6)
                    head = conn.recv(2)
                    if len(head) < 2:
                        return
                    need = int.from_bytes(head, "big")
                    buf = b""
                    while len(buf) < need:
                        chunk = conn.recv(need - len(buf))
                        if not chunk:
                            return
                        buf += chunk
                    up = socket.create_connection(self.upstreams[0], timeout=5)
                    up.sendall(len(buf).to_bytes(2, "big") + buf)
                    n = int.from_bytes(up.recv(2), "big")
                    body = b""
                    while len(body) < n:
                        body += up.recv(n - len(body))
                    conn.sendall(len(body).to_bytes(2, "big") + body)
                    up.close()
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

            threading.Thread(target=handle, daemon=True).start()

    def start(self):
        if self.running:
            return True
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            u.bind(("127.0.0.1", 53))
            self.udp = u
        except Exception as e:
            self.error = f"cannot bind udp/53: {e}"
            return False
        try:
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            t.bind(("127.0.0.1", 53))
            t.listen(32)
            t.settimeout(1.0)
            self.tcp = t
        except Exception:
            self.tcp = None
        self.running = True
        for target, args in ((self._udp_loop, (self.udp,)),
                             (self._tcp_loop, (self.tcp,)) if self.tcp else None):
            if not target:
                continue
            th = threading.Thread(target=target, args=args, daemon=True)
            th.start()
            self._threads.append(th)
        return True

    def stop(self):
        self.running = False
        for s in (self.udp, self.tcp):
            with contextlib.suppress(Exception):
                s.close()
        self.udp = self.tcp = None

    def status(self):
        return {"running": self.running, "error": self.error,
                "listening": "127.0.0.1:53" if self.running else None}


DNS_STUB = LocalDNSStub()
if os.environ.get("APEX_NO_DNS_STUB", "0") != "1":
    # Start immediately: every Go/musl binary on this host needs it, and a
    # tool that begins working only after another tool ran looks broken.
    with contextlib.suppress(Exception):
        DNS_STUB.start()


@contextlib.contextmanager
def pinned(host, ips):
    """Point one hostname at DoH-resolved IPs for this block only.

    Lets requests/urllib validate the certificate against the real hostname
    while connecting to an address the local resolver could not return.
    """
    if not ips:
        yield
        return
    real = socket.getaddrinfo

    def fake(h, port, family=0, type=0, proto=0, flags=0):
        if str(h).lower().rstrip(".") == host.lower().rstrip("."):
            out = []
            for ip in ips:
                fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
                out.append((fam, socket.SOCK_STREAM, proto or 6, "",
                            (ip, port or 0, 0, 0) if fam == socket.AF_INET6
                            else (ip, port or 0)))
            return out
        return real(h, port, family, type, proto, flags)

    socket.getaddrinfo = fake
    try:
        yield
    finally:
        socket.getaddrinfo = real


# ==========================================================================
# 2. HTTP — resilient fetch, readability, extraction
# ==========================================================================

def _looks_like_dns_error(exc):
    txt = f"{type(exc).__name__}: {exc}".lower()
    return any(k in txt for k in ("name or service", "nodename", "getaddrinfo",
                                  "failed to resolve", "temporary failure",
                                  "no address associated", "name resolution"))


def fetch(url, method="GET", headers=None, params=None, data=None, json_body=None,
          timeout=TIMEOUT, allow_redirects=True, retries=2, stream=False,
          max_bytes=MAX_BODY, doh_pin=True, cookie_jar=None):
    """One HTTP request that survives this host's DNS quirks.

    On a resolution failure it retries with a DoH-pinned address (TLS still
    validated against the hostname). Returns a dict, never raises.
    """
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update({str(k): str(v) for k, v in headers.items()})
    last = None
    attempts = 0
    while attempts <= retries:
        attempts += 1
        try:
            r = (cookie_jar or SESSION).request(
                method.upper(), url, headers=hdrs, params=params,
                data=data, json=json_body, timeout=timeout,
                allow_redirects=allow_redirects, verify=False, stream=stream)
            body = ""
            if not stream:
                raw = r.content[:max_bytes]
                body = _decode(raw, r)
            return {"ok": True, "status": r.status_code, "url": r.url,
                    "headers": dict(list(r.headers.items())[:40]),
                    "body": body, "bytes": len(r.content or b""),
                    "redirects": [h.headers.get("location") for h in r.history
                                  if h.headers.get("location")][:10],
                    "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
                    "response": r}
        except Exception as e:
            last = e
            if doh_pin and _looks_like_dns_error(e):
                host = urlparse(url).hostname
                ips = RESOLVER.ips(host) if host else []
                if ips:
                    try:
                        with pinned(host, ips):
                            r = (cookie_jar or SESSION).request(
                                method.upper(), url, headers=hdrs, params=params,
                                data=data, json=json_body, timeout=timeout,
                                allow_redirects=allow_redirects, verify=False)
                        return {"ok": True, "status": r.status_code, "url": r.url,
                                "headers": dict(list(r.headers.items())[:40]),
                                "body": _decode(r.content[:max_bytes], r),
                                "bytes": len(r.content or b""), "dns_pinned": ips[:3],
                                "redirects": [h.headers.get("location") for h in r.history
                                              if h.headers.get("location")][:10],
                                "response": r}
                    except Exception as e2:
                        last = e2
            time.sleep(min(1.5 * attempts, 4))
    err = f"{type(last).__name__}: {last}" if last else "unknown error"
    hint = ""
    if last and _looks_like_dns_error(last):
        hint = (" (name resolution failed for both libc and DNS-over-HTTPS — "
                "check the hostname or use tool=dns_lookup first)")
    return {"ok": False, "error": err + hint, "url": url, "attempts": attempts}


def _decode(raw, resp=None):
    ctype = ""
    if resp is not None:
        ctype = (resp.headers.get("content-type") or "").lower()
    enc = None
    if resp is not None:
        enc = resp.encoding
    if enc and enc.lower() not in ("iso-8859-1",):
        try:
            return raw.decode(enc, errors="replace")
        except Exception:
            pass
    m = re.search(rb'charset=["\']?([\w-]+)', raw[:2048], re.I)
    cands = [m.group(1).decode("ascii", "ignore")] if m else []
    cands += ["utf-8", "windows-1252", "latin-1"]
    for c in cands:
        try:
            return raw.decode(c)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def soup_of(html_text):
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(html_text or "", "html.parser")
    except Exception:
        return None


_JUNK_TAGS = ("script", "style", "noscript", "svg", "nav", "footer", "header",
              "aside", "form", "button", "iframe", "template")


def readable_text(html_text, limit=MAX_OUT * 2):
    """Density-based main-content extraction (a small readability clone)."""
    if not html_text:
        return ""
    soup = soup_of(html_text)
    if soup is None:
        txt = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html_text)
        txt = re.sub(r"(?s)<[^>]+>", " ", txt)
        return re.sub(r"[ \t]+", " ", _htmlmod.unescape(txt)).strip()[:limit]
    for tag in soup(list(_JUNK_TAGS)) if hasattr(soup, "__call__") else []:
        tag.decompose()
    title = (soup.title.get_text(strip=True) if soup.title else "")
    desc = ""
    mt = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
    if mt:
        desc = mt.get("content") or ""
    best, best_score = None, 0
    for node in soup.find_all(["article", "main", "section", "div", "td"]):
        text = node.get_text(" ", strip=True)
        if len(text) < 140:
            continue
        p_count = len(node.find_all("p"))
        links = node.find_all("a")
        link_chars = sum(len(a.get_text(" ", strip=True)) for a in links)
        density = 1.0 - (link_chars / max(len(text), 1))
        score = (len(text) * density) + (p_count * 60)
        if score > best_score:
            best, best_score = node, score
    root = best or soup.body or soup
    chunks = []
    for el in root.find_all(["h1", "h2", "h3", "h4", "p", "li", "pre", "blockquote",
                             "td", "dd", "figcaption"], recursive=True):
        t = el.get_text(" ", strip=True)
        if not t:
            continue
        if el.name.startswith("h"):
            chunks.append("\n## " + t)
        elif el.name in ("pre",):
            chunks.append("\n```\n" + el.get_text("\n", strip=False)[:4000] + "\n```")
        elif el.name == "li":
            chunks.append("- " + t)
        else:
            chunks.append(t)
    text = "\n".join(chunks) if chunks else root.get_text("\n", strip=True)
    text = re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]{2,}", " ", text)).strip()
    head = ""
    if title:
        head += f"# {title}\n"
    if desc:
        head += f"_{desc}_\n"
    return (head + text)[:limit]


def extract_links(html_text, base=None, limit=200):
    soup = soup_of(html_text)
    out, seen = [], set()
    if soup is not None:
        for a in soup.find_all("a", href=True):
            href = urljoin(base, a["href"].strip()) if base else a["href"].strip()
            if href.startswith(("javascript:", "#", "mailto:", "tel:")):
                continue
            if href in seen:
                continue
            seen.add(href)
            out.append({"url": href,
                        "text": a.get_text(" ", strip=True)[:120],
                        "rel": " ".join(a.get("rel") or [])})
            if len(out) >= limit:
                break
        return out
    for m in re.finditer(r'<a[^>]+href="([^"#]+)"[^>]*>(.*?)</a>', html_text or "",
                         re.I | re.S):
        href = urljoin(base, m.group(1)) if base else m.group(1)
        if href in seen:
            continue
        seen.add(href)
        out.append({"url": href, "text": re.sub(r"<[^>]+>", "", m.group(2)).strip()[:120]})
        if len(out) >= limit:
            break
    return out


def extract_forms(html_text, base=None):
    soup = soup_of(html_text)
    forms = []
    if soup is None:
        return forms
    for f in soup.find_all("form"):
        fields = []
        for el in f.find_all(["input", "textarea", "select"]):
            fields.append({"name": el.get("name"), "type": el.get("type") or el.name,
                           "value": el.get("value"),
                           "required": el.has_attr("required")})
        forms.append({"action": urljoin(base, f.get("action") or "") if base else f.get("action"),
                      "method": (f.get("method") or "GET").upper(),
                      "enctype": f.get("enctype"),
                      "fields": fields})
    return forms


_SECRET_PATTERNS = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws_secret", r"\b(?:aws_secret_access_key|AWS_SECRET)[\"'\s:=]+([A-Za-z0-9/+=]{40})"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("github_token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    ("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ("stripe_key", r"\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("basic_auth_url", r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@"),
    ("firebase_url", r"https://[a-z0-9-]+\.firebaseio\.com"),
    ("s3_bucket", r"[a-z0-9.\-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"),
]


def find_secrets(text, limit=40):
    hits, seen = [], set()
    for name, pat in _SECRET_PATTERNS:
        for m in re.finditer(pat, text or ""):
            val = m.group(0)
            key = (name, val[:40])
            if key in seen:
                continue
            seen.add(key)
            hits.append({"kind": name, "value": val[:120],
                         "context": (text[max(0, m.start() - 40):m.end() + 40]
                                     .replace("\n", " ")[:160])})
            if len(hits) >= limit:
                return hits
    return hits


def harvest_endpoints(html_text, base=None):
    """Pull API paths, JS sources and interesting comments out of a page."""
    out = {"js_files": [], "api_paths": [], "comments": [], "params": []}
    soup = soup_of(html_text)
    srcs = []
    if soup is not None:
        srcs = [s.get("src") for s in soup.find_all("script", src=True)]
        for m in soup.find_all("meta"):
            pass
    else:
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)', html_text or "", re.I)
    for s in srcs[:60]:
        u = urljoin(base, s) if base else s
        if u not in out["js_files"]:
            out["js_files"].append(u)
    paths = set()
    for m in re.finditer(r'["\'`](/?(?:api|v\d|graphql|rest|internal|admin|auth|oauth)'
                         r'[A-Za-z0-9_\-./]{0,80})["\'`]', html_text or ""):
        p = m.group(1)
        if len(p) > 2:
            paths.add(p if p.startswith("/") else "/" + p)
    out["api_paths"] = sorted(paths)[:80]
    for m in re.finditer(r"<!--(.{4,400}?)-->", html_text or "", re.S):
        c = re.sub(r"\s+", " ", m.group(1)).strip()
        if c and not c.lower().startswith(("[if", "googleoff", "googleon")):
            out["comments"].append(c[:200])
    params = set()
    for m in re.finditer(r"[?&]([a-zA-Z_][\w\-\[\]]{1,40})=", html_text or ""):
        params.add(m.group(1))
    out["params"] = sorted(params)[:80]
    return out


# ==========================================================================
# 3. WEB SEARCH — several engines, generic parsing, dedupe
# ==========================================================================

def _clean_url(u):
    """Unwrap the redirect wrappers search engines put around real results."""
    if not u:
        return u
    u = _htmlmod.unescape(u)
    if u.startswith("//"):
        u = "https:" + u
    if "uddg=" in u:                                   # DuckDuckGo /l/?uddg=
        m = re.search(r"uddg=([^&]+)", u)
        if m:
            u = unquote(m.group(1))
    if "/ck/a" in u:                                   # Bing /ck/a?…&u=a1<base64url>
        m = re.search(r"[?&]u=a1([^&]+)", u)
        if m:
            tok = m.group(1)
            tok += "=" * (-len(tok) % 4)
            try:
                u = base64.urlsafe_b64decode(tok).decode("utf-8", "replace")
            except Exception:
                pass
    if u.startswith("/url?"):                          # legacy Google /url?q=
        m = re.search(r"[?&]q=([^&]+)", u)
        if m:
            u = unquote(m.group(1))
    return u


def _parse_ddg(html_text):
    out = []
    for m in re.finditer(
            r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
            html_text or "", re.S | re.I):
        title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        out.append({"title": _htmlmod.unescape(title), "url": _clean_url(m.group(1))})
    snips = [re.sub(r"<[^>]+>", "", s).strip() for s in re.findall(
        r'class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', html_text or "", re.S | re.I)]
    for i, s in enumerate(snips[:len(out)]):
        out[i]["snippet"] = _htmlmod.unescape(re.sub(r"\s+", " ", s))[:300]
    return out


def _parse_bing(html_text):
    """Bing organic results live in <li class="b_algo"> with an obfuscated href."""
    out, seen = [], set()
    for m in re.finditer(r'<li class="b_algo[^"]*"(.*?)</li>', html_text or "",
                         re.S | re.I):
        block = m.group(1)
        a = re.search(r'<h2[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not a:
            continue
        url = _clean_url(a.group(1))
        if not url.startswith("http") or url in seen:
            continue
        seen.add(url)
        title_html = re.sub(r"<cite.*?</cite>", "", a.group(2), flags=re.S | re.I)
        title = _htmlmod.unescape(re.sub(r"<[^>]+>", "", title_html))
        title = re.sub(r"\s+", " ", title).strip()
        snippet = ""
        for cand in (block,):
            p = re.search(r'<p[^>]*class="[^"]*(?:b_lineclamp|b_algoSlug|b_paractl)[^"]*"'
                          r'[^>]*>(.*?)</p>', cand, re.S) or re.search(
                              r"<p[^>]*>(.*?)</p>", cand, re.S)
            if p:
                snippet = _htmlmod.unescape(re.sub(r"<[^>]+>", "", p.group(1)))
                snippet = re.sub(r"\s+", " ", snippet).strip()
                if snippet:
                    break
        out.append({"title": title or url, "url": url, "snippet": snippet[:300]})
    return out


def _parse_brave(html_text):
    out = []
    for m in re.finditer(r'<a[^>]+href="(https?://[^"]+)"[^>]*class="[^"]*[^"]*"[^>]*>'
                         r'.*?<div class="[^"]*title[^"]*"[^>]*>(.*?)</div>',
                         html_text or "", re.S | re.I):
        out.append({"title": re.sub(r"<[^>]+>", "", m.group(2)).strip(),
                    "url": _clean_url(m.group(1))})
    if not out:
        for m in re.finditer(r'<a[^>]+href="(https?://[^"]+)"[^>]*>\s*<span[^>]*class="[^"]*'
                             r'snippet-title[^"]*"[^>]*>(.*?)</span>', html_text or "", re.S | re.I):
            out.append({"title": re.sub(r"<[^>]+>", "", m.group(2)).strip(),
                        "url": _clean_url(m.group(1))})
    return out


def _parse_mojeek(html_text):
    out = []
    for m in re.finditer(r'<a[^>]+class="ob"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html_text or "",
                         re.S | re.I):
        out.append({"title": re.sub(r"<[^>]+>", "", m.group(2)).strip(),
                    "url": _clean_url(m.group(1))})
    if not out:
        for m in re.finditer(r'<h2><a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', html_text or "",
                             re.S | re.I):
            out.append({"title": re.sub(r"<[^>]+>", "", m.group(2)).strip(),
                        "url": _clean_url(m.group(1))})
    return out


def _parse_generic(html_text, base):
    """Last resort: anchor text that looks like a result title."""
    out = []
    for a in extract_links(html_text, base=base, limit=120):
        u = a["url"]
        if any(x in u for x in ("duckduckgo.com", "bing.com", "mojeek.com",
                                "brave.com", "google.com", "yandex")):
            continue
        if len(a.get("text") or "") < 12:
            continue
        out.append({"title": a["text"], "url": u})
    return out


def _parse_bing_rss(xml_text):
    """Bing's RSS endpoint — plain XML, no obfuscated hrefs, never JS-gated."""
    out = []
    for item in re.findall(r"<item>(.*?)</item>", xml_text or "", re.S):
        def field(tag):
            m = re.search(rf"<{tag}>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{tag}>", item, re.S)
            return _htmlmod.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else ""
        url = field("link")
        if not url.startswith("http"):
            continue
        out.append({"title": field("title")[:200], "url": _clean_url(url),
                    "snippet": re.sub(r"\s+", " ", field("description"))[:300]})
    return out


def _parse_stackexchange(body):
    """Stack Overflow / Server Fault / Security SE — where the working details are."""
    try:
        j = json.loads(body)
    except Exception:
        return []
    out = []
    for it in j.get("items") or []:
        title = _htmlmod.unescape(it.get("title") or "")
        if not title or not it.get("link"):
            continue
        out.append({"title": title,
                    "url": it["link"],
                    "snippet": ("score %s · answers %s · %s"
                                % (it.get("score"), it.get("answer_count"),
                                   ", ".join(it.get("tags") or [])))[:300]})
    return out


def _parse_hn(body):
    """Hacker News via Algolia — good for tooling news and post-mortems."""
    try:
        j = json.loads(body)
    except Exception:
        return []
    out = []
    for hit in j.get("hits") or []:
        title = hit.get("title") or hit.get("story_title") or ""
        url = hit.get("url") or ("https://news.ycombinator.com/item?id=" + str(hit.get("objectID")))
        if not title:
            continue
        points = hit.get("points")
        comments = hit.get("num_comments")
        out.append({"title": title[:200], "url": url,
                    "snippet": f"HN · {points or 0} points · {comments or 0} comments"})
    return out


def _parse_marginalia(html_text):
    """Small independent index — clean anchors, no JS, no rate limit."""
    out = []
    for m in re.finditer(r"<h2[^>]*>\s*<a[^>]+href=\"(https?://[^\"]+)\"[^>]*>(.*?)</a>",
                         html_text or "", re.S | re.I):
        title = re.sub(r"\s+", " ", _htmlmod.unescape(re.sub(r"<[^>]+>", "", m.group(2)))).strip()
        if not title:
            continue
        out.append({"title": title, "url": _clean_url(m.group(1)), "snippet": ""})
    return out or _parse_generic(html_text, "https://search.marginalia.nu/")


def _parse_jina_md(md):
    """Parse the markdown returned by the render proxy for a SERP page."""
    out, seen = [], set()
    lines = (md or "").splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\s{0,6}#{1,6}\s*\[(.+?)\]\((https?://[^)\s]+)\)", line)
        if not m:
            continue
        url = _clean_url(m.group(2))
        if not url.startswith("http") or url in seen:
            continue
        host = urlparse(url).netloc
        if any(x in host for x in ("duckduckgo.com", "bing.com", "jina.ai",
                                   "google.com", "microsoft.com", "w3.org")):
            continue
        title = re.sub(r"\s+", " ", m.group(1).replace("**", "").replace("`", "")).strip()
        if len(title) < 3 or title.lower().startswith(("skip to", "accessibility")):
            continue
        seen.add(url)
        snippet = ""
        for nxt in lines[i + 1:i + 6]:
            t = nxt.strip()
            if not t or t.startswith(("#", "[", "!", "|", "---", "*", "-")):
                continue
            snippet = re.sub(r"\s+", " ", re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t))
            break
        out.append({"title": title, "url": url, "snippet": snippet[:300]})
    return out


def _parse_wiki(body):
    """Wikipedia search API — exact, citable background for factual questions."""
    try:
        j = json.loads(body)
    except Exception:
        return []
    out = []
    for hit in ((j.get("query") or {}).get("search") or []):
        title = (hit.get("title") or "").strip()
        if not title:
            continue
        snippet = _htmlmod.unescape(re.sub(r"<[^>]+>", "", hit.get("snippet") or ""))
        out.append({"title": title,
                    "url": "https://en.wikipedia.org/wiki/" + title.replace(" ", "_"),
                    "snippet": re.sub(r"\s+", " ", snippet)[:300]})
    return out


SEARCH_ENGINES = {
    # name: (endpoint, parser, params, extra headers, via_render_proxy)
    "bing": ("https://www.bing.com/search", _parse_bing_rss,
             {"q": "{q}", "format": "rss", "count": "20", "mkt": "en-US"}, None, False),
    "bing_html": ("https://www.bing.com/search", _parse_bing,
                  {"q": "{q}", "count": "20"}, None, False),
    "wiki": ("https://en.wikipedia.org/w/api.php", _parse_wiki,
             {"action": "query", "list": "search", "srsearch": "{q}",
              "format": "json", "srlimit": "10"}, None, False),
    "stack": ("https://api.stackexchange.com/2.3/search/advanced", _parse_stackexchange,
              {"order": "desc", "sort": "relevance", "q": "{q}", "pagesize": "10",
               "site": "stackoverflow", "filter": "withbody"}, None, False),
    "security_se": ("https://api.stackexchange.com/2.3/search/advanced", _parse_stackexchange,
                    {"order": "desc", "sort": "relevance", "q": "{q}", "pagesize": "10",
                     "site": "security"}, None, False),
    "hn": ("https://hn.algolia.com/api/v1/search", _parse_hn,
           {"query": "{q}", "hitsPerPage": "10"}, None, False),
    "jina_bing": ("https://www.bing.com/search", _parse_jina_md, {"q": "{q}"},
                  {"X-Return-Format": "markdown"}, True),
    "jina_ddg": ("https://duckduckgo.com/html/", _parse_jina_md, {"q": "{q}"},
                 {"X-Return-Format": "markdown"}, True),
    "marginalia": ("https://search.marginalia.nu/search", _parse_marginalia,
                   {"query": "{q}"}, None, False),
    "ddg": ("https://html.duckduckgo.com/html/", _parse_ddg, {"q": "{q}"}, None, False),
    "brave": ("https://search.brave.com/search", _parse_brave, {"q": "{q}"}, None, False),
    "mojeek": ("https://www.mojeek.com/search", _parse_mojeek, {"q": "{q}"}, None, False),
}

DEFAULT_ENGINES = ["bing", "wiki"]
DEEP_ENGINES = ["jina_bing", "jina_ddg", "hn", "marginalia"]



STOPWORDS = {"what", "is", "are", "was", "the", "how", "to", "a", "an", "of", "in",
             "for", "and", "or", "with", "on", "does", "do", "can", "why", "when",
             "where", "which", "who", "best", "vs", "it", "this", "that", "be"}


def _query_tokens(query):
    toks = [t for t in re.findall(r"[a-z0-9][a-z0-9\-\.]{2,}", (query or "").lower())]
    keep = [t for t in toks if t not in STOPWORDS]
    return keep or toks


def _relevance(item, tokens):
    if not tokens:
        return 1.0
    hay = "%s %s %s" % (item.get("title") or "", item.get("snippet") or "",
                        item.get("url") or "")
    hay = hay.lower()
    return sum(1 for t in tokens if t in hay) / float(len(tokens))


def web_search(query, engines=None, limit=10, time_filter=None, timeout=45):
    """Query several engines concurrently, merge, de-duplicate by URL."""
    engines = engines or list(DEFAULT_ENGINES)
    if isinstance(engines, str):
        engines = [e.strip() for e in engines.split(",") if e.strip()]
    specs = [(n, SEARCH_ENGINES[n]) for n in engines if n in SEARCH_ENGINES]
    if not specs:
        return {"ok": False, "query": query, "results": [],
                "error": f"unknown engines {engines}; known: {sorted(SEARCH_ENGINES)}"}
    filters = {"past_day": 'ex1:"ez1"', "past_week": 'ex1:"ez2"',
               "past_month": 'ex1:"ez3"', "past_year": 'ex1:"ez4"'}

    tokens = _query_tokens(query)
    # Search back-ends often answer a natural-language question with a stale
    # "popular pages" feed. Query them with the keywords instead.
    keyword_query = " ".join(tokens) if len(tokens) >= 1 else query

    def attempt(name, spec, q):
        url, parser, params = spec[0], spec[1], spec[2]
        hdrs = spec[3] if len(spec) > 3 else None
        render = spec[4] if len(spec) > 4 else False
        p = {k: v.replace("{q}", q) for k, v in params.items()}
        if time_filter and name.startswith("bing") and time_filter in filters:
            p["filters"] = filters[time_filter]
        try:
            if render:
                target = "https://r.jina.ai/" + url + ("?" + urlencode(p) if p else "")
                r = fetch(target, headers=hdrs, timeout=timeout, retries=1)
            else:
                r = fetch(url, params=p, timeout=timeout, retries=1)
            if not r.get("ok"):
                return [], r.get("error") or "fetch failed"
            body = r.get("body") or ""
            found = parser(body) or []
            if not found and not body.lstrip().startswith(("{", "[")):
                found = _parse_generic(body, url)
            # Guard against engines that answer an unknown query with a stale
            # "popular pages" feed: keep only items that mention the query.
            if found and tokens:
                scored = [(f, _relevance(f, tokens)) for f in found]
                kept = [f for f, s in scored if s > 0]
                if not kept and len(found) >= 3:
                    return [], ("returned %d results unrelated to the query "
                                "(stale feed)" % len(found))
                found = kept or found
            return found, None
        except Exception as e:
            return [], f"{type(e).__name__}: {e}"

    def run(name, spec):
        found, err = attempt(name, spec, keyword_query)
        if err and "unrelated" in err and keyword_query != query:
            retry, err2 = attempt(name, spec, query)
            if retry:
                return name, retry, None
            err = err2 or err
        return name, found, err

    merged, order, per_engine = {}, [], {}
    with futures.ThreadPoolExecutor(max_workers=min(4, len(specs))) as pool:
        for name, found, err in pool.map(lambda a: run(*a), specs):
            if err:
                per_engine[name] = {"error": str(err)[:200]}
                continue
            per_engine[name] = len(found)
            for item in found:
                u = (item.get("url") or "").split("#")[0]
                if not u.startswith("http"):
                    continue
                dom = urlparse(u).netloc
                if not dom or any(x in dom for x in ("duckduckgo.com", "bing.com",
                                                     "mojeek.com", "brave.com",
                                                     "marginalia-search.com", "jina.ai")):
                    continue
                key = (dom + urlparse(u).path).rstrip("/")
                if key in merged:
                    if item.get("snippet") and not merged[key]["snippet"]:
                        merged[key]["snippet"] = (item["snippet"] or "")[:300]
                    continue
                merged[key] = {"title": (item.get("title") or u)[:200], "url": u,
                               "snippet": (item.get("snippet") or "")[:300],
                               "engine": name}
                order.append(key)
    if len(order) < max(4, limit // 2) and not (engines and "jina" in " ".join(engines)):
        # Thin result set: widen to the slower, gated engines in one extra pass.
        extra = [e for e in DEEP_ENGINES if e not in engines]
        if extra:
            deep = web_search(query, engines=extra, limit=limit, time_filter=time_filter,
                              timeout=timeout)
            per_engine.update(deep.get("engines") or {})
            for item in deep.get("results") or []:
                key = (urlparse(item["url"]).netloc + urlparse(item["url"]).path).rstrip("/")
                if key in merged:
                    continue
                merged[key] = item
                order.append(key)
    results = [merged[k] for k in order][:limit]
    result_has_snippet = any(r["snippet"] for r in results)
    return {"ok": bool(results), "query": query, "count": len(results),
            "with_snippets": result_has_snippet, "results": results,
            "engines": per_engine,
            "error": None if results else "no engine returned parsable results"}


# ==========================================================================
# 4. DOWNLOADS + ARCHIVES
# ==========================================================================

_SNIFF = [
    (b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"), (b"\x7fELF", "elf-binary"),
    (b"MZ", "pe-binary"), (b"%PDF", "pdf"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"), (b"ustar", "tar"), (b"\xfd7zXZ", "xz"), (b"BZh", "bzip2"),
    (b"7z\xbc\xaf", "7z"), (b"Rar!", "rar"), (b"\x00\x00\x00\x18ftyp", "mp4"),
]


def sniff_bytes(head):
    for magic, name in _SNIFF:
        if head.startswith(magic):
            return name
    if head[:5].lower() in (b"<!doc", b"<html"):
        return "html"
    if head[:1] in (b"{", b"["):
        return "json"
    if head and all(9 <= b < 127 or b in (10, 13) for b in head[:200]):
        return "text"
    return "unknown"


def _unique_path(path):
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(f"{stem}-{i}{ext}"):
        i += 1
    return f"{stem}-{i}{ext}"


def download(url, dest=None, max_bytes=None, resume=True, extract=False,
             chmod_x=False, expected_sha256=None, headers=None, timeout=60,
             retries=2, progress=None):
    """Stream a URL to disk with resume, hashing, sniffing and extraction."""
    if not url:
        return {"ok": False, "error": "missing url"}
    if "github.com" in url and "/blob/" in url:
        url = (url.replace("github.com", "raw.githubusercontent.com")
                  .replace("/blob/", "/"))
    name = os.path.basename(urlparse(url).path) or "download.bin"
    name = unquote(name.split("?")[0]) or "download.bin"
    if dest:
        dest = dest if os.path.isabs(dest) else os.path.join(DL_DIR, dest)
        if os.path.isdir(dest):
            dest = os.path.join(dest, name)
    else:
        dest = os.path.join(DL_DIR, name)
    os.makedirs(os.path.dirname(dest) or DL_DIR, exist_ok=True)
    part = dest + ".part"
    limit = int(max_bytes) if max_bytes else None
    attempts, last_err = 0, None
    while attempts <= retries:
        attempts += 1
        existing = os.path.getsize(part) if (resume and os.path.exists(part)) else 0
        hdrs = {"User-Agent": UA}
        if headers:
            hdrs.update(headers)
        if existing:
            hdrs["Range"] = f"bytes={existing}-"
        try:
            with SESSION.get(url, headers=hdrs, stream=True, timeout=timeout,
                             verify=False, allow_redirects=True) as r:
                if r.status_code == 416 and existing:
                    os.replace(part, dest)
                    break
                if r.status_code not in (200, 206):
                    return {"ok": False, "error": f"HTTP {r.status_code} for {url}",
                            "status": r.status_code}
                mode = "ab" if (r.status_code == 206 and existing) else "wb"
                if mode == "wb":
                    existing = 0
                total = int(r.headers.get("content-length") or 0) + existing
                written = existing
                with open(part, mode) as f:
                    for chunk in r.iter_content(1 << 16):
                        if not chunk:
                            continue
                        f.write(chunk)
                        written += len(chunk)
                        if progress:
                            with contextlib.suppress(Exception):
                                progress(written, total)
                        if limit and written > limit:
                            f.close()
                            os.remove(part)
                            return {"ok": False,
                                    "error": f"aborted at max_bytes={limit}"}
                if total and written < total:
                    raise IOError(f"short read {written}/{total}")
            os.replace(part, dest)
            break
        except Exception as e:
            last_err = e
            if _looks_like_dns_error(e):
                host = urlparse(url).hostname
                ips = RESOLVER.ips(host) if host else []
                if ips:
                    try:
                        with pinned(host, ips):
                            r = SESSION.get(url, headers={"User-Agent": UA}, timeout=timeout,
                                            verify=False)
                        with open(part, "wb") as f:
                            f.write(r.content)
                        os.replace(part, dest)
                        last_err = None
                        break
                    except Exception as e2:
                        last_err = e2
            time.sleep(0.8 * attempts)
    else:
        return {"ok": False, "error": f"{type(last_err).__name__}: {last_err}"}

    size = os.path.getsize(dest)
    digest = _sha256(dest)
    with open(dest, "rb") as f:
        kind = sniff_bytes(f.read(16))
    out = {"ok": True, "path": dest, "bytes": size, "sha256": digest,
           "kind": kind, "url": url, "human_size": _human(size)}
    if expected_sha256:
        match = digest.lower() == expected_sha256.lower()
        out["sha256_verified"] = match
        if not match:
            out["warning"] = "sha256 does not match the expected digest"
    if chmod_x:
        with contextlib.suppress(Exception):
            os.chmod(dest, 0o755)
        out["executable"] = True
    if extract is True and kind in ("zip", "gzip", "tar", "xz", "bzip2"):
        ex = extract_archive(dest)
        if ex.get("ok"):
            out["extracted_to"] = ex["into"]
            out["extracted"] = ex["files"][:40]
    return out


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} GB"


def _safe_extract_member(name, target):
    target = os.path.abspath(target)
    dest = os.path.abspath(os.path.join(target, name))
    if not dest.startswith(target + os.sep) and dest != target:
        return None
    return dest


def extract_archive(path, into=None, max_files=4000):
    """Extract zip/tar/gz/xz/bz2 with traversal protection."""
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": f"file not found: {path}"}
    if not os.path.isabs(path):
        path = os.path.join(DL_DIR, path)
    into = into or os.path.splitext(path)[0] + "_x"
    into = into if os.path.isabs(into) else os.path.join(DL_DIR, into)
    os.makedirs(into, exist_ok=True)
    files = []
    try:
        with open(path, "rb") as f:
            kind = sniff_bytes(f.read(16))
        if kind == "zip" or zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for zi in z.infolist()[:max_files]:
                    if zi.is_dir():
                        continue
                    dest = _safe_extract_member(zi.filename, into)
                    if not dest:
                        continue
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with z.open(zi) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
                    if (zi.external_attr >> 16) & 0o111:
                        with contextlib.suppress(Exception):
                            os.chmod(dest, 0o755)
                    files.append(dest)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                for m in t.getmembers()[:max_files]:
                    if not m.isfile():
                        continue
                    dest = _safe_extract_member(m.name, into)
                    if not dest:
                        continue
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    src = t.extractfile(m)
                    if src is None:
                        continue
                    with src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
                    with contextlib.suppress(Exception):
                        os.chmod(dest, m.mode | 0o600)
                    files.append(dest)
        elif kind in ("gzip", "xz", "bzip2"):
            import gzip
            base = os.path.basename(path)
            for ext in (".gz", ".xz", ".bz2", ".tgz"):
                if base.lower().endswith(ext):
                    base = base[: -len(ext)]
                    break
            if base.lower().endswith(".tar"):
                base = base[:-4]
            dest = os.path.join(into, base or "extracted.bin")
            if kind == "gzip":
                opener = gzip.open
            elif kind == "bz2" or kind == "bzip2":
                import bz2
                opener = bz2.open
            else:
                import lzma
                opener = lzma.open
            with opener(path, "rb") as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
            with contextlib.suppress(Exception):
                os.chmod(dest, 0o755)
            files.append(dest)
            if kind == "gzip" and tarfile.is_tarfile(dest):
                sub = extract_archive(dest, into)
                if sub.get("ok"):
                    return sub
        else:
            return {"ok": False, "error": f"not a recognised archive ({kind})"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "partial": files[:20]}
    return {"ok": bool(files), "into": into, "count": len(files), "files": files,
            "error": None if files else "archive contained no files"}


# ==========================================================================
# 5. GITHUB
# ==========================================================================

GH_API = "https://api.github.com"


def _gh_token():
    for var in ("GH_TOKEN", "GITHUB_TOKEN", "APEX_GH_TOKEN"):
        v = os.environ.get(var)
        if v:
            return v.strip()
    for p in (os.path.expanduser("~/.config/apex/github_token"),
              os.path.join(WORKSPACE, "github_token")):
        try:
            if os.path.isfile(p):
                with open(p, encoding="utf-8") as f:
                    tok = f.read().strip()
                if tok:
                    return tok
        except Exception:
            pass
    gh = os.path.expanduser("~/.config/gh/hosts.yml")
    try:
        if os.path.isfile(gh):
            with open(gh, encoding="utf-8") as f:
                m = re.search(r"oauth_token:\s*(\S+)", f.read())
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return None


def _gh_headers(extra=None):
    h = {"Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28",
         "User-Agent": BOT_UA}
    tok = _gh_token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    if extra:
        h.update(extra)
    return h


def gh_api(path, params=None, method="GET", body=None, raw=False):
    url = path if str(path).startswith("http") else f"{GH_API}{path}"
    try:
        r = SESSION.request(method, url, params=params, headers=_gh_headers(),
                            json=body, timeout=30, verify=False)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    remain = r.headers.get("x-ratelimit-remaining")
    if r.status_code == 403 and remain == "0":
        return {"ok": False, "status": 403,
                "error": "GitHub API rate limit exhausted for this IP. Set GH_TOKEN "
                         "in the environment (5000 req/hour) or use tool=download on "
                         "raw URLs, which are not rate limited.",
                "rate_limit_reset": r.headers.get("x-ratelimit-reset")}
    if r.status_code == 404:
        return {"ok": False, "status": 404, "error": f"not found: {url}"}
    if r.status_code >= 400:
        try:
            msg = r.json().get("message")
        except Exception:
            msg = r.text[:200]
        return {"ok": False, "status": r.status_code, "error": f"HTTP {r.status_code}: {msg}"}
    if raw:
        return {"ok": True, "status": r.status_code, "text": r.text,
                "bytes": len(r.content)}
    try:
        return {"ok": True, "status": r.status_code, "data": r.json()}
    except Exception:
        return {"ok": True, "status": r.status_code, "text": r.text[:MAX_OUT]}


def _pick_asset(assets, pattern=None, exclude_suffix=(".deb", ".rpm", ".apk", ".msi",
                                                     ".dmg", ".sig", ".asc", ".sbom",
                                                     ".txt", ".sha256", ".sha512",
                                                     ".pem", ".crt", ".pkg")):
    """Choose the release asset that matches this OS/CPU, or an explicit pattern."""
    if pattern:
        pat = pattern.lower()
        hits = [a for a in assets if fnmatch.fnmatch(a["name"].lower(), pat)
                or pat in a["name"].lower()]
        return hits[0] if hits else None
    toks = _arch_tokens()
    scored = []
    for a in assets:
        n = a["name"].lower()
        if any(n.endswith(x) for x in exclude_suffix):
            continue
        score = 0
        if "linux" in n:
            score += 6
        elif any(x in n for x in ("darwin", "windows", "freebsd", "openbsd")):
            continue
        if any(t in n for t in toks):
            score += 6
        if n.endswith((".tar.gz", ".tgz", ".zip")):
            score += 2
        if "checksums" in n or n.endswith(".json"):
            score -= 5
        if score > 0:
            scored.append((score, a))
    scored.sort(key=lambda x: -x[0])
    return scored[0][1] if scored else None


def github(args):
    action = str(args.get("action") or "repo").lower()
    repo = str(args.get("repo") or "").strip().strip("/")
    if repo.startswith("http"):
        m = re.search(r"github\.com/([^/]+/[^/#?]+)", repo)
        repo = m.group(1) if m else repo
    try:
        if action in ("repo", "info", "about"):
            if not repo:
                return {"ok": False, "error": "missing repo (owner/name)"}
            r = gh_api(f"/repos/{repo}")
            if not r["ok"]:
                return r
            d = r["data"]
            return {"ok": True, "repo": d["full_name"], "description": d.get("description"),
                    "stars": d.get("stargazers_count"), "forks": d.get("forks_count"),
                    "language": d.get("language"), "license": (d.get("license") or {}).get("spdx_id"),
                    "default_branch": d.get("default_branch"),
                    "updated": d.get("updated_at"), "pushed": d.get("pushed_at"),
                    "open_issues": d.get("open_issues_count"), "topics": d.get("topics"),
                    "homepage": d.get("homepage"), "archived": d.get("archived"),
                    "clone_url": d.get("clone_url")}
        if action in ("search_repos", "search", "find"):
            q = str(args.get("q") or args.get("query") or "").strip()
            if not q:
                return {"ok": False, "error": "missing q"}
            extra = []
            if args.get("language"):
                extra.append(f"language:{args['language']}")
            if args.get("stars"):
                extra.append(f"stars:>={args['stars']}")
            r = gh_api("/search/repositories",
                       {"q": " ".join([q] + extra), "sort": str(args.get("sort") or "stars"),
                        "order": "desc", "per_page": min(int(args.get("limit") or 10), 30)})
            if not r["ok"]:
                return r
            return {"ok": True, "count": r["data"].get("total_count"),
                    "results": [{"repo": i["full_name"], "stars": i["stargazers_count"],
                                 "description": (i.get("description") or "")[:160],
                                 "language": i.get("language"), "updated": i.get("updated_at")}
                                for i in r["data"].get("items", [])]}
        if action in ("search_code", "code"):
            q = str(args.get("q") or args.get("query") or "").strip()
            if not q:
                return {"ok": False, "error": "missing q"}
            r = gh_api("/search/code", {"q": q, "per_page": min(int(args.get("limit") or 10), 30)})
            if r["ok"]:
                return {"ok": True, "source": "github", "count": r["data"].get("total_count"),
                        "results": [{"repo": i["repository"]["full_name"], "path": i["path"],
                                     "url": i.get("html_url")} for i in r["data"].get("items", [])]}
            g = fetch("https://grep.app/api/search", params={"q": q}, timeout=25)
            if g.get("ok"):
                try:
                    j = json.loads(g["body"])
                except Exception:
                    j = {}
                hits = j.get("hits", {}).get("hits", [])
                parsed = []
                for h in hits[:20]:
                    if not isinstance(h, dict):
                        continue
                    repo_v = h.get("repo")
                    path_v = h.get("path")
                    if isinstance(repo_v, dict):
                        repo_v = repo_v.get("raw")
                    if isinstance(path_v, dict):
                        path_v = path_v.get("raw")
                    content = h.get("content")
                    snippet = content.get("snippet", "") if isinstance(content, dict) else str(content or "")
                    parsed.append({"repo": repo_v, "path": path_v,
                                   "branch": h.get("branch"),
                                   "snippet": _htmlmod.unescape(
                                       re.sub(r"<[^>]+>", "", snippet)).strip()[:200]})
                total = (j.get("hits") or {}).get("total") if isinstance(j.get("hits"), dict) else len(parsed)
                return {"ok": bool(parsed), "source": "grep.app", "count": total,
                        "note": "GitHub code search needs a token; grep.app indexes public repos",
                        "results": parsed}
            return r
        if action in ("tree", "ls", "files"):
            if not repo:
                return {"ok": False, "error": "missing repo"}
            ref = str(args.get("ref") or "").strip()
            if not ref:
                meta = gh_api(f"/repos/{repo}")
                ref = meta["data"].get("default_branch", "main") if meta["ok"] else "main"
            r = gh_api(f"/repos/{repo}/git/trees/{quote(ref)}",
                       {"recursive": "1" if args.get("recursive", True) else None})
            if not r["ok"]:
                return r
            items = r["data"].get("tree", [])
            path_filter = str(args.get("path") or "").strip("/")
            if path_filter:
                items = [i for i in items if i["path"].startswith(path_filter)]
            return {"ok": True, "repo": repo, "ref": ref,
                    "truncated": r["data"].get("truncated"), "count": len(items),
                    "files": [{"path": i["path"], "type": i["type"], "size": i.get("size")}
                              for i in items[: int(args.get("limit") or 200)]]}
        if action in ("file", "read", "cat", "raw"):
            if not repo or not args.get("path"):
                return {"ok": False, "error": "need repo and path"}
            p = str(args["path"]).lstrip("/")
            ref = args.get("ref") or "HEAD"
            raw_url = f"https://raw.githubusercontent.com/{repo}/{ref}/{p}"
            r = fetch(raw_url, timeout=30, headers={"User-Agent": BOT_UA})
            if r.get("ok") and r.get("status") == 200:
                txt = r["body"]
                lines = int(args.get("limit") or 0)
                if lines:
                    txt = "\n".join(txt.splitlines()[:lines])
                return {"ok": True, "repo": repo, "path": p, "bytes": r.get("bytes"),
                        "content": txt[:MAX_OUT * 3], "url": raw_url}
            import base64
            meta = gh_api(f"/repos/{repo}/contents/{p}",
                          {"ref": args.get("ref")} if args.get("ref") else None)
            if meta["ok"] and isinstance(meta.get("data"), dict) and meta["data"].get("content"):
                txt = base64.b64decode(meta["data"]["content"]).decode("utf-8", "replace")
                return {"ok": True, "repo": repo, "path": p, "bytes": len(txt),
                        "content": txt[:MAX_OUT * 3], "source": "contents-api"}
            return {"ok": False, "error": f"could not read {p} from {repo}"}
        if action in ("releases", "release", "versions"):
            if not repo:
                return {"ok": False, "error": "missing repo"}
            tag = str(args.get("tag") or "").strip()
            if tag:
                rr = gh_api(f"/repos/{repo}/releases/tags/{quote(tag)}")
                rels = [rr["data"]] if rr["ok"] else []
                r = rr
            else:
                r = gh_api(f"/repos/{repo}/releases",
                           {"per_page": min(int(args.get("limit") or 5), 30)})
                rels = r["data"] if r["ok"] else []
            if not rels:
                return {"ok": False, "error": r.get("error", "no releases (repo may only use tags)")}
            out = []
            for rel in rels[: int(args.get("limit") or 5)]:
                assets = [{"name": a["name"], "size": a["size"], "bytes": _human(a["size"]),
                           "downloads": a.get("download_count"), "digest": a.get("digest"),
                           "url": a["browser_download_url"]}
                          for a in rel.get("assets", [])]
                best = _pick_asset(assets, args.get("pattern"))
                out.append({"tag": rel.get("tag_name"), "name": rel.get("name"),
                            "published": rel.get("published_at"),
                            "prerelease": rel.get("prerelease"), "assets": assets,
                            "this_platform": best["name"] if best else None})
            return {"ok": True, "repo": repo, "releases": out,
                    "platform": {"os": OSNAME, "arch": ARCH}}
        if action in ("download", "download_asset", "get_asset"):
            if not repo:
                return {"ok": False, "error": "missing repo"}
            tag = str(args.get("tag") or "").strip()
            rel = (gh_api(f"/repos/{repo}/releases/tags/{quote(tag)}") if tag else
                   gh_api(f"/repos/{repo}/releases/latest"))
            if not rel["ok"]:
                return rel
            assets = [{"name": a["name"], "url": a["browser_download_url"],
                       "size": a["size"], "digest": a.get("digest")}
                      for a in rel["data"].get("assets", [])]
            if not assets:
                return {"ok": False, "error": "release has no downloadable assets",
                        "tag": rel["data"].get("tag_name"),
                        "hint": "use action=file to read source, or action=clone"}
            pick = _pick_asset(assets, args.get("pattern"))
            if not pick:
                return {"ok": False, "error": "no asset matched this platform",
                        "assets": [a["name"] for a in assets][:20]}
            exp = None
            if str(pick.get("digest") or "").startswith("sha256:"):
                exp = pick["digest"].split(":", 1)[1]
            got = download(pick["url"], dest=args.get("dest"),
                           extract=bool(args.get("extract", True)),
                           chmod_x=bool(args.get("chmod_x", True)), expected_sha256=exp,
                           headers={"Accept": "application/octet-stream"})
            got["asset"] = pick["name"]
            got["tag"] = rel["data"].get("tag_name")
            return got
        if action in ("clone", "git"):
            if not repo:
                return {"ok": False, "error": "missing repo"}
            dest = os.path.join(WORKSPACE, "src", repo.replace("/", "_"))
            if os.path.isdir(os.path.join(dest, ".git")) and not args.get("fresh"):
                return {"ok": True, "path": dest, "note": "already cloned"}
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            depth = str(args.get("depth") or 1)
            r = run(["git", "clone", "--depth", depth, "--single-branch",
                     f"https://github.com/{repo}.git", dest], timeout=420)
            if not r["ok"]:
                return {"ok": False, "error": r.get("error") or r["out"][-400:]}
            size = sum(os.path.getsize(os.path.join(dp, f))
                       for dp, _, fs in os.walk(dest) for f in fs)
            return {"ok": True, "path": dest, "size": _human(size)}
        if action in ("user", "org"):
            who = str(args.get("user") or repo or "").strip()
            if not who:
                return {"ok": False, "error": "missing user"}
            r = gh_api(f"/users/{who}")
            if not r["ok"]:
                return r
            d = r["data"]
            return {"ok": True, "login": d.get("login"), "name": d.get("name"),
                    "company": d.get("company"), "blog": d.get("blog"),
                    "location": d.get("location"), "public_repos": d.get("public_repos"),
                    "followers": d.get("followers"), "created": d.get("created_at"),
                    "type": d.get("type")}
        if action == "gists":
            who = str(args.get("user") or repo or "").strip()
            r = gh_api(f"/users/{who}/gists", {"per_page": 10})
            if not r["ok"]:
                return r
            return {"ok": True, "gists": [{"id": g["id"], "desc": g.get("description"),
                                           "files": list(g.get("files", {}).keys()),
                                           "url": g.get("html_url")} for g in r["data"]]}
        if action == "api":
            p = str(args.get("path") or "")
            if not p:
                return {"ok": False, "error": "missing path (e.g. /rate_limit)"}
            return gh_api(p, args.get("params"))
        return {"ok": False, "error": f"unknown github action {action}",
                "valid": ["repo", "search_repos", "search_code", "tree", "file",
                          "releases", "download", "clone", "user", "gists", "api"]}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ==========================================================================
# 6. PROVISIONING — install real tools from GitHub releases
# ==========================================================================

TOOL_REGISTRY = {
    "cloudflared": {"repo": "cloudflare/cloudflared", "asset": "cloudflared-linux-arm64",
                    "bin": "cloudflared", "verify": "--version",
                    "why": "public HTTPS tunnel for local ports"},
    "ffuf": {"repo": "ffuf/ffuf", "bin": "ffuf", "verify": "-V",
             "why": "fast web content/parameter fuzzing"},
    "nuclei": {"repo": "projectdiscovery/nuclei", "bin": "nuclei", "verify": "-version",
               "why": "template-driven vulnerability scanning"},
    "subfinder": {"repo": "projectdiscovery/subfinder", "bin": "subfinder",
                  "verify": "-version", "why": "passive subdomain enumeration"},
    "httpx": {"repo": "projectdiscovery/httpx", "bin": "httpx", "verify": "-version",
              "why": "fast HTTP probing/fingerprinting"},
    "katana": {"repo": "projectdiscovery/katana", "bin": "katana", "verify": "-version",
               "why": "JS-aware crawler"},
    "naabu": {"repo": "projectdiscovery/naabu", "bin": "naabu", "verify": "-version",
              "why": "fast port scanner"},
    "dnsx": {"repo": "projectdiscovery/dnsx", "bin": "dnsx", "verify": "-version",
             "why": "bulk DNS toolkit"},
    "tlsx": {"repo": "projectdiscovery/tlsx", "bin": "tlsx", "verify": "-version",
             "why": "TLS handshake/certificate enumeration"},
    "amass": {"repo": "owasp-amass/amass", "bin": "amass", "verify": "-version",
              "why": "attack-surface enumeration"},
    "gobuster": {"repo": "OJ/gobuster", "bin": "gobuster", "verify": "version",
                 "why": "directory/DNS/vhost brute force"},
    "feroxbuster": {"repo": "epi052/feroxbuster", "bin": "feroxbuster",
                    "verify": "--version", "why": "recursive content discovery"},
    "chisel": {"repo": "jpillora/chisel", "bin": "chisel", "verify": "--version",
               "why": "TCP tunnel over HTTP"},
    "interactsh-client": {"repo": "projectdiscovery/interactsh",
                          "bin": "interactsh-client", "verify": "-version",
                          "why": "out-of-band interaction (blind SSRF/XXE)"},
    "gau": {"repo": "lc/gau", "bin": "gau", "verify": "--version",
            "why": "historical URLs from AlienVault/Wayback"},
    "waybackurls": {"repo": "tomnomnom/waybackurls", "bin": "waybackurls",
                    "verify": "", "why": "archived URL harvest"},
}


def provision(args):
    action = str(args.get("action") or "install").lower()
    name = str(args.get("tool") or args.get("name") or "").strip().lower()
    if action in ("list", "ls", "status"):
        rows = []
        for k, v in sorted(TOOL_REGISTRY.items()):
            found = which(v["bin"])
            rows.append({"tool": k, "installed": bool(found), "path": found,
                         "why": v["why"], "repo": v["repo"]})
        return {"ok": True, "bin_dir": BIN_DIR, "tools": rows,
                "installed_count": sum(1 for r in rows if r["installed"])}
    if action in ("install", "add", "get"):
        if not name and not args.get("repo"):
            return {"ok": False, "error": "missing tool name",
                    "available": sorted(TOOL_REGISTRY)}
        spec = TOOL_REGISTRY.get(name) or {}
        if spec and which(spec["bin"]) and not args.get("force"):
            p = which(spec["bin"])
            ver = run([p, spec["verify"]], timeout=30) if spec.get("verify") else {"out": ""}
            return {"ok": True, "tool": name, "already_installed": True, "path": p,
                    "version": (ver.get("out") or "").splitlines()[0][:120] if ver.get("out") else ""}
        repo = spec.get("repo") or args.get("repo")
        if not repo:
            return {"ok": False, "error": f"unknown tool {name}; pass repo=owner/name or "
                                          f"use one of {sorted(TOOL_REGISTRY)}"}
        rel = gh_api(f"/repos/{repo}/releases/latest")
        if not rel["ok"]:
            return rel
        assets = [{"name": a["name"], "url": a["browser_download_url"],
                   "size": a["size"], "digest": a.get("digest")}
                  for a in rel["data"].get("assets", [])]
        pick = _pick_asset(assets, args.get("pattern") or spec.get("asset"))
        if not pick:
            return {"ok": False, "error": "no release asset for this platform",
                    "assets": [a["name"] for a in assets][:25]}
        exp = None
        if str(pick.get("digest") or "").startswith("sha256:"):
            exp = pick["digest"].split(":", 1)[1]
        dl = download(pick["url"], dest=os.path.join(BIN_DIR, pick["name"]),
                      extract=True, chmod_x=True, expected_sha256=exp)
        if not dl.get("ok"):
            return dl
        want = spec.get("bin") or name or repo.split("/")[-1]
        candidates = []
        if dl.get("path") and os.path.isfile(dl["path"]):
            candidates.append(dl["path"])
        candidates.extend(dl.get("extracted", []) or [])
        chosen = None
        for c in candidates:
            base = os.path.basename(c).lower()
            if base == want.lower() or base.startswith(want.lower()):
                chosen = c
                break
        if not chosen:
            execs = []
            for c in candidates:
                if os.path.isfile(c):
                    with open(c, "rb") as f:
                        if sniff_bytes(f.read(4)) == "elf-binary":
                            execs.append(c)
            chosen = execs[0] if execs else None
        if not chosen:
            return {"ok": False, "error": "no executable found in the archive",
                    "download": dl}
        target = os.path.join(BIN_DIR, want)
        if os.path.abspath(chosen) != os.path.abspath(target):
            shutil.copy2(chosen, target)
        os.chmod(target, 0o755)
        verify = run([target, spec.get("verify") or "--version"], timeout=45)
        ver_line = next((l.strip()[:160] for l in (verify.get("out") or "").splitlines()
                         if l.strip()), "")
        return {"ok": True, "tool": name or want, "path": target, "version": ver_line,
                "release": rel["data"].get("tag_name"), "asset": pick["name"],
                "ran": bool(verify.get("ok")), "sha256": dl.get("sha256"),
                "note": ("installed and executable; available on PATH for tool=execute"
                         if verify.get("ok") else
                         "installed but the version check failed — inspect manually")}
    if action in ("uninstall", "remove"):
        spec = TOOL_REGISTRY.get(name)
        if not spec:
            return {"ok": False, "error": "unknown tool"}
        p = os.path.join(BIN_DIR, spec["bin"])
        if os.path.exists(p):
            os.remove(p)
            return {"ok": True, "removed": p}
        return {"ok": False, "error": "not installed in the managed bin dir"}
    return {"ok": False, "error": f"unknown action {action}",
            "valid": ["list", "install", "uninstall"]}


# ==========================================================================
# 7. NET — port scan, TLS, IP intel, HTTP probe, tech fingerprint
# ==========================================================================

SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 500: "isakmp", 512: "exec", 513: "login", 514: "syslog",
    515: "lpd", 548: "afp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
    902: "vmware", 993: "imaps", 995: "pop3s", 1025: "nfs-or-iis", 1080: "socks",
    1099: "rmi", 1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
    2049: "nfs", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "docker-tls",
    3000: "http-dev", 3128: "squid", 3260: "iscsi", 3306: "mysql", 3389: "rdp",
    4444: "metasploit", 4848: "glassfish", 5000: "http-dev", 5432: "postgres",
    5555: "adb", 5601: "kibana", 5672: "rabbitmq", 5900: "vnc", 5984: "couchdb",
    6000: "x11", 6379: "redis", 6443: "k8s-api", 7001: "weblogic", 7070: "realserver",
    8000: "http-alt", 8008: "http-alt", 8009: "ajp", 8080: "http-alt", 8081: "http-alt",
    8088: "http-alt", 8161: "activemq", 8443: "https-alt", 8888: "http-alt",
    9000: "portainer", 9042: "cassandra", 9090: "http-alt", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 9443: "https-alt", 9999: "http-alt",
    10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    27018: "mongodb", 50000: "sap", 50070: "hdfs", 61616: "activemq",
}
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
             465, 512, 513, 514, 587, 636, 873, 993, 995, 1080, 1433, 1521, 1723,
             2049, 2181, 2375, 3000, 3306, 3389, 4444, 5000, 5432, 5555, 5601,
             5672, 5900, 5984, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8088,
             8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017, 50000]


WEB_PORTS = [80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443]
DB_PORTS = [1433, 1521, 3306, 5432, 6379, 9042, 9200, 27017]


def parse_ports(spec):
    """'1-1000,3389' | 'top' | 'web' | 'db' | service names → port list.

    Presets can be mixed with explicit ports ("web,5002"), which is what the
    auto-fire planner uses when the objective names a service on a
    non-standard port: a plain "web" sweep would report nothing open for a
    host that is demonstrably listening.
    """
    spec = str(spec or "top").strip().lower()
    if spec in ("top", "top100", "common", ""):
        return sorted(TOP_PORTS)
    if spec in ("web", "http"):
        return list(WEB_PORTS)
    if spec in ("db", "database"):
        return list(DB_PORTS)
    if spec in ("all", "1-65535", "full"):
        return list(range(1, 65536))
    ports = set()
    for part in re.split(r"[,\s]+", spec):
        if not part:
            continue
        if part in ("top", "top100", "common"):
            ports.update(TOP_PORTS)
            continue
        if part in ("web", "http"):
            ports.update(WEB_PORTS)
            continue
        if part in ("db", "database"):
            ports.update(DB_PORTS)
            continue
        m = re.match(r"^(\d+)\s*-\s*(\d+)$", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                a, b = b, a
            ports.update(range(max(1, a), min(65535, b) + 1))
            continue
        if part.isdigit():
            ports.add(int(part))
            continue
        for p, svc in SERVICE_MAP.items():
            if svc == part:
                ports.add(p)
    return sorted(p for p in ports if 0 < p < 65536)


def _banner(ip, port, timeout=2.0, hostname=None):
    """Grab a service banner; sends a minimal probe for silent services."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 3000, 5000):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = s.recv(512)
            s.close()
            first = data.decode("latin-1", "replace").splitlines()
            return " | ".join(l.strip() for l in first[:1] + [
                l for l in first[1:8] if l.lower().startswith(("server:", "x-powered-by",
                                                               "location:", "http/"))])[:180]
        if port in (443, 8443, 9443, 465, 993, 995, 636):
            try:
                ctx = ssl._create_unverified_context()
                ss = ctx.wrap_socket(s, server_hostname=hostname or ip)
                ver = ss.version()
                cert = ss.getpeercert()
                cn = ""
                for tup in cert.get("subject", ()):
                    for k, v in tup:
                        if k == "commonName":
                            cn = v
                ss.close()
                return f"TLS {ver} cert CN={cn}" if cn else f"TLS {ver}"
            except Exception as e:
                return f"TLS error: {type(e).__name__}"
        if port == 22:
            pass
        s.settimeout(timeout)
        data = s.recv(512)
        s.close()
        return re.sub(r"\s+", " ", data.decode("latin-1", "replace")).strip()[:180]
    except Exception as e:
        return f"error: {type(e).__name__}"


def port_scan(host, ports="top", timeout=2.0, concurrency=250, banner=True):
    if not host:
        return {"ok": False, "error": "missing host"}
    host = re.sub(r"^(?:https?|ftp)://", "", str(host)).split("/")[0].split(":")[0]
    ips = RESOLVER.ips(host)
    if not ips:
        return {"ok": False, "error": f"cannot resolve {host}"}
    ip = next((i for i in ips if ":" not in i), ips[0])
    plist = parse_ports(ports)
    if not plist:
        return {"ok": False, "error": f"no ports parsed from {ports!r}"}
    if len(plist) > 20000:
        plist = plist[:20000]
    open_ports, lock = [], threading.Lock()
    sem = threading.Semaphore(max(1, min(int(concurrency), 500)))
    started = time.time()

    def worker(p):
        with sem:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                rc = s.connect_ex((ip, p))
                s.close()
                if rc == 0:
                    with lock:
                        open_ports.append(p)
            except Exception:
                pass

    threads = []
    for i in range(0, len(plist), 400):
        batch = [threading.Thread(target=worker, args=(p,), daemon=True)
                 for p in plist[i:i + 400]]
        for t in batch:
            t.start()
        for t in batch:
            t.join(timeout=timeout + 2)
        threads.extend(batch)
    results = [{"port": p, "service": SERVICE_MAP.get(p, "unknown")}
               for p in sorted(open_ports)]
    if banner and results:
        bsem = threading.Semaphore(16)

        def grab(entry):
            with bsem:
                entry["banner"] = _banner(ip, entry["port"],
                                          timeout=max(1.2, min(timeout, 2.5)),
                                          hostname=host)

        bthreads = [threading.Thread(target=grab, args=(e,), daemon=True) for e in results]
        for t in bthreads:
            t.start()
        for t in bthreads:
            t.join(timeout=8)
        for e in results:
            b = e.get("banner") or ""
            if b.startswith("error:"):
                e["banner_note"] = ("port accepted the TCP handshake but sent no banner — "
                                    "common for filtered/CDN endpoints")
    return {"ok": True, "host": host, "ip": ip, "scanned": len(plist),
            "open_count": len(results), "open_ports": results,
            "duration_s": round(time.time() - started, 1),
            "note": "TCP connect scan; provision tool=naabu for SYN-scale sweeps"}


def _decode_cert(der):
    """Decode a DER certificate without the `cryptography` package.

    getpeercert() returns {} whenever verification is disabled, which made
    every certificate look anonymous (empty issuer, no expiry, no SANs).
    Writing the PEM out and letting the stdlib test decoder read it fixes that
    with no dependency. Uses the workspace because this host has no /tmp.
    """
    if not der:
        return {}
    path = None
    try:
        os.makedirs(WORKSPACE, exist_ok=True)
        path = os.path.join(WORKSPACE,
                            ".apex_cert_%d_%d.pem" % (os.getpid(), threading.get_ident()))
        with open(path, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(path) or {}
    except Exception:
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def tls_info(host, port=443, sni=None):
    """Certificate + protocol detail without needing the openssl binary."""
    if not host:
        return {"ok": False, "error": "missing host"}
    host = re.sub(r"^(?:https?://)", "", str(host)).split("/")[0].split(":")[0]
    ips = RESOLVER.ips(host)
    ip = next((i for i in ips if ":" not in i), None) or host
    servername = sni or host
    out = {"ok": True, "host": host, "ip": ip, "port": int(port)}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, int(port)), timeout=15) as raw:
            with ctx.wrap_socket(raw, server_hostname=servername) as s:
                der = s.getpeercert(binary_form=True)
                cert = _decode_cert(der) or (s.getpeercert() or {})
                out["tls_version"] = s.version()
                out["cipher"] = s.cipher()[0] if s.cipher() else None
                out["subject"] = {k: v for tup in cert.get("subject", ()) for k, v in tup}
                out["issuer"] = {k: v for tup in cert.get("issuer", ()) for k, v in tup}
                out["not_before"] = cert.get("notBefore")
                out["not_after"] = cert.get("notAfter")
                out["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                out["sha256_fingerprint"] = hashlib.sha256(der).hexdigest() if der else None
                out["serial"] = cert.get("serialNumber")
    except Exception as e:
        return {"ok": False, "host": host, "ip": ip, "error": f"{type(e).__name__}: {e}"}
    try:
        exp = ssl.cert_time_to_seconds(out["not_after"] or "")
        days = int((exp - time.time()) // 86400)
        out["days_until_expiry"] = days
        out["expired"] = days < 0
        out["expires_soon"] = 0 <= days < 30
    except Exception:
        pass
    try:
        vctx = ssl.create_default_context()
        with socket.create_connection((ip, int(port)), timeout=15) as raw:
            with vctx.wrap_socket(raw, server_hostname=servername):
                out["verified_by_ca_store"] = True
    except Exception as e:
        out["verified_by_ca_store"] = False
        out["verify_error"] = f"{type(e).__name__}: {str(e)[:120]}"
    weak = []
    for name, ver in (("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                      ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
        if ver is None:
            continue
        try:
            c2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c2.check_hostname = False
            c2.verify_mode = ssl.CERT_NONE
            with contextlib.suppress(Exception):
                c2.minimum_version = ver
                c2.maximum_version = ver
            with socket.create_connection((ip, int(port)), timeout=8) as raw:
                with c2.wrap_socket(raw, server_hostname=servername):
                    weak.append(name)
        except Exception:
            pass
    out["weak_protocols_accepted"] = weak
    return out


def ip_intel(target):
    """Geo/ASN + reverse DNS + Shodan InternetDB in one call."""
    if not target:
        return {"ok": False, "error": "missing ip or host"}
    ips = RESOLVER.ips(target)
    ip = next((i for i in ips if ":" not in i), ips[0] if ips else None)
    if not ip:
        return {"ok": False, "error": f"cannot resolve {target}"}
    out = {"ok": True, "target": target, "ip": ip}
    try:
        g = SESSION.get(f"http://ip-api.com/json/{ip}",
                        params={"fields": "status,country,countryCode,regionName,city,"
                                          "zip,lat,lon,timezone,isp,org,as,asname,mobile,"
                                          "proxy,hosting,reverse,query"},
                        timeout=15, headers={"User-Agent": BOT_UA})
        if g.status_code == 200:
            out["geo"] = g.json()
    except Exception as e:
        out["geo_error"] = str(e)[:120]
    rev = RESOLVER.reverse(ip)
    if rev.get("ok"):
        out["ptr"] = rev.get("ptr")
    try:
        s = SESSION.get(f"https://internetdb.shodan.io/{ip}", timeout=20,
                        headers={"User-Agent": BOT_UA})
        if s.status_code == 200:
            j = s.json()
            out["shodan_internetdb"] = {"ports": j.get("ports", []),
                                        "hostnames": j.get("hostnames", []),
                                        "cpes": j.get("cpes", [])[:10],
                                        "tags": j.get("tags", []),
                                        "vulns": j.get("vulns", [])[:20]}
        elif s.status_code == 404:
            out["shodan_internetdb"] = {"note": "no observations for this IP"}
    except Exception as e:
        out["shodan_error"] = str(e)[:120]
    return out


_TECH = [
    ("WordPress", lambda h, b, c: "wp-content" in b or "wp-includes" in b, "cms"),
    ("Drupal", lambda h, b, c: "drupal" in b.lower() or h.get("x-drupal-cache") is not None, "cms"),
    ("Joomla", lambda h, b, c: "/media/jui/" in b or "joomla" in b.lower(), "cms"),
    ("Magento", lambda h, b, c: "magento" in b.lower() or "mage/cookies" in str(c).lower(), "cms"),
    ("Shopify", lambda h, b, c: "cdn.shopify.com" in b or h.get("x-shopify-stage") is not None, "cms"),
    ("Next.js", lambda h, b, c: "__NEXT_DATA__" in b or h.get("x-nextjs-cache") is not None, "framework"),
    ("Nuxt", lambda h, b, c: "__NUXT__" in b or "/_nuxt/" in b, "framework"),
    ("React", lambda h, b, c: "data-reactroot" in b or "react.development" in b or "__react" in b, "javascript"),
    ("Angular", lambda h, b, c: "ng-version" in b or "ng-app" in b, "javascript"),
    ("Vue.js", lambda h, b, c: "vue.js" in b.lower() or "data-v-" in b, "javascript"),
    ("jQuery", lambda h, b, c: "jquery" in b.lower(), "javascript"),
    ("Bootstrap", lambda h, b, c: "bootstrap.min.css" in b or "bootstrap/" in b, "css"),
    ("Django", lambda h, b, c: "csrfmiddlewaretoken" in b or "csrftoken" in str(c), "framework"),
    ("Laravel", lambda h, b, c: "laravel_session" in str(c) or "XSRF-TOKEN" in str(c), "framework"),
    ("Rails", lambda h, b, c: "_rails_session" in str(c) or "csrf-token" in b, "framework"),
    ("Spring", lambda h, b, c: "Whitelabel Error Page" in b or "JSESSIONID" in str(c), "framework"),
    ("ASP.NET", lambda h, b, c: "asp.net" in str(h.get("x-powered-by", "")).lower()
        or h.get("x-aspnet-version") is not None or "__viewstate" in b.lower(), "framework"),
    ("Express", lambda h, b, c: "express" in str(h.get("x-powered-by", "")).lower(), "framework"),
    ("PHP", lambda h, b, c: "php" in str(h.get("x-powered-by", "")).lower()
        or "phpsessid" in str(c).lower(), "language"),
    ("GraphQL", lambda h, b, c: "/graphql" in b or "__typename" in b, "api"),
    ("Swagger UI", lambda h, b, c: "swagger-ui" in b.lower() or "swagger.json" in b, "api"),
    ("Cloudflare", lambda h, b, c: h.get("cf-ray") is not None
        or "cloudflare" in str(h.get("server", "")).lower(), "cdn"),
    ("Akamai", lambda h, b, c: "akamai" in str(h.get("server", "")).lower()
        or h.get("x-akamai-transformed") is not None, "cdn"),
    ("Fastly", lambda h, b, c: "fastly" in str(h.get("x-served-by", "")).lower()
        or "fastly" in str(h.get("via", "")).lower(), "cdn"),
    ("Vercel", lambda h, b, c: h.get("x-vercel-id") is not None, "hosting"),
    ("Netlify", lambda h, b, c: "netlify" in str(h.get("server", "")).lower(), "hosting"),
    ("Nginx", lambda h, b, c: "nginx" in str(h.get("server", "")).lower(), "server"),
    ("Apache", lambda h, b, c: "apache" in str(h.get("server", "")).lower(), "server"),
    ("IIS", lambda h, b, c: "microsoft-iis" in str(h.get("server", "")).lower(), "server"),
    ("Caddy", lambda h, b, c: "caddy" in str(h.get("server", "")).lower(), "server"),
    ("OpenResty", lambda h, b, c: "openresty" in str(h.get("server", "")).lower(), "server"),
    ("Tomcat", lambda h, b, c: "tomcat" in b.lower()
        or "coyote" in str(h.get("server", "")).lower(), "server"),
    ("Jenkins", lambda h, b, c: "jenkins" in b.lower() or h.get("x-jenkins") is not None, "app"),
    ("GitLab", lambda h, b, c: "gitlab" in b.lower() or "_gitlab_session" in str(c), "app"),
    ("Grafana", lambda h, b, c: "grafana" in b.lower(), "app"),
    ("Kibana", lambda h, b, c: "kibana" in b.lower(), "app"),
    ("Jira", lambda h, b, c: "jira" in b.lower() or "atlassian" in b.lower(), "app"),
    ("phpMyAdmin", lambda h, b, c: "phpmyadmin" in b.lower(), "app"),
    ("Elasticsearch", lambda h, b, c: '"cluster_name"' in b and '"lucene_version"' in b, "app"),
    ("Kubernetes API", lambda h, b, c: '"kind":"Status"' in b and '"apiVersion"' in b, "app"),
]

SEC_HEADERS = ["strict-transport-security", "content-security-policy",
               "x-frame-options", "x-content-type-options", "referrer-policy",
               "permissions-policy", "cross-origin-opener-policy",
               "cross-origin-resource-policy"]


def tech_fingerprint(headers, body, cookies=""):
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    b = (body or "")[:600000]
    found = []
    for name, test, kind in _TECH:
        try:
            if test(h, b, cookies):
                found.append({"name": name, "kind": kind})
        except Exception:
            continue
    return found


def http_probe(url, follow=True, timeout=TIMEOUT):
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    r = fetch(url, timeout=timeout, allow_redirects=follow)
    tried = [url]
    if not r.get("ok"):
        alt = url.replace("https://", "http://", 1) if url.startswith("https://") else url
        r2 = fetch(alt, timeout=timeout, allow_redirects=follow)
        tried.append(alt)
        if r2.get("ok"):
            r = r2
        else:
            return {"ok": False, "error": r.get("error"), "tried": tried}
    body = r.get("body", "")
    soup = soup_of(body)
    title = soup.title.get_text(strip=True)[:200] if (soup and soup.title) else ""
    hdrs = r.get("headers", {})
    low = {k.lower(): v for k, v in hdrs.items()}
    resp = r.get("response")
    cookies = "; ".join(f"{c.name}={c.value}" for c in (resp.cookies if resp is not None else []))
    missing = [h for h in SEC_HEADERS if h not in low]
    eps = harvest_endpoints(body, base=r["url"])
    return {"ok": True, "url": r["url"], "status": r["status"],
            "server": low.get("server"), "powered_by": low.get("x-powered-by"),
            "title": title, "bytes": r.get("bytes"), "elapsed_ms": r.get("elapsed_ms"),
            "redirects": r.get("redirects"), "dns_pinned": r.get("dns_pinned"),
            "tech": tech_fingerprint(hdrs, body, cookies),
            "security_headers": {h: low.get(h) for h in SEC_HEADERS},
            "missing_security_headers": missing,
            "cookies": [c.name for c in (resp.cookies if resp is not None else [])],
            "forms": extract_forms(body, base=r["url"])[:10],
            "js_files": eps["js_files"][:40], "api_paths": eps["api_paths"][:40],
            "param_names": eps["params"][:40],
            "secrets": find_secrets(body)[:10],
            "body_head": re.sub(r"\s+", " ", body)[:1200]}


# ==========================================================================
# 8. DNS INTELLIGENCE — records, enumeration, AXFR, DNSSEC, mail, takeover
# ==========================================================================

ALL_RR = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"]

# Common names checked before anything is downloaded; the big list is opt-in.
SEED_SUBS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "mx", "remote", "vpn", "ftp",
    "api", "dev", "staging", "stage", "test", "qa", "uat", "demo", "beta", "admin",
    "portal", "app", "apps", "auth", "sso", "login", "id", "accounts", "secure",
    "cdn", "static", "assets", "media", "img", "images", "files", "download",
    "git", "gitlab", "jenkins", "ci", "build", "grafana", "kibana", "monitor",
    "status", "docs", "wiki", "confluence", "jira", "support", "help", "chat",
    "db", "mysql", "postgres", "redis", "mongo", "elastic", "es", "kafka",
    "intranet", "internal", "office", "owa", "autodiscover", "exchange", "ldap",
    "ns1", "ns2", "dns", "dns1", "dns2", "backup", "old", "new", "v2", "m",
    "mobile", "shop", "store", "pay", "payments", "billing", "crm", "erp",
    "proxy", "gw", "gateway", "edge", "lb", "vpn2", "sftp", "ssh", "bastion",
]

TAKEOVER_FINGERPRINTS = [
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "No such app"),
    ("s3.amazonaws.com", "NoSuchBucket"),
    ("azurewebsites.net", "Error 404 - Web app not found"),
    ("cloudfront.net", "Bad request"),
    ("fastly.net", "Fastly error: unknown domain"),
    ("pantheonsite.io", "The gods are wise"),
    ("readthedocs.io", "unknown to Read the Docs"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("ghost.io", "Domain is not configured"),
    ("teamwork.com", "Oops - We didn't find your site"),
    ("zendesk.com", "Help Center Closed"),
    ("statuspage.io", "This page is taking too long to load"),
    ("cargo.site", "404 Not Found"),
    ("unbounce.com", "The requested URL was not found"),
    ("netlify.app", "Not Found - Request ID"),
    ("vercel.app", "DEPLOYMENT_NOT_FOUND"),
    ("trafficmanager.net", "there is no resource with that name"),
    ("wordpress.com", "doesn’t exist"),
]


def dns_records(domain, types=None, include_ns_parent=False):
    """Resolve several record types at once through DoH."""
    domain = str(domain or "").strip().strip(".")
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).hostname or domain
    if not domain:
        return {"ok": False, "error": "missing domain"}
    types = types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    if isinstance(types, str):
        types = [t.strip().upper() for t in re.split(r"[,\s]+", types) if t.strip()]
    out, any_ok, errors = {}, False, {}
    for rt in types:
        res = RESOLVER.query(domain, rt)
        if res.get("ok") and res.get("records"):
            out[rt] = res["records"]
            any_ok = True
        elif res.get("ok"):
            out[rt] = []
        else:
            errors[rt] = res.get("error")
    ips = [r["value"] for r in out.get("A", []) if isinstance(r, dict) and r.get("value")]
    ptr = {}
    for ip in ips[:5]:
        rv = RESOLVER.reverse(ip)
        if rv.get("ok") and rv.get("ptr"):
            ptr[ip] = rv["ptr"]
    result = {"ok": any_ok or bool(out), "domain": domain, "records": out,
              "resolver": RESOLVER.last_provider, "ips": ips, "ptr": ptr or None}
    if errors and not any_ok:
        result["errors"] = errors
    return result


def dns_axfr(domain):
    """Attempt a zone transfer against every authoritative NS."""
    domain = str(domain or "").strip().strip(".")
    if not domain:
        return {"ok": False, "error": "missing domain"}
    ns_res = RESOLVER.query(domain, "NS")
    if not ns_res.get("ok") or not ns_res.get("records"):
        return {"ok": False, "error": "no NS records for zone"}
    nameservers = [r["value"] for r in ns_res["records"] if isinstance(r, dict)]
    try:
        import dns.query
        import dns.zone
        import dns.exception
    except Exception as e:
        return {"ok": False, "error": f"dnspython unavailable: {e}"}
    attempts, records = [], []
    for ns in nameservers:
        ns_ip = (RESOLVER.ips(ns) or [None])[0]
        if not ns_ip:
            attempts.append({"ns": ns, "error": "unresolvable"})
            continue
        try:
            xfr = dns.query.xfr(ns_ip, domain, timeout=15, lifetime=25)
            zone = dns.zone.from_xfr(xfr)
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(str(name) + " " + str(rdata))
            attempts.append({"ns": ns, "ip": ns_ip, "transferred": True,
                             "records": len(records)})
            break
        except dns.exception.FormError as e:
            attempts.append({"ns": ns, "ip": ns_ip, "transferred": False, "error": str(e)[:120]})
        except Exception as e:
            attempts.append({"ns": ns, "ip": ns_ip, "transferred": False,
                             "error": f"{type(e).__name__}: {str(e)[:100]}"})
    ok = any(a.get("transferred") for a in attempts)
    return {"ok": ok, "domain": domain, "nameservers": nameservers,
            "attempts": attempts, "record_count": len(records),
            "records": records[:500] if ok else [],
            "note": "AXFR open = full zone disclosure" if ok else
                    "all nameservers refused the transfer (expected)"}


CRT_URLS = ["https://crt.sh/?q={q}&output=json", "https://crt.sh/?q={q}"]


def subdomains(domain, brute=False, wordlist=None, max_names=600, concurrency=40):
    """Passive (crt.sh, hackertarget, wayback) plus optional DNS brute force."""
    domain = str(domain or "").strip().strip(".").lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).hostname or domain
    if not domain:
        return {"ok": False, "error": "missing domain"}
    found, sources = {}, {}
    # crt.sh certificate transparency
    try:
        r = fetch(CRT_URLS[0].format(q=quote("%." + domain)), timeout=45)
        certs = []
        if r.get("ok"):
            try:
                certs = json.loads(r["body"])
            except Exception:
                certs = [{"name_value": n} for n in re.findall(
                    r"[\w.*-]+\." + re.escape(domain), r["body"])]
        count = 0
        for c in certs if isinstance(certs, list) else []:
            for name in str(c.get("name_value", "")).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith("." + domain) and name != domain:
                    if name not in found:
                        found[name] = "crt.sh"
                        count += 1
        sources["crt.sh"] = count
    except Exception as e:
        sources["crt.sh"] = f"error: {str(e)[:80]}"
    # hackertarget hostsearch
    try:
        r = fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
        count = 0
        if r.get("ok") and "error" not in r.get("body", "")[:40].lower():
            for line in r["body"].splitlines():
                host = line.split(",")[0].strip().lower()
                if host.endswith("." + domain) and host not in found:
                    found[host] = "hackertarget"
                    count += 1
            sources["hackertarget"] = count
    except Exception as e:
        sources["hackertarget"] = f"error: {str(e)[:80]}"
    # wayback CDX index
    try:
        r = fetch("http://web.archive.org/cdx/search/cdx",
                  params={"url": f"*.{domain}/*", "output": "text", "fl": "original",
                          "collapse": "urlkey", "limit": "4000"}, timeout=60)
        count = 0
        if r.get("ok"):
            for line in r["body"].splitlines():
                m = re.match(r"https?://([^/:]+)", line.strip())
                if not m:
                    continue
                host = m.group(1).lower()
                if host.endswith("." + domain) and host not in found:
                    found[host] = "wayback"
                    count += 1
            sources["wayback"] = count
    except Exception as e:
        sources["wayback"] = f"error: {str(e)[:80]}"
    # optional brute force through DoH
    if brute:
        names = list(SEED_SUBS)
        if wordlist:
            wl = wordlist
            if not os.path.isabs(wl):
                cand = os.path.join(DL_DIR, os.path.basename(wl))
                if os.path.isfile(cand):
                    wl = cand
            if os.path.isfile(wl):
                try:
                    with open(wl, encoding="utf-8", errors="replace") as f:
                        extra = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                    names = list(dict.fromkeys(extra + names))
                except Exception:
                    pass
        else:
            # keep the on-device brute force bounded
            names = names[: max(60, min(int(max_names), 4000))]
        sem = threading.Semaphore(max(1, min(int(concurrency), 60)))
        hits = []

        def try_name(n):
            with sem:
                full = f"{n}.{domain}"
                res = RESOLVER.query(full, "A")
                if res.get("ok") and res.get("records"):
                    hits.append(full)

        threads = [threading.Thread(target=try_name, args=(n,), daemon=True) for n in names]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        new = 0
        for h in hits:
            if h not in found:
                found[h] = "bruteforce"
                new += 1
        sources["bruteforce"] = new
    order = sorted(found, key=lambda k: (len(k.split(".")), k))
    return {"ok": bool(found), "domain": domain, "count": len(order),
            "sources": sources, "subdomains": order[:max_names],
            "error": None if found else "no subdomains found in any source"}


def dns_dnssec(domain):
    domain = str(domain or "").strip().strip(".")
    if not domain:
        return {"ok": False, "error": "missing domain"}
    ds = RESOLVER.query(domain, "DS")
    dnskey = RESOLVER.query(domain, "DNSKEY")
    # RRSIG visibility through DoH: the AD flag means the resolver validated it
    ad_flag = None
    try:
        r = SESSION.get("https://dns.google/resolve",
                        params={"name": domain, "type": "A", "do": "1"},
                        headers={"Accept": "application/dns-json"}, timeout=15, verify=False)
        ad_flag = bool(r.json().get("AD"))
    except Exception:
        pass
    has_ds = bool(ds.get("ok") and ds.get("records"))
    has_key = bool(dnskey.get("ok") and dnskey.get("records"))
    return {"ok": True, "domain": domain, "ds_records": ds.get("records", []),
            "dnskey_records": [r.get("value", "")[:120] for r in dnskey.get("records", [])][:4],
            "validated_ad_flag": ad_flag, "signed": has_key,
            "chain_of_trust": has_ds and has_key, "ds_present": has_ds,
            "verdict": ("DNSSEC signed and validated" if (has_ds and has_key and ad_flag)
                        else "DNSSEC signed but not validating" if has_key
                        else "no DNSSEC")}


DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2",
                  "mail", "dkim", "s1", "s2", "smtp", "email", "mta", "protonmail",
                  "zoho", "mandrill", "mailchimp", "krs", "hs1", "hs2", "amazonses"]


def mail_auth(domain):
    """SPF, DMARC and DKIM posture — the usual 'spoofable mail' evidence."""
    domain = str(domain or "").strip().strip(".")
    if not domain:
        return {"ok": False, "error": "missing domain"}
    out = {"ok": True, "domain": domain}
    txt = RESOLVER.query(domain, "TXT")
    spf = [r for r in txt.get("records", [])
           if isinstance(r, dict) and str(r.get("value", "")).startswith("v=spf1")]
    out["spf"] = spf[0]["value"] if spf else None
    out["spf_present"] = bool(spf)
    if spf:
        v = spf[0]["value"]
        out["spf_all"] = (re.search(r"([~+\-?]all)\b", v).group(1)
                          if re.search(r"([~+\-?]all)\b", v) else "none")
        out["spf_lookups"] = len(re.findall(r"\b(?:include|a|mx|ptr|exists|redirect)\b", v))
        out["spf_weak_all"] = out["spf_all"] in ("+all", "?all", "none")
    dmarc = RESOLVER.query("_dmarc." + domain, "TXT")
    dm = [r for r in dmarc.get("records", [])
          if isinstance(r, dict) and "v=DMARC1" in str(r.get("value", ""))]
    out["dmarc"] = dm[0]["value"] if dm else None
    out["dmarc_present"] = bool(dm)
    if dm:
        p = re.search(r"\bp=(\w+)", dm[0]["value"])
        out["dmarc_policy"] = p.group(1) if p else None
        out["dmarc_weak_policy"] = out.get("dmarc_policy") in ("none", None)
    dkim = None
    for sel in DKIM_SELECTORS:
        r = RESOLVER.query(f"{sel}._domainkey.{domain}", "TXT")
        recs = [x for x in r.get("records", []) if isinstance(x, dict)]
        if recs:
            dkim = {"selector": sel, "record": str(recs[0].get("value", ""))[:200]}
            break
    out["dkim"] = dkim
    out["spoofable"] = (not out["dmarc_present"] or out.get("dmarc_weak_policy")) \
        and (not out["spf_present"] or out.get("spf_weak_all"))
    return out


def takeover_scan(domain, names=None):
    """CNAME takeover check for the apex and any discovered subdomains."""
    domain = str(domain or "").strip(".")
    if not domain:
        return {"ok": False, "error": "missing domain"}
    targets = list(names or [])
    if not targets:
        sub = subdomains(domain)
        targets = [domain] + (sub.get("subdomains") or [])[:40]
    findings, checked = [], 0
    for host in targets[:80]:
        cname = RESOLVER.query(host, "CNAME")
        chain = [r.get("value") for r in cname.get("records", [])
                 if isinstance(r, dict) and r.get("type") == "CNAME"]
        if not chain:
            continue
        checked += 1
        tail = chain[-1].lower()
        for svc, fingerprint in TAKEOVER_FINGERPRINTS:
            if svc in tail:
                probe = fetch(f"http://{tail}", timeout=20)
                body = probe.get("body", "") if probe.get("ok") else ""
                dangling = fingerprint.lower()[:20] in body.lower() or not probe.get("ok")
                findings.append({"host": host, "cname": chain,
                                 "service": svc, "dangling": dangling,
                                 "evidence": (body or probe.get("error") or "")[:200]})
                break
    return {"ok": True, "domain": domain, "checked": checked,
            "findings": findings,
            "verdict": ("possible takeover: dangling CNAME" if any(
                f.get("dangling") for f in findings) else "no dangling CNAME detected"),
            "caveat": "a CNAME to a SaaS host is not a takeover unless the app "
                      "behind it is unclaimed; verify by visiting it"}


# ==========================================================================
# 9. TUNNEL — public HTTPS URL for a local port via cloudflared
# ==========================================================================

def pid_alive(pid):
    """True if `pid` exists. Portable, and never signals the process.

    On Windows os.kill(pid, 0) is not a probe: it calls TerminateProcess with
    the given value as the exit code, so asking "are you alive?" would kill the
    process. OpenProcess + GetExitCodeProcess is the correct query there.
    """
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                return False
            try:
                code = wintypes.DWORD()
                if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                    return True
                return code.value == STILL_ACTIVE
            finally:
                k32.CloseHandle(h)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


class TunnelManager:
    """cloudflared quick tunnels, supervised and health-checked.

    A quick tunnel needs no Cloudflare account and gives a random
    https://*.trycloudflare.com name within a few seconds. The binary needs
    the DNS stub (no /etc/resolv.conf on this host) and a CA bundle, both of
    which env_for_child() and DNS_STUB provide.
    """

    def __init__(self):
        self.procs = {}
        self._lock = threading.Lock()
        self._load()

    # ---- state -------------------------------------------------------
    def _load(self):
        try:
            with open(TUNNEL_STATE, encoding="utf-8") as f:
                self.state = json.load(f)
        except Exception:
            self.state = {"tunnels": {}}

    def _save(self):
        try:
            tmp = TUNNEL_STATE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
            os.replace(tmp, TUNNEL_STATE)
        except Exception:
            pass

    def _alive(self, pid):
        if not pid or not pid_alive(pid):
            return False
        # PID reuse guard: a recycled pid would otherwise look like a live
        # connector and we would hand out a URL that answers 502.
        try:
            with open(f"/proc/{int(pid)}/cmdline", "rb") as f:
                return b"cloudflared" in f.read()
        except Exception:
            return True

    # ---- binary ------------------------------------------------------
    def ensure_binary(self):
        p = which("cloudflared")
        if p:
            return p, None
        res = provision({"action": "install", "tool": "cloudflared"})
        if res.get("ok"):
            return res.get("path") or which("cloudflared"), None
        return None, res.get("error", "could not install cloudflared")

    # ---- start -------------------------------------------------------
    def start(self, port, host="127.0.0.1", scheme="http", token=None,
              wait_seconds=45, health=True):
        try:
            port = int(port)
        except Exception:
            return {"ok": False, "error": "port must be an integer"}
        binary, err = self.ensure_binary()
        if not binary:
            return {"ok": False, "error": f"cloudflared unavailable: {err}"}
        DNS_STUB.start()
        target = f"{scheme}://{host}:{port}"
        if token:
            argv = [binary, "tunnel", "--no-autoupdate", "run", "--token", str(token)]
        else:
            argv = [binary, "tunnel", "--url", target, "--no-autoupdate",
                    "--loglevel", "info"]
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    env=env_for_child(), cwd=WORKSPACE)
        except Exception as e:
            return {"ok": False, "error": f"spawn failed: {e}"}
        tid = f"t{int(time.time())}{random.randint(100, 999)}"
        rec = {"id": tid, "port": port, "target": target, "pid": proc.pid,
               "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "url": None, "backend": "cloudflared",
               "mode": "token" if token else "quick", "log": []}
        url_re = re.compile(r"https://[a-z0-9][a-z0-9-]*\.trycloudflare\.com")
        deadline = time.time() + wait_seconds
        try:
            while time.time() < deadline:
                line = proc.stdout.readline() if proc.stdout else ""
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.3)
                    continue
                line = line.rstrip()
                rec["log"].append(line[:300])
                m = url_re.search(line)
                if m and "api.trycloudflare" not in m.group(0):
                    rec["url"] = m.group(0)
                    break
        except Exception:
            pass
        with self._lock:
            self.procs[tid] = proc
            self.state.setdefault("tunnels", {})[tid] = rec
            self._save()
        if not rec["url"]:
            tail = "\n".join(rec["log"][-6:])
            if token:
                return {"ok": True, "tunnel": rec, "note":
                        "token tunnel started; the hostname is defined in Cloudflare"}
            self.stop(tid)
            return {"ok": False,
                    "error": "cloudflared did not report a tunnel URL",
                    "log_tail": tail[:900],
                    "hint": "check egress on TCP 7844 / UDP 7844"}
        if health and not token:
            rec["health"] = self.check(rec["url"], port)
        with self._lock:
            self.state["tunnels"][tid] = rec
            self._save()
        return {"ok": True, "tunnel": rec,
                "public_url": rec["url"], "local_target": target,
                "note": "share this URL only with the authorized recipient list"}

    # ---- health ------------------------------------------------------
    def check(self, url, port=None, tries=8):
        """Verify the tunnel end to end, resolving the public name via DoH."""
        host = urlparse(url).hostname
        local = None
        if port:
            lr = fetch(f"http://127.0.0.1:{port}/", timeout=8)
            local = lr.get("status") if lr.get("ok") else lr.get("error")
        public = None
        for attempt in range(tries):
            r = fetch(url, timeout=20, retries=0, doh_pin=True)
            if r.get("ok"):
                public = r.get("status")
                if public and public < 500:
                    break
            time.sleep(min(2 + attempt, 6))
        return {"local_status": local, "public_status": public,
                "reachable": bool(public), "checked_at": time.time()}

    # ---- status / stop ----------------------------------------------
    def status(self, tid=None):
        rows = []
        for k, rec in list(self.state.get("tunnels", {}).items()):
            if tid and k != tid:
                continue
            rows.append({**rec, "running": self._alive(rec.get("pid"))})
        if tid:
            for r in rows:
                if r.get("url") and r.get("running"):
                    r["health"] = self.check(r["url"], r.get("port"), tries=2)
            return {"ok": bool(rows), "tunnel": rows[0] if rows else None,
                    "error": None if rows else f"no tunnel {tid}"}
        return {"ok": True, "count": len(rows), "tunnels": rows}

    def stop(self, tid=None):
        stopped = []
        with self._lock:
            targets = [tid] if tid else list(self.state.get("tunnels", {}).keys())
            for k in targets:
                rec = self.state.get("tunnels", {}).get(k)
                proc = self.procs.get(k)
                try:
                    if proc:
                        proc.terminate()
                        try:
                            proc.wait(timeout=6)
                        except Exception:
                            proc.kill()
                except Exception:
                    pass
                pid = (rec or {}).get("pid")
                if pid and self._alive(pid):
                    with contextlib.suppress(Exception):
                        os.kill(int(pid), 15)
                if rec:
                    rec["running"] = False
                    rec["stopped"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                stopped.append(k)
            self._save()
        return {"ok": True, "stopped": stopped}

    def expose(self, port, **kw):
        if not port:
            return {"ok": False, "error": "missing port"}
        existing = [t for t in self.status().get("tunnels", [])
                    if t.get("port") == int(port) and t.get("running") and t.get("url")]
        for rec in existing:
            # Reuse only a tunnel that still forwards traffic; a connector can
            # outlive its usefulness while its pid is recycled.
            h = self.check(rec["url"], int(port), tries=3)
            if h.get("public_status") and h["public_status"] < 500:
                rec["health"] = h
                return {"ok": True, "tunnel": rec, "public_url": rec["url"],
                        "reused": True}
            self.stop(rec["id"])
        return self.start(int(port), **kw)


TUNNELS = TunnelManager()


# ==========================================================================
# 10. BROWSER — one interface, several backends, degrade instead of fail
# ==========================================================================

BROWSER_ACTIONS = ["navigate", "text", "html", "links", "forms", "screenshot",
                   "js", "click", "type", "wait", "back", "close", "status"]


class BrowserDriver:
    """Playwright → CDP → agent-browser CLI → server-side render fallback."""

    def __init__(self):
        self.pw = None
        self.page = None
        self.backend = None
        self.error = None
        self.last_url = None
        self._lock = threading.Lock()
        self._detect()

    def _detect(self):
        if os.environ.get("APEX_BROWSER"):
            self.backend = os.environ["APEX_BROWSER"]
            return
        try:
            import playwright  # noqa: F401
            self.backend = "playwright"
            return
        except Exception:
            pass
        if which("agent-browser"):
            self.backend = "agent-browser"
            return
        try:
            import websockets  # noqa: F401
            if os.environ.get("APEX_CHROME_CDP"):
                self.backend = "cdp"
                return
        except Exception:
            pass
        if os.environ.get("APEX_CHROME_CDP"):
            self.backend = "cdp"
            return
        self.backend = "render"      # server-side rendering service, no local browser

    # ---- playwright --------------------------------------------------
    def _pw_start(self):
        from playwright.sync_api import sync_playwright
        self.pw = sync_playwright().start()
        browser = self.pw.chromium.launch(headless=True,
                                         args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = browser.new_context(user_agent=UA, viewport={"width": 1366, "height": 900})
        self.page = ctx.new_page()
        self.backend = "playwright-live"

    # ---- cdp ---------------------------------------------------------
    def _cdp_call(self, ws_url, method, params=None, session=None):
        import websockets.sync.client as ws_client
        payload = {"id": random.randint(1, 1 << 30), "method": method,
                   "params": params or {}}
        if session:
            payload["sessionId"] = session
        with ws_client.connect(ws_url, max_size=64 << 20, open_timeout=15) as ws:
            ws.send(json.dumps(payload))
            for _ in range(60):
                msg = json.loads(ws.recv(timeout=20))
                if msg.get("id") == payload["id"]:
                    return msg.get("result", {})

    def _cdp_endpoint(self):
        base = os.environ.get("APEX_CHROME_CDP", "http://127.0.0.1:9222")
        r = fetch(f"{base.rstrip('/')}/json/new?about:blank", method="PUT", timeout=10)
        if not r.get("ok"):
            r = fetch(f"{base.rstrip('/')}/json/new?about:blank", timeout=10)
        if r.get("ok"):
            try:
                j = json.loads(r["body"])
                if j.get("webSocketDebuggerUrl"):
                    return j["webSocketDebuggerUrl"]
            except Exception:
                pass
        r = fetch(f"{base.rstrip('/')}/json", timeout=10)
        if r.get("ok"):
            try:
                for t in json.loads(r["body"]):
                    if t.get("webSocketDebuggerUrl"):
                        return t["webSocketDebuggerUrl"]
            except Exception:
                pass
        return None

    def _cdp(self, action, url=None, js=None, selector=None, text=None, wait_seconds=2):
        ws = self._cdp_endpoint()
        if not ws:
            return {"ok": False, "error": "no CDP endpoint answering (APEX_CHROME_CDP)"}
        if action == "navigate":
            self._cdp_call(ws, "Page.navigate", {"url": url})
            time.sleep(max(1, int(wait_seconds)))
            r = self._cdp_call(ws, "Runtime.evaluate",
                               {"expression": "document.title + '\\n' + location.href",
                                "returnByValue": True})
            return {"ok": True, "backend": "cdp",
                    "result": r.get("result", {}).get("value")}
        expr = {"text": "document.body.innerText",
                "html": "document.documentElement.outerHTML",
                "links": "JSON.stringify([...document.querySelectorAll('a[href]')]"
                         ".map(a=>({url:a.href,text:a.innerText.trim().slice(0,120)})))",
                "js": js or "1"}.get(action)
        if action in ("click", "type"):
            if not selector:
                return {"ok": False, "error": "missing selector"}
            sel = json.dumps(selector)
            if action == "click":
                body = "e.click();return 'clicked';"
            else:
                body = ("e.value=" + json.dumps(str(text or "")) +
                        ";e.dispatchEvent(new Event('input',{bubbles:true}));"
                        "return 'typed';")
            expr = "(()=>{const e=document.querySelector(" + sel + ");" \
                   "if(!e)return 'no element';" + body + "})()"
        if expr is None:
            return {"ok": False, "error": f"unsupported cdp action {action}"}
        r = self._cdp_call(ws, "Runtime.evaluate",
                           {"expression": expr, "returnByValue": True, "awaitPromise": True})
        val = r.get("result", {}).get("value")
        return {"ok": True, "backend": "cdp",
                "result": (val if not isinstance(val, str) else val[:MAX_OUT * 2])}

    # ---- agent-browser CLI -------------------------------------------
    def _agent_browser(self, action, url=None, js=None, selector=None, text=None,
                       wait_seconds=2):
        exe = which("agent-browser")
        if not exe:
            return {"ok": False, "error": "agent-browser CLI not installed"}
        session = os.environ.get("APEX_AB_SESSION", "apex")
        argv = [exe, "--session", session]
        if action == "navigate":
            r = run(argv + ["open", url or "about:blank"], timeout=90)
            snap = run(argv + ["snapshot", "-i"], timeout=60)
            return {"ok": r["ok"], "backend": "agent-browser",
                    "stdout": r.get("stdout", "")[:1200],
                    "snapshot": snap.get("stdout", "")[:MAX_OUT]}
        if action == "text":
            r = run(argv + ["get", "text", "body"], timeout=60)
            return {"ok": r["ok"], "backend": "agent-browser",
                    "text": r.get("stdout", "")[:MAX_OUT * 2]}
        if action == "html":
            r = run(argv + ["get", "html"], timeout=60)
            return {"ok": r["ok"], "backend": "agent-browser",
                    "html": r.get("stdout", "")[:MAX_OUT * 2]}
        if action == "screenshot":
            path = os.path.join(WORKSPACE, "screenshots",
                                f"shot_{int(time.time())}.png")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            r = run(argv + ["screenshot", path], timeout=90)
            return {"ok": r["ok"], "backend": "agent-browser", "path": path,
                    "stdout": r.get("stdout", "")[:400]}
        if action == "click" and selector:
            r = run(argv + ["click", selector], timeout=60)
            return {"ok": r["ok"], "backend": "agent-browser", "stdout": r.get("stdout", "")[:400]}
        if action == "type" and selector:
            r = run(argv + ["fill", selector, text or ""], timeout=60)
            return {"ok": r["ok"], "backend": "agent-browser", "stdout": r.get("stdout", "")[:400]}
        if action == "js" and js:
            r = run(argv + ["eval", js], timeout=60)
            return {"ok": r["ok"], "backend": "agent-browser", "result": r.get("stdout", "")[:MAX_OUT]}
        return {"ok": False, "error": f"agent-browser backend has no {action} action"}

    # ---- server-side render -----------------------------------------
    def _render(self, action, url=None, js=None, selector=None, text=None,
                wait_seconds=2):
        url = url or self.last_url
        if not url:
            return {"ok": False, "error": "no page loaded yet — pass url on the first call"}
        r = fetch(f"https://r.jina.ai/{url}", timeout=60,
                  headers={"X-Return-Format": "markdown", "Accept": "text/plain"})
        if r.get("ok") and r.get("status", 500) < 400 and len(r.get("body", "")) > 80:
            body = r["body"]
            if action in ("text", "navigate"):
                return {"ok": True, "backend": "render-proxy", "url": url,
                        "text": body[:MAX_OUT * 3],
                        "note": "rendered server-side (JavaScript executed off-host)"}
            if action == "links":
                # The render proxy answers markdown, so links are [text](url).
                seen, links = set(), []
                for m in re.finditer(r"\[([^\]]*)\]\((https?://[^)\s]+)\)", body):
                    u = _clean_url(m.group(2))
                    if u in seen:
                        continue
                    seen.add(u)
                    links.append({"url": u, "text": (m.group(1) or "").strip()[:120]})
                if not links:
                    links = extract_links(body, base=url, limit=200)
                return {"ok": True, "backend": "render-proxy", "url": url,
                        "count": len(links), "links": links[:200]}
            if action == "html":
                return {"ok": True, "backend": "render-proxy",
                        "html": body[:MAX_OUT * 3]}
        page = fetch(url, timeout=40)
        if not page.get("ok"):
            return {"ok": False, "error": page.get("error"),
                    "hint": "install a browser backend: pip install playwright && "
                            "playwright install chromium, or set APEX_CHROME_CDP"}
        html_text = page["body"]
        out = {"ok": True, "backend": "static-fetch", "url": page["url"],
               "status": page["status"], "html_bytes": len(html_text)}
        if action in ("text", "navigate"):
            out["text"] = readable_text(html_text, MAX_OUT * 2)
            soup = soup_of(html_text)
            if soup and soup.title:
                out["title"] = soup.title.get_text(strip=True)[:200]
            if len(out["text"]) < 300:
                out["hint"] = ("page is JavaScript-driven; try tool=browser with "
                               "action=navigate url=<same> again (render proxy) or "
                               "install a real browser backend")
        elif action == "links":
            out["links"] = extract_links(html_text, base=page["url"], limit=200)
        elif action == "forms":
            out["forms"] = extract_forms(html_text, base=page["url"])
        elif action == "html":
            out["html"] = html_text[:MAX_OUT * 3]
        else:
            return {"ok": False, "error": f"static backend cannot do {action}"}
        return out

    # ---- public ------------------------------------------------------
    def run(self, action, **kw):
        action = (action or "navigate").lower()
        if action in ("get_text", "extract_text"):
            action = "text"
        if action in ("get_html", "source"):
            action = "html"
        if action in ("extract_links", "get_links"):
            action = "links"
        if action in ("eval_js", "eval", "evaluate"):
            action = "js"
        with self._lock:
            if action == "status":
                return {"ok": True, "backend": self.backend, "error": self.error,
                        "playwright": self._has("playwright"),
                        "agent_browser": bool(which("agent-browser")),
                        "cdp_endpoint": os.environ.get("APEX_CHROME_CDP"),
                        "actions": BROWSER_ACTIONS}
            if action == "close":
                return {"ok": True, "note": "no persistent browser process is held"}
            if kw.get("url"):
                self.last_url = kw["url"]
            elif self.last_url:
                kw["url"] = self.last_url
            if self.backend == "playwright":
                try:
                    self._pw_start()
                except Exception as e:
                    self.error = f"{type(e).__name__}: {str(e)[:200]}"
                    self.backend = "agent-browser" if which("agent-browser") else "render"
            try:
                if self.backend.startswith("playwright"):
                    return self._pw(action, **kw)
                if self.backend == "cdp":
                    return self._cdp(action, **kw)
                if self.backend == "agent-browser":
                    return self._agent_browser(action, **kw)
                return self._render(action, **kw)
            except Exception as e:
                return {"ok": False, "backend": self.backend,
                        "error": f"{type(e).__name__}: {str(e)[:200]}"}

    def _has(self, mod):
        try:
            __import__(mod)
            return True
        except Exception:
            return False

    def _pw(self, action, url=None, js=None, selector=None, text=None,
            wait_seconds=2, full_page=True):
        p = self.page
        if action == "navigate":
            if not url:
                return {"ok": False, "error": "navigate needs url"}
            resp = p.goto(url, timeout=60000, wait_until="domcontentloaded")
            p.wait_for_timeout(int(float(wait_seconds or 2) * 1000))
            return {"ok": True, "backend": self.backend, "url": p.url,
                    "status": resp.status if resp else None, "title": p.title(),
                    "html_bytes": len(p.content())}
        if action == "text":
            txt = (p.inner_text(selector) if selector else p.inner_text("body"))
            return {"ok": True, "backend": self.backend, "url": p.url,
                    "text": txt[:MAX_OUT * 3]}
        if action == "html":
            return {"ok": True, "backend": self.backend,
                    "html": p.content()[:MAX_OUT * 3]}
        if action == "links":
            links = p.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => ({url: e.href, text: e.innerText.trim().slice(0,120)}))")
            return {"ok": True, "backend": self.backend, "links": links[:300],
                    "count": len(links)}
        if action == "forms":
            return {"ok": True, "backend": self.backend,
                    "forms": extract_forms(p.content(), base=p.url)}
        if action == "js":
            if not js:
                return {"ok": False, "error": "js action needs js=<expression>"}
            return {"ok": True, "backend": self.backend,
                    "result": str(p.evaluate(js))[:MAX_OUT * 2]}
        if action == "click":
            if not selector:
                return {"ok": False, "error": "click needs selector"}
            p.click(selector, timeout=20000)
            p.wait_for_timeout(int(float(wait_seconds or 1) * 1000))
            return {"ok": True, "backend": self.backend, "url": p.url, "title": p.title()}
        if action == "type":
            if not selector:
                return {"ok": False, "error": "type needs selector"}
            p.fill(selector, str(text or ""), timeout=20000)
            return {"ok": True, "backend": self.backend, "typed_into": selector}
        if action == "wait":
            p.wait_for_timeout(int(float(wait_seconds or 3) * 1000))
            return {"ok": True, "backend": self.backend, "url": p.url}
        if action == "back":
            p.go_back()
            return {"ok": True, "backend": self.backend, "url": p.url}
        if action == "screenshot":
            path = os.path.join(WORKSPACE, "screenshots", f"shot_{int(time.time())}.png")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            p.screenshot(path=path, full_page=bool(full_page))
            return {"ok": True, "backend": self.backend, "path": path}
        return {"ok": False, "error": f"unsupported action {action}",
                "actions": BROWSER_ACTIONS}


BROWSER = BrowserDriver()


# ==========================================================================
# 11. WEB helpers — robots, sitemap, wayback, diff, JS endpoints
# ==========================================================================

def robots(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    base = "{0.scheme}://{0.netloc}".format(urlparse(url))
    r = fetch(base + "/robots.txt", timeout=20)
    if not r.get("ok") or r.get("status") != 200:
        return {"ok": False, "url": base + "/robots.txt",
                "error": r.get("error") or f"HTTP {r.get('status')}"}
    body = r["body"]
    disallow = re.findall(r"(?im)^\s*disallow:\s*(\S*)", body)
    allow = re.findall(r"(?im)^\s*allow:\s*(\S*)", body)
    sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", body)
    agents = re.findall(r"(?im)^\s*user-agent:\s*(\S+)", body)
    return {"ok": True, "url": base + "/robots.txt", "bytes": len(body),
            "user_agents": agents[:10],
            "disallow": [d for d in disallow if d][:120],
            "allow": [a for a in allow if a][:60], "sitemaps": sitemaps[:10],
            "interesting": [d for d in disallow
                            if re.search(r"admin|backup|config|db|private|internal|"
                                         r"api|debug|test|staging|\.git|\.env", d, re.I)][:30],
            "raw_head": body[:1500]}


def sitemap(url, max_urls=300):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    seen, urls = set(), []

    def walk(sm, depth=0):
        if sm in seen or depth > 3 or len(urls) >= max_urls:
            return
        seen.add(sm)
        r = fetch(sm, timeout=30)
        if not r.get("ok"):
            return
        text = r["body"]
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I)
        is_index = bool(re.search(r"<sitemapindex\b", text, re.I))
        for loc in locs:
            if is_index or loc.lower().endswith((".xml", ".xml.gz")):
                walk(loc, depth + 1)
            elif loc not in urls:
                urls.append(loc)
            if len(urls) >= max_urls:
                return

    walk(url)
    if not urls:
        rb = robots(url)
        for sm in rb.get("sitemaps", [])[:5]:
            walk(sm)
    return {"ok": bool(urls), "start": url, "sitemaps_read": len(seen),
            "count": len(urls), "urls": urls[:max_urls],
            "error": None if urls else "no sitemap entries found"}


def wayback(url, limit=200, since=None):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    params = {"url": url if "*" in url else url + "*", "output": "json",
              "fl": "timestamp,original,statuscode,mimetype", "collapse": "urlkey",
              "limit": str(min(int(limit), 5000))}
    if since:
        params["from"] = str(since)
    r = fetch("http://web.archive.org/cdx/search/cdx", params=params, timeout=90)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error")}
    try:
        rows = json.loads(r["body"]) if r["body"].strip().startswith("[") else []
    except Exception:
        rows = []
    if rows and isinstance(rows[0], list) and rows[0] and rows[0][0] == "timestamp":
        rows = rows[1:]
    out = []
    for row in rows[: int(limit)]:
        if isinstance(row, list) and len(row) >= 2:
            ts, orig = row[0], row[1]
            out.append({"timestamp": ts, "url": orig,
                        "status": row[2] if len(row) > 2 else None,
                        "mime": row[3] if len(row) > 3 else None,
                        "snapshot": f"https://web.archive.org/web/{ts}/{orig}"})
    kinds = {}
    for o in out:
        k = (o["mime"] or "?").split(";")[0]
        kinds[k] = kinds.get(k, 0) + 1
    return {"ok": bool(out), "target": url, "count": len(out),
            "mimetypes": kinds, "results": out[:limit],
            "error": None if out else "no archived captures"}


def js_endpoints(url, limit=60):
    """Fetch a page, then its script bundles, and mine API paths and secrets."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    page = fetch(url, timeout=40)
    if not page.get("ok"):
        return {"ok": False, "error": page.get("error")}
    eps = harvest_endpoints(page["body"], base=page["url"])
    paths = set(eps["api_paths"])
    secrets = find_secrets(page["body"])
    scanned = []
    for js in eps["js_files"][:8]:
        r = fetch(js, timeout=30)
        if not r.get("ok"):
            continue
        scanned.append({"js": js, "bytes": r.get("bytes")})
        for m in re.finditer(r'["\'`](/?(?:api|v\d|graphql|rest|internal|admin|auth)'
                             r'[A-Za-z0-9_\-./{}$]{0,90})["\'`]', r["body"]):
            paths.add(m.group(1) if m.group(1).startswith("/") else "/" + m.group(1))
        secrets.extend(find_secrets(r["body"], limit=20))
    return {"ok": True, "page": page["url"], "scripts_scanned": scanned,
            "endpoints": sorted(paths)[:limit], "secrets": secrets[:20],
            "forms": extract_forms(page["body"], base=page["url"])[:8]}


def diff_urls(url_a, url_b, headers=None):
    a = fetch(url_a, headers=headers, timeout=30)
    b = fetch(url_b, headers=headers, timeout=30)
    if not (a.get("ok") and b.get("ok")):
        return {"ok": False, "error": a.get("error") or b.get("error")}
    import difflib
    ta = readable_text(a["body"]).splitlines()
    tb = readable_text(b["body"]).splitlines()
    delta = list(difflib.unified_diff(ta, tb, fromfile=url_a, tofile=url_b, lineterm="", n=2))
    return {"ok": True, "identical": a["body"] == b["body"],
            "len_a": len(a["body"]), "len_b": len(b["body"]),
            "status_a": a["status"], "status_b": b["status"],
            "diff": ("\n".join(delta))[:MAX_OUT * 2] or "(no textual difference)"}


# ==========================================================================
# 12. DISPATCH
# ==========================================================================

def tool_dns(args):
    action = str(args.get("action") or "records").lower()
    domain = args.get("domain") or args.get("host") or args.get("target")
    if action in ("records", "lookup", "query"):
        return dns_records(domain, args.get("record") or args.get("type") or args.get("records"))
    if action in ("subdomains", "subs", "enum"):
        return subdomains(domain, brute=bool(args.get("brute")),
                          wordlist=args.get("wordlist"),
                          max_names=int(args.get("max") or 600),
                          concurrency=int(args.get("concurrency") or 40))
    if action in ("axfr", "zone_transfer", "transfer"):
        return dns_axfr(domain)
    if action in ("dnssec", "dnssec_check"):
        return dns_dnssec(domain)
    if action in ("mail", "mail_auth", "email", "spf"):
        return mail_auth(domain)
    if action in ("reverse", "ptr"):
        return RESOLVER.reverse(args.get("ip") or domain)
    if action in ("takeover", "cname_takeover"):
        return takeover_scan(domain, args.get("names"))
    if action in ("stub", "stub_status"):
        return {"ok": True, **DNS_STUB.status(),
                "why": "binaries on this host have no /etc/resolv.conf"}
    return {"ok": False, "error": f"unknown dns action {action}",
            "valid": ["records", "subdomains", "axfr", "dnssec", "mail", "reverse",
                      "takeover", "stub"]}


def tool_fetch(args):
    """Full-page fetch with readability text, links, forms, endpoints."""
    url = args.get("url")
    if not url:
        return {"ok": False, "error": "missing url"}
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    mode = str(args.get("action") or "text").lower()
    if mode in ("robots",):
        return robots(url)
    if mode in ("sitemap", "sitemap_urls"):
        return sitemap(url, int(args.get("max") or 300))
    if mode in ("wayback", "archive", "history"):
        return wayback(url, int(args.get("max") or 200), args.get("since"))
    if mode in ("js", "endpoints", "harvest"):
        return js_endpoints(url)
    if mode in ("diff",):
        if not args.get("url_b"):
            return {"ok": False, "error": "diff needs url_b"}
        return diff_urls(url, args["url_b"], args.get("headers"))
    r = fetch(url, headers=args.get("headers"), timeout=int(args.get("timeout") or TIMEOUT),
              method=str(args.get("method") or "GET"), data=args.get("body"))
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error"), "url": url}
    body = r["body"]
    out = {"ok": True, "url": r["url"], "status": r["status"], "bytes": r.get("bytes"),
           "content_type": (r.get("headers") or {}).get("Content-Type"),
           "dns_pinned": r.get("dns_pinned")}
    soup = soup_of(body)
    if soup and soup.title:
        out["title"] = soup.title.get_text(strip=True)[:200]
    eps = harvest_endpoints(body, base=r["url"])
    if mode in ("links",):
        out["links"] = extract_links(body, base=r["url"], limit=250)
    elif mode in ("forms",):
        out["forms"] = extract_forms(body, base=r["url"])
    elif mode in ("full", "all"):
        out["text"] = readable_text(body, MAX_OUT * 2)
        out["links"] = extract_links(body, base=r["url"], limit=120)
        out["forms"] = extract_forms(body, base=r["url"])[:10]
        out["js_files"] = eps["js_files"][:30]
        out["api_paths"] = eps["api_paths"][:30]
        out["comments"] = eps["comments"][:15]
    elif mode in ("json",):
        try:
            out["json"] = json.loads(body)
        except Exception:
            out["raw"] = body[:MAX_OUT * 2]
    elif mode in ("raw",):
        out["raw"] = body[:MAX_OUT * 3]
    else:
        out["text"] = readable_text(body, MAX_OUT * 2)
    secrets = find_secrets(body)
    if secrets:
        out["secrets"] = secrets[:10]
    if len(out.get("text") or "") < 250 and mode in ("text", "full", "all"):
        out["hint"] = "page looks JavaScript-rendered — try tool=browser action=navigate"
    return out


def tool_web_search(args):
    queries = args.get("queries") or args.get("query") or args.get("q")
    if isinstance(queries, str):
        queries = [queries]
    if not queries:
        return {"ok": False, "error": "missing query"}
    limit = int(args.get("limit") or 10)
    engines = args.get("engines")
    out, seen = [], set()
    for q in list(queries)[:3]:
        res = web_search(q, engines=engines, limit=limit,
                         time_filter=args.get("time") if args.get("time") in
                         ("past_day", "past_week", "past_month", "past_year") else None)
        for item in res.get("results", []):
            key = item["url"].split("#")[0].rstrip("/")
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return {"ok": bool(out), "count": len(out), "results": out[:limit * 2],
            "queries": list(queries)[:3],
            "error": None if out else "no search engine returned results"}


def tool_tunnel(args):
    action = str(args.get("action") or "status").lower()
    if action in ("start", "expose", "open", "run"):
        port = args.get("port") or args.get("local_port")
        if not port and args.get("url"):
            u = urlparse(str(args["url"]))
            port = u.port or (443 if u.scheme == "https" else 80)
        if not port:
            return {"ok": False, "error": "missing port (local service to expose)"}
        return TUNNELS.expose(int(port), host=str(args.get("host") or "127.0.0.1"),
                              scheme=str(args.get("scheme") or "http"),
                              token=args.get("token"),
                              wait_seconds=int(args.get("wait") or 45))
    if action in ("status", "list", "ls"):
        return TUNNELS.status(args.get("id"))
    if action in ("check", "health"):
        url = args.get("url")
        if not url:
            st = TUNNELS.status()
            items = [t for t in st.get("tunnels", []) if t.get("url")]
            if not items:
                return {"ok": False, "error": "no tunnel with a URL"}
            url, port = items[-1]["url"], items[-1].get("port")
        else:
            port = args.get("port")
        return {"ok": True, "url": url, "health": TUNNELS.check(url, port)}
    if action in ("stop", "kill", "close"):
        return TUNNELS.stop(args.get("id"))
    if action in ("install", "ensure"):
        p, err = TUNNELS.ensure_binary()
        return {"ok": bool(p), "path": p, "error": err}
    return {"ok": False, "error": f"unknown tunnel action {action}",
            "valid": ["start", "status", "check", "stop", "install"]}


def tool_env(args):
    """Describe what this box can actually do right now."""
    stub = DNS_STUB.status() if not args.get("start_stub") else (
        DNS_STUB.start(), DNS_STUB.status())[1]
    probe = {}
    for host in ("github.com", "example.com"):
        probe[host] = {"doh": len(RESOLVER.ips(host)),
                       "libc": (lambda: sorted({a[4][0] for a in
                                                socket.getaddrinfo(host, None)}))()
                       if _libc_ok(host) else "FAILED"}
    return {"ok": True, "python": sys.version.split()[0], "platform": platform.platform(),
            "arch": ARCH, "workspace": WORKSPACE, "bin_dir": BIN_DIR,
            "downloads": DL_DIR, "ca_bundle": _ca_bundle(),
            "dns_stub": stub, "resolution": probe,
            "resolver_provider": RESOLVER.last_provider,
            "resolver_cache": len(_cache),
            "browser": BROWSER.run("status"),
            "tunnel_binary": which("cloudflared"),
            "installed_tools": [t for t in TOOL_REGISTRY if which(TOOL_REGISTRY[t]["bin"])],
            "cloudflared_version": (run([which("cloudflared"), "--version"], timeout=30).get("out", "").splitlines() or [""])[0] if which("cloudflared") else None}


def _libc_ok(host):
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


TOOL_SPECS = {
    "dns_lookup": '{"action":"records","domain":"example.com","record":"A,MX,TXT"}',
    "dns_enum": '{"action":"subdomains","domain":"example.com","brute":true,"max":600}',
    "web_search": '{"queries":["…"],"limit":10,"time":"all"}',
    "fetch_url": '{"url":"https://…","action":"text|links|forms|full|js|json|raw|robots|sitemap|wayback|diff"}',
    "github": '{"action":"releases|file|tree|search_repos|search_code|download|clone","repo":"owner/name","path":"…","tag":"…","pattern":"*arm64*"}',
    "download": '{"url":"https://…","dest":"name","extract":true,"chmod_x":true,"max_bytes":200000000}',
    "extract": '{"path":"/abs/archive.zip"}',
    "provision": '{"action":"install","tool":"nuclei"}',
    "port_scan": '{"host":"example.com","ports":"top|1-1000|web","banner":true}',
    "tls_info": '{"host":"example.com","port":443}',
    "ip_intel": '{"target":"8.8.8.8"}',
    "http_probe": '{"url":"https://example.com"}',
    "tunnel": '{"action":"start","port":8088}',
    "browser": '{"action":"navigate|text|html|links|forms|js|click|type|screenshot|status","url":"…","selector":"…","js":"…"}',
    "env_check": '{}',
}


def call(name, args=None):
    """Single entry point used by the agent loop. Never raises."""
    args = args if isinstance(args, dict) else {}
    try:
        if name in ("dns_lookup", "dns"):
            return tool_dns(args)
        if name == "dns_enum":
            a = dict(args)
            a.setdefault("action", "subdomains")
            return tool_dns(a)
        if name in ("web_search", "search"):
            return tool_web_search(args)
        if name in ("fetch_url", "open_url", "fetch", "read_url"):
            return tool_fetch(args)
        if name in ("github", "gh"):
            return github(args)
        if name in ("download", "dl"):
            if not args.get("url"):
                return {"ok": False, "error": "missing url"}
            return download(args["url"], dest=args.get("dest") or args.get("path"),
                            max_bytes=args.get("max_bytes"),
                            extract=bool(args.get("extract")),
                            chmod_x=bool(args.get("chmod_x")),
                            expected_sha256=args.get("sha256"),
                            headers=args.get("headers"))
        if name in ("extract", "extract_archive", "unzip"):
            return extract_archive(args.get("path") or args.get("file"),
                                   args.get("into"))
        if name in ("provision", "install_tool"):
            return provision(args)
        if name == "port_scan":
            return port_scan(args.get("host") or args.get("target") or args.get("ip"),
                             args.get("ports") or args.get("port") or "top",
                             float(args.get("timeout") or 2.0),
                             int(args.get("concurrency") or 250),
                             bool(args.get("banner", True)))
        if name == "tls_info":
            return tls_info(args.get("host") or args.get("domain") or args.get("url"),
                            int(args.get("port") or 443), args.get("sni"))
        if name in ("ip_intel", "ipinfo", "whois_ip"):
            return ip_intel(args.get("target") or args.get("ip") or args.get("host"))
        if name == "http_probe":
            return http_probe(args.get("url") or args.get("host"),
                              bool(args.get("follow", True)))
        if name == "tunnel":
            return tool_tunnel(args)
        if name == "browser":
            kw = {k: args[k] for k in ("url", "selector", "text", "js", "wait_seconds",
                                       "full_page") if k in args}
            return BROWSER.run(args.get("action") or "navigate", **kw)
        if name in ("env_check", "doctor"):
            return tool_env(args)
        return {"ok": False, "error": f"apex_tools has no tool {name}",
                "available": sorted(TOOL_SPECS)}
    except Exception as e:
        return {"ok": False, "error": f"{name} failed: {type(e).__name__}: {e}"}


def tool_help():
    """Prompt-ready description of this layer."""
    lines = []
    for k, v in TOOL_SPECS.items():
        lines.append(f"- {k}: {v}")
    return "\n".join(lines)


def self_test():
    """Quick health summary used by env_check."""
    return {"stub": DNS_STUB.status(), "dns": len(RESOLVER.ips("github.com")),
            "browser": BROWSER.backend, "ca": _ca_bundle(),
            "bin": [t for t in TOOL_REGISTRY if which(TOOL_REGISTRY[t]["bin"])]}


if __name__ == "__main__":
    print(json.dumps(self_test(), indent=2))
