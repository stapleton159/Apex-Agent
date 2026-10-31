"""apex_selfedit — operator-directed self-modification loop for the harness.

The operator types what capability is missing ("add a tab that shows X", "make
the gate accept Y", "log every request to a file"). A model turns that into a
list of exact string replacements against the harness sources. The engine:

  1. backs every editable file up (sha256 manifest) into
     apex_workspace/selfedit/runs/<run>/backup
  2. asks the model for strict JSON ops and applies them in memory
  3. writes them atomically, then validates: python compiles, harness anchors
     survived, the UI keeps every tab matched to a panel
  4. on a failed validation the backup is restored immediately and the error is
     fed back into the next iteration (the loop, like the agent loop)
  5. on success the restart is handed to apex_selfedit_supervisor.py, because
     the process that rewrote itself cannot verify that it came back up. The
     supervisor waits for this pid to die, launches the harness, polls /health,
     and restores the backup + relaunches if the harness cannot boot.

Phases: idle -> planning -> applying -> validating -> restarting -> done
        (or) failed | rolled_back | stopped

Only files in EDITABLE may be touched. The supervisor is deliberately excluded:
it is the recovery path, so it must never be the thing being modified.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid

import requests

# --------------------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------------------

EDITABLE = ["scriptai2.py", "templates/index.html", "apex_selfedit.py",
            "apex_ops.py", "apex_tools.py"]

# Present in the backup => must still be present after the edit. This is what
# stops a "small fix" from quietly deleting the agent loop or the UI shell.
ANCHORS = {
    "scriptai2.py": [
        'if __name__ == "__main__":',
        "APP.run(",
        '@APP.route("/status")',
        "def agent_loop(",
        "def dispatch_tool(",
        "SELFEDIT.register(",
    ],
    "templates/index.html": [
        '<nav role="tablist">',
        'data-tab="console"',
        'id="selfedit"',
    ],
}

MAX_ITERS = int(os.environ.get("SELFEDIT_MAX_ITERS", "3"))
MAX_PATCH = int(os.environ.get("SELFEDIT_MAX_PATCH", "160000"))
HEALTH_TIMEOUT = int(os.environ.get("SELFEDIT_HEALTH_TIMEOUT", "60"))
FIND_MIN = 12
LOG_KEEP = 400
DIFF_KEEP = 60000

# --------------------------------------------------------------------------
# STATE
# --------------------------------------------------------------------------

_C = {}                 # context injected by the app (root, workspace, port...)
_LOCK = threading.RLock()
_WORKER = None
_STOP = threading.Event()


def configure(ctx):
    _C.clear()
    _C.update(ctx or {})
    for key, default in (("root", os.path.dirname(os.path.abspath(__file__))),
                         ("port", 5002),
                         ("python", sys.executable),
                         ("endpoint", "https://openrouter.ai/api/v1/chat/completions")):
        _C.setdefault(key, default)
    os.makedirs(_base(), exist_ok=True)
    os.makedirs(_runs(), exist_ok=True)


def _base():
    ws = _C.get("workspace") or os.path.join(_C["root"], "workspace")
    return os.path.join(ws, "selfedit")


def _runs():
    return os.path.join(_base(), "runs")


def _state_path():
    return os.path.join(_base(), "state.json")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _sha(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def _load():
    try:
        with open(_state_path(), "r", encoding="utf-8") as f:
            st = json.load(f)
        if isinstance(st, dict):
            return st
    except Exception:
        pass
    return {"run_id": None, "phase": "idle", "log": [], "history": [],
            "started": None, "updated": None, "ops": [], "files_changed": [],
            "diff": "", "validation": None, "error": None, "boots": 0}


def _save(st):
    os.makedirs(_base(), exist_ok=True)
    st["updated"] = _now()
    tmp = _state_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, indent=1)
    os.replace(tmp, _state_path())


def _log(st, tag, msg):
    line = "%s  %s" % (_now(), msg)
    st.setdefault("log", []).append(line)
    if len(st["log"]) > LOG_KEEP:
        del st["log"][:-LOG_KEEP]
    _save(st)
    fn = _C.get("ui_event")
    if callable(fn):
        try:
            fn(tag, "selfedit", msg)
        except Exception:
            pass


def _phase(st, phase, msg=None):
    st["phase"] = phase
    if msg:
        _log(st, "SELFEDIT", msg)
    else:
        _save(st)


# --------------------------------------------------------------------------
# FILE SCOPE + HASHING
# --------------------------------------------------------------------------

def _rel_path(rel):
    return os.path.join(_C["root"], rel)


def _scope_files():
    out = {}
    for rel in EDITABLE:
        p = _rel_path(rel)
        if os.path.isfile(p):
            out[rel] = p
    return out


def _read(rel):
    with open(_rel_path(rel), "r", encoding="utf-8", newline="") as f:
        return f.read()


def _write_atomic(rel, text, mode=None):
    p = _rel_path(rel)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    tmp = p + ".selfedit-tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    if mode is None:
        try:
            mode = os.stat(p).st_mode & 0o7777
        except Exception:
            mode = None
    if mode is not None:
        try:
            os.chmod(tmp, mode)
        except Exception:
            pass
    os.replace(tmp, p)


# --------------------------------------------------------------------------
# BACKUP / RESTORE
# --------------------------------------------------------------------------

def backup(run_id, rels=None):
    """Copy every editable file into the run's backup dir; return (dir, manifest)."""
    rels = rels or list(_scope_files())
    dest = os.path.join(_runs(), run_id, "backup")
    manifest = {}
    for rel in rels:
        src = _rel_path(rel)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        with open(src, "rb") as f:
            data = f.read()
        manifest[rel] = {"sha256": _sha(data), "size": len(data)}
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    return dest, manifest


def _marker(run_id, name):
    """Read a supervisor-written outcome marker for a run, if it exists."""
    p = os.path.join(_runs(), run_id or "", name)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f) or {"reason": "empty marker"}
    except Exception:
        return {"reason": "unreadable " + name}


def _write_marker(run_id, name, payload):
    d = os.path.join(_runs(), run_id or "")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1)


def _manifest(dest):
    try:
        with open(os.path.join(dest, "manifest.json"), "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def restore(dest, rels=None):
    """Put the backup back, verifying each sha256. Returns a report list."""
    man = _manifest(dest)
    rels = rels or list(man)
    report = []
    for rel in rels:
        src = os.path.join(dest, rel)
        if not os.path.isfile(src):
            report.append({"file": rel, "ok": False, "error": "backup missing"})
            continue
        with open(src, "rb") as f:
            data = f.read()
        want = (man.get(rel) or {}).get("sha256")
        if want and _sha(data) != want:
            report.append({"file": rel, "ok": False,
                           "error": "backup hash mismatch"})
            continue
        _write_atomic(rel, data.decode("utf-8", "replace"))
        with open(_rel_path(rel), "rb") as f:
            got = _sha(f.read())
        report.append({"file": rel, "ok": got == _sha(data),
                       "sha256": got[:12]})
    return report


def diff_run(dest, rels=None, limit=DIFF_KEEP):
    """Unified diff between the backup and the live files."""
    man = _manifest(dest)
    rels = rels or list(man)
    chunks = []
    for rel in rels:
        old_p = os.path.join(dest, rel)
        new_p = _rel_path(rel)
        if not os.path.isfile(old_p) or not os.path.isfile(new_p):
            continue
        try:
            with open(old_p, "r", encoding="utf-8", errors="replace") as f:
                old = f.readlines()
            with open(new_p, "r", encoding="utf-8", errors="replace") as f:
                new = f.readlines()
        except Exception as e:
            chunks.append("-- %s: diff failed: %s" % (rel, e))
            continue
        if old == new:
            continue
        chunks.append("".join(difflib.unified_diff(
            old, new, fromfile="a/" + rel, tofile="b/" + rel, n=3)))
    text = "\n".join(chunks).strip()
    if len(text) > limit:
        text = text[:limit] + "\n… diff truncated at %d chars" % limit
    return text


# --------------------------------------------------------------------------
# APPLY
# --------------------------------------------------------------------------

def _norm_rel(name):
    rel = str(name or "").strip().replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    return rel.lstrip("/")


def apply_ops(ops):
    """Stage ops in memory. Nothing is written until _commit()."""
    scope = _scope_files()
    staged = {}
    errs = []
    if not isinstance(ops, list) or not ops:
        return {"ok": False, "errors": ["no ops supplied"], "staged": {}, "files": []}
    total = 0
    for i, op in enumerate(ops, 1):
        if not isinstance(op, dict):
            errs.append("op %d: not an object" % i)
            continue
        rel = _norm_rel(op.get("file"))
        if rel not in scope:
            errs.append("op %d: '%s' is not an editable file (allowed: %s)"
                        % (i, rel or "?", ", ".join(sorted(scope))))
            continue
        find = op.get("find")
        rep = op.get("replace")
        if not isinstance(find, str) or not isinstance(rep, str):
            errs.append("op %d: 'find' and 'replace' must be strings" % i)
            continue
        if len(find) < FIND_MIN:
            errs.append("op %d: 'find' is %d chars — needs >=%d to be unique"
                        % (i, len(find), FIND_MIN))
            continue
        if find == rep:
            errs.append("op %d: 'find' equals 'replace' (no-op)" % i)
            continue
        text = staged.get(rel)
        if text is None:
            try:
                text = _read(rel)
            except Exception as e:
                errs.append("op %d: cannot read %s: %s" % (i, rel, e))
                continue
        n = text.count(find)
        if n == 0:
            errs.append("op %d (%s): 'find' not present — copy the exact bytes "
                        "from the excerpt" % (i, rel))
            continue
        if n > 1:
            errs.append("op %d (%s): 'find' occurs %d times — add surrounding "
                        "lines for uniqueness" % (i, rel, n))
            continue
        staged[rel] = text.replace(find, rep, 1)
        total += len(rep)
    if total > MAX_PATCH:
        errs.append("patch too large: %d chars > %d" % (total, MAX_PATCH))
    if errs:
        return {"ok": False, "errors": errs, "staged": {}, "files": []}
    return {"ok": True, "errors": [], "staged": staged, "files": sorted(staged)}


def _commit(staged):
    for rel, text in staged.items():
        _write_atomic(rel, text)
    return sorted(staged)


# --------------------------------------------------------------------------
# VALIDATE
# --------------------------------------------------------------------------

def _anchors(rel, baseline=None):
    want = ANCHORS.get(rel) or []
    base = baseline if baseline is not None else ""
    if not base:
        return []
    return [a for a in want if a in base]


def validate(rels, dest):
    """Checks that must pass before the harness is allowed to restart."""
    checks = []
    errors = []
    man = _manifest(dest)

    for rel in rels:
        p = _rel_path(rel)
        if not os.path.isfile(p):
            errors.append("%s is missing after the edit" % rel)
            checks.append({"check": "%s exists" % rel, "ok": False})
            continue
        try:
            text = _read(rel)
        except Exception as e:
            errors.append("%s unreadable: %s" % (rel, e))
            continue
        if not text.strip():
            errors.append("%s is empty" % rel)
            continue
        if rel.endswith(".py"):
            try:
                compile(text, rel, "exec")
                checks.append({"check": "%s compiles" % rel, "ok": True})
            except SyntaxError as e:
                errors.append("%s:%s syntax error: %s" % (rel, e.lineno, e.msg))
                checks.append({"check": "%s compiles" % rel, "ok": False})
                continue
        old = ""
        old_p = os.path.join(dest, rel)
        if os.path.isfile(old_p):
            try:
                with open(old_p, "r", encoding="utf-8", errors="replace") as f:
                    old = f.read()
            except Exception:
                old = ""
        for a in _anchors(rel, old):
            ok = a in text
            checks.append({"check": "%s keeps %r" % (rel, a[:34]), "ok": ok})
            if not ok:
                errors.append("%s lost required anchor: %s" % (rel, a[:60]))

        if old:
            shrink = len(text) / float(max(1, len(old)))
            ok = shrink >= 0.85
            checks.append({"check": "%s size sane (%.0f%%)" % (rel, shrink * 100),
                           "ok": ok})
            if not ok:
                errors.append("%s shrank to %.0f%% of its previous size"
                              % (rel, shrink * 100))

    # structural checks on the files that define the harness + its UI
    if "scriptai2.py" in rels:
        text = _read("scriptai2.py")
        old = ""
        old_p = os.path.join(dest, "scriptai2.py")
        if os.path.isfile(old_p):
            try:
                old = open(old_p, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                old = ""
        new_n = len(re.findall(r"@APP\.route\(", text))
        old_n = len(re.findall(r"@APP\.route\(", old)) if old else 0
        ok = new_n >= old_n
        checks.append({"check": "routes not removed (%d -> %d)" % (old_n, new_n),
                       "ok": ok})
        if not ok:
            errors.append("route count dropped %d -> %d" % (old_n, new_n))
        if "SELFEDIT.register(" in old and "SELFEDIT.register(" not in text:
            errors.append("the self-edit hook was removed from scriptai2.py")

    if "templates/index.html" in rels:
        text = _read("templates/index.html")
        tabs = set(re.findall(r'data-tab="([A-Za-z0-9_-]+)"', text))
        panels = set(re.findall(
            r'<section class="panel[^"]*"\s+id="([A-Za-z0-9_-]+)"', text))
        ok = tabs == panels and tabs
        checks.append({"check": "tab/panel pairs match (%d tabs)" % len(tabs),
                       "ok": bool(ok)})
        if not ok:
            errors.append("tabs without a panel: %s | panels without a tab: %s"
                          % (sorted(tabs - panels) or "none",
                             sorted(panels - tabs) or "none"))
        for a in ("</html>", "</body>", "function jpost("):
            ok = a in text
            checks.append({"check": "index.html keeps %r" % a, "ok": ok})
            if not ok:
                errors.append("templates/index.html lost %r" % a)

    return {"ok": not errors, "checks": checks, "errors": errors}


# --------------------------------------------------------------------------
# MODEL
# --------------------------------------------------------------------------

SYSTEM = """You modify a running Python/Flask security harness (APEX) on request.

Return ONE JSON object and nothing else:
{"summary": "one line, what you changed",
 "ops": [{"file": "scriptai2.py", "find": "<exact bytes copied from the file>",
          "replace": "<new bytes>", "why": "short reason"}],
 "restart": true}

Rules that are enforced mechanically — a violation is rejected and retried:
- Only these files may be edited: scriptai2.py, templates/index.html,
  apex_selfedit.py, apex_ops.py, apex_tools.py
- "find" must be an exact, VERBATIM copy of a contiguous block of the current
  file, at least 12 characters, and must occur EXACTLY ONCE. Copy it from the
  excerpts below; never retype it from memory, never paraphrase whitespace.
- Include 2-6 surrounding lines in "find" when a single line is not unique.
- Do not reindent or reformat code you are not changing.
- "replace" must be a drop-in substitute for "find" (same indentation level).
- Total replacement text across all ops must stay under %d characters.
- Never delete a route, a tab, a panel, the agent loop, or the __main__ block.
- templates/index.html is rendered by Jinja: do not introduce literal
  double-brace or brace-percent sequences (they would be parsed as template
  directives and break the page).
- "restart": true unless the change only touches files that are re-read on every
  request.
- If the request cannot be done with unique string replacements, return
  {"summary": "...", "ops": [], "restart": false} and say what is missing.
""" % MAX_PATCH


def _excerpts(rels):
    """Compact, exact view of the parts of the files a model needs to patch."""
    out = []
    for rel in rels:
        p = _rel_path(rel)
        if not os.path.isfile(p):
            continue
        try:
            text = _read(rel)
        except Exception:
            continue
        out.append("=== %s  (%d bytes, sha256 %s) ==="
                   % (rel, len(text.encode("utf-8", "replace")),
                      _sha(text.encode("utf-8", "replace"))[:12]))
        lines = text.splitlines()
        if rel.endswith(".py"):
            routes = []
            for i, ln in enumerate(lines):
                if ln.startswith("@APP.route("):
                    nxt = ""
                    for probe in lines[i + 1:i + 5]:
                        if probe.strip().startswith("def "):
                            nxt = probe.strip()
                            break
                    routes.append("  %5d  %s  ->  %s" % (i + 1, ln.strip(), nxt))
            out.append("ROUTE MAP:\n" + ("\n".join(routes) or "  (none)"))
            tail = lines[-18:]
            out.append("TAIL (lines %d-%d):\n%s"
                       % (max(1, len(lines) - 17), len(lines),
                          "\n".join("%5d| %s" % (len(lines) - len(tail) + i + 1, l)
                                    for i, l in enumerate(tail))))
        if rel.endswith(".html"):
            nav = []
            for ln in lines:
                if 'role="tab"' in ln or 'role="tablist"' in ln:
                    nav.append("  " + ln.strip())
            out.append("TAB BAR:\n" + ("\n".join(nav) or "  (none)"))
            panels = []
            for i, ln in enumerate(lines):
                m = re.search(r'<section class="panel[^"]*"\s+id="([A-Za-z0-9_-]+)"',
                              ln)
                if m:
                    panels.append("  %5d  panel id=%s" % (i + 1, m.group(1)))
            out.append("PANELS:\n" + ("\n".join(panels) or "  (none)"))
            disp = ["  %5d  %s" % (i + 1, ln.strip()) for i, ln in enumerate(lines)
                    if "dataset.tab ===" in ln]
            out.append("TAB DISPATCH:\n" + ("\n".join(disp) or "  (none)"))
            cls = sorted(set(re.findall(r"^\s*\.([a-z][a-z0-9-]{2,})\s*[,{ ]",
                                        text, re.M)))
            out.append("CSS CLASSES: " + (", ".join(cls[:90]) or "(none)"))
    return "\n\n".join(out)


def _messages(st):
    rels = list(_scope_files())
    parts = [
        "OPERATOR REQUEST:\n" + (st.get("prompt") or "(manual ops)"),
        "FILE INVENTORY:\n" + "\n".join(
            "  %-24s %8d bytes" % (r, len(_read(r).encode("utf-8", "replace")))
            for r in rels),
        "EXCERPTS (copy 'find' from here, verbatim):\n" + _excerpts(rels),
    ]
    hist = st.get("history") or []
    if hist:
        last = hist[-1]
        parts.append("YOUR PREVIOUS ATTEMPT WAS REJECTED — fix these and try again:\n"
                     + "\n".join("  - " + e for e in (last.get("errors") or [])[:12]))
        if last.get("summary"):
            parts.append("previous summary: " + str(last["summary"])[:400])
    parts.append("Return the JSON object now.")
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": "\n\n".join(parts)}]


def _ask(messages):
    key = (_C.get("key") or (lambda: ""))()
    if not key:
        return None, "OPENROUTER_API_KEY not set"
    model = (_C.get("model") or (lambda: ""))() or "deepseek/deepseek-chat-v3.1"
    chain = [model]
    for m in os.environ.get("APEX_SELFEDIT_MODELS", "").split(","):
        m = m.strip()
        if m and m not in chain:
            chain.append(m)
    headers = {"Authorization": "Bearer " + key,
               "HTTP-Referer": "http://localhost:%s" % _C.get("port", 5002),
               "X-Title": "APEX Self-Edit", "Content-Type": "application/json"}
    last = "no attempt made"
    for m in chain:
        try:
            r = requests.post(_C["endpoint"], headers=headers, json={
                "model": m, "messages": messages, "temperature": 0.2,
                "stream": False, "max_tokens": 4000,
            }, timeout=(30, 300))
        except requests.RequestException as e:
            last = "connection error: %s" % e
            continue
        if r.status_code == 200:
            try:
                body = r.json()
                return body["choices"][0]["message"]["content"], None
            except Exception as e:
                last = "bad response shape: %s" % e
                continue
        body = (r.text or "")[:400]
        if r.status_code == 402:
            return None, ("model credits exhausted (HTTP 402): %s — add credits, "
                          "or drive the loop with explicit ops" % body)
        last = "HTTP %s: %s" % (r.status_code, body)
        if r.status_code in (401, 403, 402):
            break
    return None, last


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def parse_reply(text):
    if not text:
        return None, "empty model reply"
    raw = text.strip()
    m = _FENCE.search(raw)
    if m:
        raw = m.group(1).strip()
    if not raw.startswith("{"):
        i, j = raw.find("{"), raw.rfind("}")
        if i < 0 or j <= i:
            return None, "reply contained no JSON object"
        raw = raw[i:j + 1]
    try:
        obj = json.loads(raw)
    except Exception as e:
        return None, "JSON parse failed: %s" % e
    if not isinstance(obj, dict):
        return None, "JSON root is not an object"
    ops = obj.get("ops")
    if ops is None:
        ops = []
    if not isinstance(ops, list):
        return None, "'ops' is not a list"
    obj["ops"] = ops
    return obj, None


# --------------------------------------------------------------------------
# RESTART
# --------------------------------------------------------------------------

def _restart(st):
    """Hand the restart to the supervisor, then exit so the port is released."""
    sup = os.path.join(_C["root"], "apex_selfedit_supervisor.py")
    if not os.path.isfile(sup):
        st["error"] = "supervisor missing: %s" % sup
        _phase(st, "failed", "cannot restart — supervisor file not found")
        return {"ok": False, "error": st["error"]}
    rundir = os.path.join(_runs(), st["run_id"])
    os.makedirs(rundir, exist_ok=True)
    outp = os.path.join(rundir, "supervisor.out")
    env = dict(os.environ)
    env["PORT"] = str(_C.get("port", 5002))
    cmd = [_C.get("python") or sys.executable, sup,
           "--run", st["run_id"],
           "--wait-pid", str(os.getpid()),
           "--root", _C["root"],
           "--port", str(_C.get("port", 5002)),
           "--backup", st["backup_dir"],
           "--timeout", str(HEALTH_TIMEOUT)]
    st["phase"] = "restarting"
    st["awaiting_boot"] = True
    _log(st, "SELFEDIT", "restart handed to supervisor: %s"
         % " ".join(cmd[-9:]))
    try:
        with open(outp, "ab") as f:
            subprocess.Popen(cmd, cwd=_C["root"], stdout=f,
                             stderr=subprocess.STDOUT, env=env,
                             start_new_session=True, close_fds=True)
    except Exception as e:
        st["error"] = "supervisor launch failed: %s" % e
        _phase(st, "failed", "supervisor launch failed: %s" % e)
        return {"ok": False, "error": st["error"]}
    _save(st)
    threading.Timer(1.6, lambda: os._exit(0)).start()
    return {"ok": True, "restarting": True}


# --------------------------------------------------------------------------
# LOOP
# --------------------------------------------------------------------------

def _worker(st):
    global _WORKER
    dest = st["backup_dir"]
    rels = list(_scope_files())
    manual = st.pop("manual_ops", None)
    try:
        for it in range(1, int(st.get("max_iters") or MAX_ITERS) + 1):
            if _STOP.is_set():
                _phase(st, "stopped", "stopped by operator before iteration %d" % it)
                return
            st["iteration"] = it
            _phase(st, "planning", "iteration %d/%d — planning the change"
                   % (it, st.get("max_iters")))
            if manual:
                obj = {"summary": st.get("summary") or "manual ops",
                       "ops": manual, "restart": bool(st.get("restart"))}
                manual = None
                err = None
            else:
                text, err = _ask(_messages(st))
                if err:
                    st["error"] = err
                    st.setdefault("history", []).append(
                        {"iteration": it, "ok": False, "errors": [err]})
                    _phase(st, "failed", "model unavailable: %s" % err)
                    return
                obj, perr = parse_reply(text)
                if perr:
                    st.setdefault("history", []).append(
                        {"iteration": it, "ok": False, "errors": [perr]})
                    _log(st, "WARN", "iteration %d rejected: %s" % (it, perr))
                    continue
            st["summary"] = str(obj.get("summary") or "")[:400]
            ops = obj.get("ops") or []
            if not ops:
                msg = ("model returned no ops — nothing it can safely patch: "
                       + (st["summary"] or "no reason given"))
                st.setdefault("history", []).append(
                    {"iteration": it, "ok": False, "errors": [msg]})
                st["error"] = msg
                _phase(st, "failed", msg)
                return
            _phase(st, "applying", "iteration %d — applying %d op(s)"
                   % (it, len(ops)))
            res = apply_ops(ops)
            if not res["ok"]:
                st.setdefault("history", []).append(
                    {"iteration": it, "ok": False, "errors": res["errors"],
                     "summary": st.get("summary")})
                _log(st, "WARN", "iteration %d ops rejected: %s"
                     % (it, "; ".join(res["errors"])[:300]))
                if st.get("manual"):
                    # Operator-supplied ops: no point asking the model to
                    # reinterpret them, so report what was wrong and stop.
                    st["error"] = "; ".join(res["errors"])[:400]
                    _phase(st, "failed", "the supplied ops were rejected")
                    return
                continue
            _commit(res["staged"])
            st["files_changed"] = res["files"]
            st["ops"] = [{"file": _norm_rel(o.get("file")), "why": o.get("why", ""),
                          "find": (o.get("find") or "")[:400],
                          "replace": (o.get("replace") or "")[:800]}
                         for o in ops if isinstance(o, dict)]
            st["diff"] = diff_run(dest, res["files"])
            with open(os.path.join(_runs(), st["run_id"], "final.diff"),
                      "w", encoding="utf-8") as f:
                f.write(st["diff"])
            _phase(st, "validating", "iteration %d — %d file(s) written, validating"
                   % (it, len(res["files"])))
            val = validate(rels, dest)
            st["validation"] = val
            if not val["ok"]:
                rep = restore(dest, rels)
                st.setdefault("history", []).append(
                    {"iteration": it, "ok": False, "errors": val["errors"],
                     "summary": st.get("summary"), "restored": rep})
                st["files_changed"] = []
                st["diff"] = ""
                _log(st, "WARN", "iteration %d failed validation and was rolled "
                                 "back: %s" % (it, "; ".join(val["errors"])[:300]))
                if st.get("manual"):
                    st["error"] = "; ".join(val["errors"])[:400]
                    _phase(st, "failed", "the supplied ops failed validation")
                    return
                continue
            st.setdefault("history", []).append(
                {"iteration": it, "ok": True, "errors": [],
                 "summary": st.get("summary"), "files": res["files"]})
            _log(st, "SELFEDIT", "iteration %d validated: %s"
                 % (it, ", ".join(res["files"])))
            st.pop("manual_ops", None)
            if obj.get("restart") or st.get("restart"):
                _restart(st)
                return
            _phase(st, "done", "change applied without restart")
            return
        st["error"] = "no valid change after %d iteration(s)" % st.get("max_iters")
        rep = restore(dest, rels)
        st["files_changed"] = []
        st["validation"] = {"ok": False, "errors": [st["error"]], "checks": []}
        _phase(st, "failed", "%s — restored: %s"
               % (st["error"], ", ".join(r["file"] for r in rep)))
    except Exception as e:                              # pragma: no cover
        st["error"] = "%s: %s" % (type(e).__name__, e)
        try:
            restore(dest, rels)
        except Exception:
            pass
        _phase(st, "failed", "loop crashed and was rolled back: %s" % st["error"])
    finally:
        _WORKER = None


# --------------------------------------------------------------------------
# PUBLIC API
# --------------------------------------------------------------------------

def _recent_runs(limit=8):
    """Newest-first run directories, with the outcome each marker implies."""
    base = _runs()
    rows = []
    try:
        names = os.listdir(base)
    except Exception:
        return rows
    for n in names:
        d = os.path.join(base, n)
        if not os.path.isdir(d):
            continue
        have = lambda f: os.path.isfile(os.path.join(d, f))
        phase = ("rolled_back" if have("rollback.json") else
                 "done" if have("restart_ok.json") else
                 "applied" if have("final.diff") else "unknown")
        try:
            ts = os.path.getmtime(d)
        except Exception:
            ts = 0
        rows.append({
            "run": n, "phase": phase, "at": ts,
            "files": [f for f in _scope_files() if have(os.path.join("backup", f))],
        })
    rows.sort(key=lambda r: r["at"], reverse=True)
    for r in rows:
        r["when"] = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["at"]))
                      if r["at"] else "")
        r.pop("at", None)
    return rows[:limit]


def status():
    st = _load()
    sup = {}
    rid = st.get("run_id")
    if rid:
        for name in ("supervisor.json", "rollback.json", "restart_ok.json"):
            p = os.path.join(_runs(), rid, name)
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        sup[name[:-5]] = json.load(f)
                except Exception:
                    pass
    return {
        "ok": True,
        "run_id": st.get("run_id"),
        "phase": st.get("phase") or "idle",
        "running": bool(_WORKER and _WORKER.is_alive()),
        "prompt": st.get("prompt") or "",
        "summary": st.get("summary") or "",
        "iteration": st.get("iteration") or 0,
        "max_iters": st.get("max_iters") or MAX_ITERS,
        "restart": bool(st.get("restart")),
        "files_changed": st.get("files_changed") or [],
        "backup_dir": st.get("backup_dir") or "",
        "ops": st.get("ops") or [],
        "validation": st.get("validation"),
        "history": st.get("history") or [],
        "diff": st.get("diff") or "",
        "log": st.get("log") or [],
        "error": st.get("error"),
        "started": st.get("started"),
        "updated": st.get("updated"),
        "supervisor": sup,
        "runs": _recent_runs(),
        "editable": sorted(_scope_files()),
        "limits": {"max_iters": MAX_ITERS, "max_patch": MAX_PATCH,
                   "health_timeout": HEALTH_TIMEOUT},
    }


def start(payload):
    global _WORKER
    with _LOCK:
        if _WORKER is not None and _WORKER.is_alive():
            return {"ok": False, "error": "a self-edit run is already active"}
        payload = payload or {}
        prompt = str(payload.get("prompt") or "").strip()
        ops = payload.get("ops")
        if not prompt and not ops:
            return {"ok": False, "error": "a prompt describing the change is required"}
        mission = {}
        fn = _C.get("mission")
        if callable(fn):
            try:
                mission = fn() or {}
            except Exception:
                mission = {}
        if mission.get("status") == "running" and not payload.get("force"):
            return {"ok": False, "error": "a mission is running — stop it first or "
                                          "send force=true (a restart would kill it)"}
        try:
            max_iters = int(payload.get("max_iters") or MAX_ITERS)
        except Exception:
            max_iters = MAX_ITERS
        max_iters = max(1, min(max_iters, 6))
        run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        dest, man = backup(run_id)
        st = _load()
        st.update({
            "run_id": run_id, "phase": "planning", "prompt": prompt,
            "started": _now(), "iteration": 0, "max_iters": max_iters,
            "restart": bool(payload.get("restart", True)),
            "files_changed": [], "backup_dir": dest, "ops": [], "diff": "",
            "validation": None, "error": None, "history": [], "log": [],
            "summary": str(payload.get("summary") or ""),
            "boots": 0, "awaiting_boot": False,
            "manifest": man,
        })
        if ops:
            st["manual_ops"] = ops
            st["manual"] = True
        os.makedirs(os.path.join(_runs(), run_id), exist_ok=True)
        _save(st)
        _log(st, "SELFEDIT", "run %s started — %d file(s) backed up to %s"
             % (run_id, len(man), dest))
        _STOP.clear()
        _WORKER = threading.Thread(target=_worker, args=(st,), daemon=True)
        _WORKER.start()
        return {"ok": True, "run_id": run_id, "phase": "planning"}


def stop():
    _STOP.set()
    st = _load()
    if _WORKER is not None and _WORKER.is_alive():
        _log(st, "WARN", "stop requested — the loop stops after the current step")
        return {"ok": True, "stopping": True}
    return {"ok": True, "stopping": False, "phase": st.get("phase")}


def rollback(run_id=None):
    st = _load()
    rid = _norm_rel(run_id) if run_id else st.get("run_id")
    if st.get("phase") == "restarting":
        return {"ok": False, "error": "the harness is restarting — wait for it to "
                                      "come back before rolling back"}
    # An explicit run means "restore the baseline that run started from", which is
    # not necessarily the newest backup on disk.
    dest = os.path.join(_runs(), rid or "", "backup")
    if not os.path.isdir(dest):
        dest = st.get("backup_dir") or ""
    if not os.path.isdir(dest):
        return {"ok": False, "error": "no backup found for run %s" % rid}
    rep = restore(dest)
    st["files_changed"] = []
    st["diff"] = ""
    st["error"] = None
    _phase(st, "rolled_back", "operator rolled back run %s: %s"
           % (rid, ", ".join(r["file"] for r in rep)))
    return {"ok": all(r["ok"] for r in rep), "restored": rep,
            "needs_restart": True}


def on_boot():
    """Called in __main__ before the server binds: close out a restart."""
    try:
        st = _load()
    except Exception:
        return {"ok": False, "error": "state unreadable"}
    if not st.get("awaiting_boot"):
        return {"ok": True, "boot": "no pending self-edit"}
    st["awaiting_boot"] = False
    st["boots"] = int(st.get("boots") or 0) + 1
    dest = st.get("backup_dir") or ""
    rels = list(_scope_files())
    try:
        # A rollback marker is authoritative: the supervisor already decided the
        # new code could not boot, and "the harness is up" must not be reported
        # as a successful change.
        rb = (_marker(st.get("run_id"), "rollback.pending.json")
              or _marker(st.get("run_id"), "rollback.json"))
        if rb:
            rep = restore(dest, rels)
            st["files_changed"] = []
            st["diff"] = ""
            st["error"] = ("the restart failed and the change was rolled back: %s"
                           % (rb.get("reason") or "unknown"))
            _phase(st, "rolled_back", "rolled back after a failed restart (%s); "
                                      "backups restored: %s"
                   % (rb.get("reason") or "unknown",
                      ", ".join(r["file"] for r in rep)))
            return {"ok": False, "boot": "rolled back"}
        if st.get("phase") == "restarting":
            st["phase"] = "validating"
        val = validate(rels, dest)
        st["validation"] = val
        if val["ok"]:
            _phase(st, "done", "restart verified — harness is serving the new "
                               "code (boot %d)" % st["boots"])
            return {"ok": True, "boot": "verified"}
        rep = restore(dest, rels)
        st["files_changed"] = []
        st["error"] = "post-restart validation failed: %s" % "; ".join(val["errors"])[:300]
        _log(st, "WARN", "post-restart validation failed, backups restored: %s"
             % ", ".join(r["file"] for r in rep))
        if st["boots"] <= 1:
            # Tell the supervisor (and the next boot) that this relaunch is a
            # recovery, not a successful self-edit.
            try:
                _write_marker(st.get("run_id"), "rollback.pending.json",
                              {"reason": st["error"], "at": _now()})
            except Exception:
                pass
            st["phase"] = "rolled_back"
            st["awaiting_boot"] = True
            out = _restart(st)
            if out.get("ok"):
                return {"ok": True, "boot": "rolled back, restarting clean"}
        _phase(st, "rolled_back", "rolled back to the previous code; restart the "
                                  "harness to unload the rejected version")
        return {"ok": False, "boot": "rolled back"}
    except Exception as e:                              # pragma: no cover
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}


# --------------------------------------------------------------------------
# ROUTES
# --------------------------------------------------------------------------

def register(APP, ctx):
    """Mount /selfedit* on the app. ctx is injected to avoid a circular import."""
    configure(ctx or {})
    from flask import jsonify, request

    def _state():
        return jsonify(status())

    def _start():
        return jsonify(start(request.get_json(silent=True) or {}))

    def _stop():
        return jsonify(stop())

    def _rollback():
        data = request.get_json(silent=True) or {}
        return jsonify(rollback(data.get("run")))

    def _diff():
        run = request.args.get("run") or ""
        p = os.path.join(_runs(), _norm_rel(run), "final.diff")
        if not os.path.isfile(p):
            return jsonify({"ok": False, "error": "no diff stored for that run",
                            "diff": ""})
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return jsonify({"ok": True, "run": run, "diff": f.read()})

    APP.add_url_rule("/selfedit", "selfedit_state", _state, methods=["GET"])
    APP.add_url_rule("/selfedit/start", "selfedit_start", _start, methods=["POST"])
    APP.add_url_rule("/selfedit/stop", "selfedit_stop", _stop, methods=["POST"])
    APP.add_url_rule("/selfedit/rollback", "selfedit_rollback", _rollback,
                     methods=["POST"])
    APP.add_url_rule("/selfedit/diff", "selfedit_diff", _diff, methods=["GET"])
    return {"ok": True, "routes": ["/selfedit", "/selfedit/start",
                                   "/selfedit/stop", "/selfedit/rollback",
                                   "/selfedit/diff"]}
