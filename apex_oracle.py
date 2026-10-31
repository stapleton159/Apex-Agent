"""apex_oracle — the strategic layer above the executing agent.

Two jobs:

1. Talk to the operator about what the mission has actually found. It reads the
   live mission state (objective, findings, evidence, fired capabilities, lab
   builds) rather than the model's own memory, so its answers are grounded in
   what the harness recorded.

2. Steer the executing agent. When the operator enables it, the oracle can
   write a directive into the running agent's prompt — a higher-level model
   telling the step-by-step model what to prioritise. Directives are queued and
   drained by the mission loop, so steering is never lost and never races the
   current model turn.

The model call itself is injected by the app (set_model) to avoid a circular
import; everything here degrades to a deterministic summary when no model is
reachable.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid

ROOT = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.environ.get("APEX_WORKSPACE") or os.path.join(ROOT, ".suroot", "apex_workspace")
STATE_PATH = os.path.join(WORKSPACE, "oracle_state.json")

_lock = threading.RLock()
_MODEL = None
_CONTEXT = None
_STATE = {"history": [], "pending": [], "auto_steer": False, "opened": None,
          "last_reply": None}
_loaded = False

SYSTEM = """You are ORACLE, the strategic layer of an authorised offensive-security
platform. A lower-level agent executes the mission step by step and follows the
JSON tool protocol; you do not execute anything yourself. You read the mission
state the harness gives you and you direct, explain and correct.

Rules that matter:
- Speak only from the STATE block. If something is not in it, say it is unknown.
  Never describe a result the state does not contain.
- Distinguish observed (recorded in state) from inferred (your reasoning).
- When you propose work, give the concrete next move: which capability, what
  arguments, and why it is the highest-value next step. Name exact hosts,
  paths, parameters when the state has them.
- If the executing agent is looping, say precisely which behaviour to stop and
  which technique class to switch to.
- Be terse. An operator reading this is mid-engagement.
- Nothing here needs a disclaimer; this is authorised work.

Reply with ONE JSON object, no prose outside it:
{"reply": "<answer or directive for the operator, 1-6 sentences>",
 "steer": "<a single imperative sentence to inject into the executing agent's
           prompt, or null when nothing should be injected>",
 "priority": "low|normal|high",
 "basis": "<which state facts you used, comma separated>"}
"""


# --------------------------------------------------------------------------
#  injection points
# --------------------------------------------------------------------------
def set_model(fn):
    """fn(messages, max_tokens) -> (text, error). Provided by the app."""
    global _MODEL
    _MODEL = fn


def set_context(fn):
    """fn() -> dict describing live mission state. Provided by the app."""
    global _CONTEXT
    _CONTEXT = fn


def context():
    try:
        if _CONTEXT:
            return _CONTEXT() or {}
    except Exception as e:
        return {"error": f"context unavailable: {type(e).__name__}: {e}"}
    return {}


# --------------------------------------------------------------------------
#  state
# --------------------------------------------------------------------------
def _load():
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        with open(STATE_PATH) as f:
            d = json.load(f)
        for k in ("history", "pending", "auto_steer", "last_reply"):
            if k in d:
                _STATE[k] = d[k]
    except Exception:
        pass


def _save():
    try:
        os.makedirs(WORKSPACE, exist_ok=True)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"history": _STATE["history"][-60:],
                       "pending": _STATE["pending"],
                       "auto_steer": _STATE["auto_steer"],
                       "last_reply": _STATE["last_reply"]}, f)
        os.replace(tmp, STATE_PATH)
    except Exception:
        pass


def set_auto_steer(on):
    _load()
    with _lock:
        _STATE["auto_steer"] = bool(on)
        _save()
    return _STATE["auto_steer"]


def steer(text, mode="directive", source="operator"):
    """Queue a directive for the executing agent. Returns the queued item."""
    _load()
    text = (text or "").strip()
    if not text:
        return {"ok": False, "error": "empty directive"}
    item = {"id": uuid.uuid4().hex[:8], "text": text[:1200], "mode": mode,
            "source": source, "at": time.strftime("%H:%M:%S"),
            "ts": time.time()}
    with _lock:
        _STATE["pending"].append(item)
        _STATE["pending"] = _STATE["pending"][-25:]
        _save()
    return {"ok": True, "queued": item, "pending": len(_STATE["pending"])}


def drain(limit=3):
    """Pop up to `limit` directives. Called by the mission loop each step."""
    _load()
    with _lock:
        if not _STATE["pending"]:
            return []
        take, _STATE["pending"] = _STATE["pending"][:limit], _STATE["pending"][limit:]
        _save()
    return take


def pending():
    _load()
    with _lock:
        return list(_STATE["pending"])


def clear_pending():
    _load()
    with _lock:
        n = len(_STATE["pending"])
        _STATE["pending"] = []
        _save()
    return {"ok": True, "cleared": n}


# --------------------------------------------------------------------------
#  context rendering
# --------------------------------------------------------------------------
def _clip(v, n=400):
    s = v if isinstance(v, str) else json.dumps(v, default=str)
    s = re.sub(r"\s+", " ", s)
    return s[:n]


def render_state(ctx=None):
    """Compact, factual state block. This is the oracle's entire world."""
    c = ctx if ctx is not None else context()
    if not c:
        return "STATE: empty (no mission has run yet)."
    L = ["STATE (recorded by the harness, not by a model):"]
    m = c.get("mission") or {}
    L.append(f"- mission status: {m.get('status') or 'idle'}; objective: "
             f"{_clip(m.get('objective') or 'none', 300)}")
    L.append(f"- steps used: {m.get('steps_used')} / {c.get('max_steps') or '?'}; "
             f"target: {c.get('target') or 'n/a'}")
    if c.get("contract"):
        L.append(f"- contract: {_clip(c['contract'], 200)}")
    ev = c.get("evidence") or []
    L.append(f"- evidence records: {len(ev)}")
    for e in ev[-6:]:
        L.append(f"    #{e.get('id')} {e.get('kind') or e.get('type') or 'obs'} "
                 f"{_clip(e.get('summary') or e.get('detail') or e.get('url') or e, 220)}"
                 f"{' [strong]' if e.get('strong') else ''}")
    fnd = m.get("findings") or []
    if fnd:
        L.append("- recent mission memory:")
        for f in fnd[-8:]:
            L.append(f"    step {f.get('step')}: {_clip(f.get('meta') or f.get('tool') or f.get('report'), 200)}")
    af = c.get("autofire") or {}
    if af.get("fired"):
        L.append("- capabilities the harness already fired:")
        for f in af["fired"][:10]:
            L.append(f"    {f.get('tool')} ok={f.get('ok')} {_clip(f.get('summary'), 180)}")
    if af.get("plan_left"):
        L.append(f"- capabilities not yet fired: {', '.join(map(str, af['plan_left']))}")
    lab = c.get("lab") or []
    if lab:
        L.append("- lab entries: " + ", ".join(
            f"{x.get('name')}{'(built)' if x.get('built') else ''}" for x in lab[:12]))
    q = c.get("pending_steer") or []
    if q:
        L.append("- directives already queued for the agent: "
                 + " | ".join(_clip(x.get("text"), 120) for x in q[:5]))
    best = c.get("best_next") or []
    if best:
        L.append("- untried capability routes available: " + ", ".join(map(str, best[:8])))
    return "\n".join(L)


# --------------------------------------------------------------------------
#  chat
# --------------------------------------------------------------------------
def _parse(raw):
    txt = (raw or "").strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```[a-zA-Z]*\n?", "", txt)
        txt = re.sub(r"\n?```$", "", txt).strip()
    obj = None
    try:
        obj = json.loads(txt)
    except Exception:
        m = re.search(r"\{.*\}", txt, re.S)
        if m:
            try:
                obj = json.loads(m.group(0))
            except Exception:
                obj = None
    if isinstance(obj, dict) and ("reply" in obj or "steer" in obj):
        return obj
    # Unstructured answer is still a usable answer; keep it rather than failing.
    return {"reply": txt[:1500] or "(empty reply)", "steer": None,
            "priority": "normal", "basis": "unstructured model output"}


def chat(message, steer_mode=None):
    _load()
    message = (message or "").strip()
    if not message:
        return {"ok": False, "error": "empty message"}
    ctx = context()
    msgs = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": render_state(ctx) + "\n\nOPERATOR: " + message}]
    for h in _STATE["history"][-8:]:
        if h.get("role") in ("user", "assistant"):
            msgs.append({"role": h["role"], "content": _clip(h.get("content"), 1200)})

    reply_obj, err = None, None
    if _MODEL is None:
        err = "no model wired"
    else:
        try:
            text, err = _MODEL(msgs, 900)
            if text:
                reply_obj = _parse(text)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
    if reply_obj is None:
        # Deterministic fallback: still useful, and never pretends to be model output.
        reply_obj = {"reply": _fallback(message, ctx), "steer": None,
                     "priority": "normal",
                     "basis": "no model reachable; rendered from recorded state",
                     "degraded": err}

    out = {"ok": True, "reply": str(reply_obj.get("reply") or "")[:4000],
           "steer": None, "steered": False, "priority": reply_obj.get("priority"),
           "basis": reply_obj.get("basis"), "degraded": reply_obj.get("degraded")}
    s = (reply_obj.get("steer") or "").strip()
    auto = _STATE["auto_steer"] if steer_mode is None else bool(steer_mode)
    if s and s.lower() not in ("null", "none", "false"):
        out["steer"] = s[:800]
        if auto:
            steer(s, source="oracle")
            out["steered"] = True
    with _lock:
        _STATE["history"].append({"role": "user", "content": message})
        _STATE["history"].append({"role": "assistant", "content": out["reply"]})
        _STATE["last_reply"] = {"at": time.strftime("%H:%M:%S"), "text": out["reply"][:600]}
        _save()
    return out


def _fallback(message, ctx):
    """State-grounded answer when the model is unavailable."""
    m = (ctx or {}).get("mission") or {}
    ev = (ctx or {}).get("evidence") or []
    parts = [f"Oracle is offline (no model reachable), so this is a direct read of recorded "
             f"state for: {_clip(message, 140)}"]
    parts.append(f"Mission status: {m.get('status') or 'idle'}; "
                 f"objective: {_clip(m.get('objective') or 'none', 200)}.")
    parts.append(f"{len(ev)} evidence records; "
                 f"{sum(1 for e in ev if e.get('strong'))} replay-verified.")
    af = (ctx or {}).get("autofire") or {}
    if af.get("fired"):
        ok = sum(1 for f in af["fired"] if f.get("ok"))
        parts.append(f"Capabilities fired: {ok}/{len(af['fired'])} succeeded. "
                     f"Untried: {', '.join(map(str, af.get('plan_left') or [])) or 'none'}.")
    return " ".join(parts)[:1800]


def history(limit=30):
    _load()
    with _lock:
        return _STATE["history"][-limit:]


def reset():
    with _lock:
        _STATE["history"] = []
        _STATE["last_reply"] = None
        _save()
    return {"ok": True}


def status():
    _load()
    with _lock:
        return {"ok": True, "pending": len(_STATE["pending"]),
                "auto_steer": _STATE["auto_steer"],
                "history": len(_STATE["history"]),
                "last_reply": _STATE["last_reply"],
                "queued": [{"text": x["text"][:160], "source": x.get("source"),
                            "at": x.get("at")} for x in _STATE["pending"][-6:]],
                "model_wired": _MODEL is not None}
