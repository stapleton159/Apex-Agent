#!/usr/bin/env python3
"""Unit checks for apex_selfedit before it is wired into the harness.

Runs against a throwaway copy of the real sources, never the live files.
"""
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import apex_selfedit as SE

FAILS = []
PASS = [0]
LIVE_BEFORE = [""]


def check(name, cond, detail=""):
    if cond:
        PASS[0] += 1
        print("PASS  %s" % name)
    else:
        FAILS.append(name + ((" :: " + detail) if detail else ""))
        print("FAIL  %s  %s" % (name, detail))


def md5(p):
    return hashlib.md5(open(p, "rb").read()).hexdigest()


def build_sandbox():
    d = tempfile.mkdtemp(prefix="selfedit_")
    os.makedirs(os.path.join(d, "templates"), exist_ok=True)
    for rel in ("scriptai2.py", "templates/index.html", "apex_ops.py",
                "apex_tools.py", "apex_selfedit.py",
                "apex_selfedit_supervisor.py"):
        src = os.path.join(ROOT, rel)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(d, rel))
    return d


def main():
    d = build_sandbox()
    events = []
    SE.configure({"root": d, "workspace": os.path.join(d, "ws"), "port": 5599,
                  "python": sys.executable,
                  "ui_event": lambda t, n, x: events.append((t, n, x)),
                  "mission": lambda: {"status": "idle"},
                  "model": lambda: "test/model", "key": lambda: ""})

    live_md5 = os.path.join(ROOT, "scriptai2.py")
    LIVE_BEFORE[0] = md5(live_md5)
    before = md5(os.path.join(d, "scriptai2.py"))

    # 1. scope: supervisor must never be editable
    scope = SE._scope_files()
    check("scope includes scriptai2.py", "scriptai2.py" in scope)
    check("scope excludes the supervisor",
          "apex_selfedit_supervisor.py" not in scope)
    check("scope excludes templates of nothing else",
          set(scope) <= set(SE.EDITABLE))

    # 2. backup + manifest hashes
    dest, man = SE.backup("run1")
    check("backup captured every editable file", set(man) == set(scope),
          str(sorted(set(scope) - set(man))))
    check("manifest hashes match live files",
          all(man[r]["sha256"] == hashlib.sha256(
              open(os.path.join(d, r), "rb").read()).hexdigest() for r in man))
    check("backup manifest written",
          os.path.isfile(os.path.join(dest, "manifest.json")))

    # 3. apply a real, unique edit
    anchor = 'if __name__ == "__main__":'
    res = SE.apply_ops([{"file": "scriptai2.py",
                         "find": anchor,
                         "replace": "# selfedit test marker\n" + anchor,
                         "why": "test"}])
    check("valid op applies", res["ok"], str(res["errors"]))
    check("op stages exactly one file", res["files"] == ["scriptai2.py"],
          str(res["files"]))
    check("staging does not touch disk",
          md5(os.path.join(d, "scriptai2.py")) == before)
    SE._commit(res["staged"])
    check("commit writes the file",
          md5(os.path.join(d, "scriptai2.py")) != before)
    text = SE._read("scriptai2.py")
    check("marker present once", text.count("# selfedit test marker") == 1)
    check("__main__ block still present once", text.count(anchor) == 1)

    # 4. validation passes on a healthy edit
    val = SE.validate(list(SE._scope_files()), dest)
    check("validate ok after sane edit", val["ok"], str(val["errors"]))
    check("validate reports compile check",
          any("compiles" in c["check"] for c in val["checks"]))
    check("validate reports tab/panel pairing",
          any("tab/panel" in c["check"] for c in val["checks"]))

    # 5. diff sees the change
    dt = SE.diff_run(dest)
    check("diff mentions the marker", "+# selfedit test marker" in dt,
          dt[:200])

    # 6. restore is byte exact
    rep = SE.restore(dest)
    check("restore succeeded", all(r["ok"] for r in rep), json.dumps(rep)[:300])
    check("restore is byte exact",
          md5(os.path.join(d, "scriptai2.py")) == before)

    # 7. rejected ops
    bad = [
        ("absent find", [{"file": "scriptai2.py", "find": "zzz-not-in-file-zzz",
                          "replace": "x"}]),
        ("short find", [{"file": "scriptai2.py", "find": "import os",
                         "replace": "import os  # x"}]),
        ("non editable file", [{"file": "apex_selfedit_supervisor.py",
                                "find": "import argparse", "replace": "x"}]),
        ("path traversal", [{"file": "../etc/passwd", "find": "root:x:0:0",
                             "replace": "x"}]),
        ("no-op", [{"file": "scriptai2.py", "find": anchor, "replace": anchor}]),
        ("empty ops", []),
    ]
    for name, ops in bad:
        r = SE.apply_ops(ops)
        check("rejects %s" % name, not r["ok"], str(r.get("errors"))[:120])

    # ambiguous find must be refused: "import os" style duplicates
    amb = "def _load_env_file():"
    r = SE.apply_ops([{"file": "scriptai2.py", "find": "return None",
                       "replace": "return 'x'"}])
    check("rejects ambiguous find", not r["ok"], str(r.get("errors")))

    # 8. syntax error must fail validation and roll back
    txt = SE._read("scriptai2.py")
    SE._write_atomic("scriptai2.py", txt + "\ndef broken(:\n")
    v = SE.validate(["scriptai2.py"], dest)
    check("validate catches syntax error", not v["ok"],
          str(v.get("errors"))[:160])
    SE.restore(dest)

    # 9. deleting a required anchor must fail
    txt = SE._read("scriptai2.py")
    SE._write_atomic("scriptai2.py", txt.replace("def agent_loop(", "def gone("))
    v = SE.validate(["scriptai2.py"], dest)
    check("validate catches removed anchor", not v["ok"],
          str(v.get("errors"))[:160])
    SE.restore(dest)

    # 10. index.html tab/panel mismatch must fail
    html = SE._read("templates/index.html")
    SE._write_atomic("templates/index.html",
                     html.replace('<button role="tab" data-tab="lab"',
                                  '<button role="tab" data-tab="labXX"', 1))
    v = SE.validate(["templates/index.html"], dest)
    check("validate catches orphan tab", not v["ok"],
          str(v.get("errors"))[:200])
    SE.restore(dest)

    # 11. truncated html must fail
    html = SE._read("templates/index.html")
    SE._write_atomic("templates/index.html", html[:len(html) // 2])
    v = SE.validate(["templates/index.html"], dest)
    check("validate catches truncated html", not v["ok"],
          str(v.get("errors"))[:160])
    SE.restore(dest)

    # 12. multi-op composition on one file
    r = SE.apply_ops([
        {"file": "scriptai2.py", "find": anchor,
         "replace": "# SELFEDIT_MARK_ONE\n" + anchor},
        {"file": "scriptai2.py", "find": "# SELFEDIT_MARK_ONE\n" + anchor,
         "replace": "# SELFEDIT_MARK_ONE\n# SELFEDIT_MARK_TWO\n" + anchor},
    ])
    check("multiple ops compose on one file", r["ok"], str(r["errors"]))
    staged_txt = r.get("staged", {}).get("scriptai2.py", "")
    check("composition result has both markers",
          staged_txt.count("# SELFEDIT_MARK_ONE") == 1 and
          staged_txt.count("# SELFEDIT_MARK_TWO") == 1,
          "one=%d two=%d" % (staged_txt.count("# SELFEDIT_MARK_ONE"),
                             staged_txt.count("# SELFEDIT_MARK_TWO")))

    # 13. patch size cap
    big = "x" * (SE.MAX_PATCH + 10)
    r = SE.apply_ops([{"file": "scriptai2.py", "find": anchor,
                       "replace": big + anchor}])
    check("rejects oversized patch", not r["ok"], str(r["errors"])[:120])

    # 14. reply parsing
    obj, err = SE.parse_reply('```json\n{"summary":"s","ops":[],"restart":true}\n```')
    check("parses fenced json", err is None and obj["summary"] == "s", str(err))
    obj, err = SE.parse_reply('prose before {"summary":"s2","ops":[],"restart":false} after')
    check("parses json inside prose", err is None and obj["summary"] == "s2", str(err))
    obj, err = SE.parse_reply('{"summary":"s3"}')
    check("missing ops becomes empty list", err is None and obj["ops"] == [], str(err))
    obj, err = SE.parse_reply("no json here")
    check("rejects non-json", obj is None and err, str(err))

    # 15. prompts carry the file map and never leak the api key
    st = {"prompt": "add a tab that lists requests", "history": []}
    msgs = SE._messages(st)
    check("prompt includes route map", "ROUTE MAP" in msgs[1]["content"])
    check("prompt includes tab bar", "TAB BAR" in msgs[1]["content"])
    check("prompt includes panels", "PANELS" in msgs[1]["content"])
    check("prompt states the JSON schema", '"ops"' in msgs[0]["content"])
    check("prompt mentions the Jinja restriction",
          "Jinja" in msgs[0]["content"])

    # 16. status shape is what the UI expects
    s = SE.status()
    for k in ("ok", "phase", "run_id", "log", "history", "ops", "validation",
              "diff", "editable", "limits"):
        check("status has %s" % k, k in s, str(sorted(s)))

    # 17. start refuses unknown payloads / running mission
    SE.configure({"root": d, "workspace": os.path.join(d, "ws"), "port": 5599,
                  "python": sys.executable,
                  "ui_event": lambda t, n, x: None,
                  "mission": lambda: {"status": "running"},
                  "model": lambda: "test/model", "key": lambda: ""})
    r = SE.start({"prompt": ""})
    check("start requires a prompt", not r["ok"], str(r))
    r = SE.start({"prompt": "add something"})
    check("start refuses while a mission runs", not r["ok"], str(r))

    # 18. live files were never touched by the test
    # The suite must never write to the real sources; compare against the hash
    # taken when the suite started instead of a pinned literal.
    check("live scriptai2.py untouched by the suite",
          md5(live_md5) == LIVE_BEFORE[0], md5(live_md5))

    print("\n%d checks passed, %d failed" % (PASS[0], len(FAILS)))
    for f in FAILS:
        print("  FAILED: " + f)
    shutil.rmtree(d, ignore_errors=True)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
