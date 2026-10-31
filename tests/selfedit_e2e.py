#!/usr/bin/env python3
"""End-to-end test of the self-edit loop on a throwaway copy of the app.

Runs the real harness (own port, own workspace) out of a sandbox directory and
drives two self-edits:

  A. a valid change -> patch, validate, restart, /health on a new pid, phase done
  B. a change that compiles but cannot boot -> supervisor rollback, files
     restored, phase rolled_back

The live sources in the home directory are never touched.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import requests

SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOX = os.path.join(tempfile.gettempdir(), "selfedit_e2e")
PORT = 5003
BASE = "http://127.0.0.1:%d" % PORT

FAILS = []
OKS = [0]


def check(name, cond, detail=""):
    if cond:
        OKS[0] += 1
        print("PASS  %s" % name)
    else:
        FAILS.append("%s :: %s" % (name, detail))
        print("FAIL  %s  %s" % (name, detail))


def build():
    shutil.rmtree(BOX, ignore_errors=True)
    os.makedirs(os.path.join(BOX, "templates"), exist_ok=True)
    for fn in os.listdir(SRC):
        if fn.endswith(".py") and not fn.startswith("."):
            shutil.copy2(os.path.join(SRC, fn), os.path.join(BOX, fn))
    shutil.copy2(os.path.join(SRC, "templates/index.html"),
                 os.path.join(BOX, "templates/index.html"))


def start_app():
    env = dict(os.environ)
    env["PORT"] = str(PORT)
    env["APEX_WORKSPACE"] = os.path.join(BOX, "ws")
    env.pop("MODEL_NAME", None)
    log = open(os.path.join(BOX, "app.log"), "ab")
    p = subprocess.Popen([sys.executable, os.path.join(BOX, "scriptai2.py")],
                         cwd=BOX, stdout=log, stderr=subprocess.STDOUT,
                         env=env, start_new_session=True)
    return p


def health(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(BASE + "/health", timeout=3)
            if r.status_code == 200 and r.json().get("ok"):
                return r.json()
        except Exception:
            pass
        time.sleep(0.7)
    return None


def wait_pid_change(old_pid, timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        h = None
        try:
            h = requests.get(BASE + "/health", timeout=3).json()
        except Exception:
            pass
        if h and h.get("pid") != old_pid:
            return h
        time.sleep(1.0)
    return None


def selfedit():
    try:
        return requests.get(BASE + "/selfedit", timeout=5).json()
    except Exception:
        return {}


def run_change(name, ops, expect_phase, timeout=180):
    h0 = requests.get(BASE + "/health", timeout=5).json()
    old = h0["pid"]
    r = requests.post(BASE + "/selfedit/start", timeout=20,
                      json={"prompt": name, "ops": ops, "restart": True,
                            "max_iters": 1}).json()
    check("%s: start accepted" % name, r.get("ok"), str(r))
    run_id = r.get("run_id")
    h1 = wait_pid_change(old, timeout)
    check("%s: harness came back on a new pid" % name,
          bool(h1) and h1.get("pid") != old, str(h1))
    st = selfedit()
    check("%s: phase is %s" % (name, expect_phase),
          st.get("phase") == expect_phase,
          "phase=%s error=%s" % (st.get("phase"), st.get("error")))
    return run_id, st


def main():
    build()
    app = start_app()
    try:
        h = health()
        check("harness boots in the sandbox", bool(h), "no /health")
        if not h:
            return 1
        check("boot pid recorded", bool(h.get("pid")))
        check("self-edit subsystem reports ready",
              (h.get("selfedit") or {}).get("ok") is True, str(h.get("selfedit")))

        page = requests.get(BASE + "/", timeout=15)
        check("dashboard renders", page.status_code == 200 and "APEX" in page.text,
              "status=%s" % page.status_code)
        check("dashboard has the Self-Edit tab",
              'data-tab="selfedit"' in page.text and 'id="selfedit"' in page.text)
        check("dashboard has the self-edit controls",
              all(k in page.text for k in ("btnSeStart", "sePrompt", "seDiff")))

        # ---------------- A. a valid change ----------------
        ops = [{"file": "scriptai2.py",
                "find": 'if __name__ == "__main__":',
                "replace": '# SELFEDIT_E2E_MARKER = "applied"\n'
                           'if __name__ == "__main__":',
                "why": "e2e marker"}]
        run_id, st = run_change("valid change", ops, "done")
        live = open(os.path.join(BOX, "scriptai2.py"), encoding="utf-8").read()
        check("A: the new line is in the file",
              'SELFEDIT_E2E_MARKER = "applied"' in live)
        check("A: the run reports it changed scriptai2.py",
              st.get("files_changed") == ["scriptai2.py"],
              str(st.get("files_changed")))
        check("A: validation passed", (st.get("validation") or {}).get("ok") is True)
        check("A: a diff is stored against the backup",
              "SELFEDIT_E2E_MARKER" in (st.get("diff") or ""))
        okf = os.path.join(BOX, "ws", "selfedit", "runs", run_id or "", "restart_ok.json")
        # the supervisor writes this a moment after the relaunched app is serving
        for _ in range(40):
            if os.path.isfile(okf):
                break
            time.sleep(0.5)
        check("A: the supervisor recorded a clean restart", os.path.isfile(okf), okf)
        check("A: history shows an accepted iteration",
              any(x.get("ok") for x in (st.get("history") or [])),
              str(st.get("history"))[:200])

        # ---------------- B. a change that cannot boot ----------------
        ops_b = [{"file": "scriptai2.py",
                  "find": "import os\nimport re\nimport sys\n",
                  "replace": 'raise RuntimeError("selfedit e2e boot failure")\n'
                             "import os\nimport re\nimport sys\n",
                  "why": "e2e boot failure"}]
        run_b, st_b = run_change("unbootable change", ops_b, "rolled_back")
        live = open(os.path.join(BOX, "scriptai2.py"), encoding="utf-8").read()
        check("B: the bad line is gone", "selfedit e2e boot failure" not in live)
        check("B: the earlier good change survived the rollback",
              'SELFEDIT_E2E_MARKER = "applied"' in live)
        check("B: no files are reported as changed", st_b.get("files_changed") == [],
              str(st_b.get("files_changed")))
        rb = os.path.join(BOX, "ws", "selfedit", "runs", run_b or "", "rollback.json")
        # the supervisor writes this a moment after the relaunched app is serving
        for _ in range(40):
            if os.path.isfile(rb):
                break
            time.sleep(0.5)
        check("B: the supervisor recorded a rollback", os.path.isfile(rb), rb)
        if os.path.isfile(rb):
            data = json.load(open(rb, encoding="utf-8"))
            check("B: rollback says the harness recovered", data.get("recovered") is True,
                  str(data)[:300])
            check("B: rollback names the boot failure",
                  "selfedit e2e boot failure" in str(data.get("reason") or "") or
                  "exited" in str(data.get("reason") or ""),
                  str(data.get("reason"))[:200])
        check("B: the harness is still serving", bool(health(30)))

        # ---------------- C. operator rollback of a named run ------------
        # Roll back to the baseline run A started from, by id: the newest backup
        # on disk contains A's change, so an id-less rollback is the wrong tool.
        r = requests.post(BASE + "/selfedit/rollback", timeout=20,
                          json={"run": run_id}).json()
        check("C: rollback accepted", r.get("ok"), str(r))
        live = open(os.path.join(BOX, "scriptai2.py"), encoding="utf-8").read()
        check("C: operator rollback removed the e2e marker",
              "SELFEDIT_E2E_MARKER" not in live)
        bak_a = os.path.join(BOX, "ws", "selfedit", "runs", run_id or "",
                            "backup", "scriptai2.py")
        check("C: the file matches run A's own backup byte for byte",
              os.path.isfile(bak_a) and open(bak_a, "rb").read() ==
              open(os.path.join(BOX, "scriptai2.py"), "rb").read())
        check("C: operator rollback reports a restore for scriptai2.py",
              any(x.get("file") == "scriptai2.py" and x.get("ok")
                  for x in (r.get("restored") or [])), str(r)[:300])

        # ---------------- D. refusal paths ----------------
        r = requests.post(BASE + "/selfedit/start", timeout=10, json={}).json()
        check("D: start without a prompt is refused", r.get("ok") is False, str(r))
        r = requests.post(BASE + "/selfedit/start", timeout=10,
                          json={"prompt": "x", "ops": [
                              {"file": "apex_selfedit_supervisor.py",
                               "find": "import argparse", "replace": "import os"}]}).json()
        check("D: an op against the supervisor is accepted then rejected by the loop",
              r.get("ok") is True, str(r))
        for _ in range(40):
            st = selfedit()
            if st.get("phase") in ("failed", "rolled_back"):
                break
            time.sleep(0.5)
        check("D: the loop refused to edit the recovery path",
              st.get("phase") == "failed", "phase=%s" % st.get("phase"))
        check("D: the refusal names the non-editable file",
              "not an editable file" in (st.get("error") or ""),
              str(st.get("error"))[:250])
        check("D: no restart or rollback happened for the refused run",
              not os.path.isfile(os.path.join(
                  BOX, "ws", "selfedit", "runs", st.get("run_id") or "",
                  "rollback.json")))
        check("D: the supervisor file is unchanged",
              "import argparse" in open(
                  os.path.join(BOX, "apex_selfedit_supervisor.py"),
                  encoding="utf-8").read())
    finally:
        try:
            os.killpg(os.getpgid(app.pid), signal.SIGTERM)
        except Exception:
            pass
        time.sleep(1)
        # the supervisor may have relaunched the app; clear anything on our port
        subprocess.run("pkill -f 'selfedit_e2e/scriptai2[.]py' || true", shell=True)
        subprocess.run("pkill -f 'apex_selfedit_supervisor[.]py' || true", shell=True)

    print("\n%d checks passed, %d failed" % (OKS[0], len(FAILS)))
    for f in FAILS:
        print("  FAILED: " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
