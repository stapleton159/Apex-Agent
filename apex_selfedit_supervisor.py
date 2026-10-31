#!/usr/bin/env python3
"""apex_selfedit_supervisor — restarts the harness after a self-edit.

The process that rewrote its own source cannot honestly report whether it came
back up: once it exits, nothing it wrote afterwards is trustworthy. So the
self-edit engine spawns this supervisor in a new session, then exits. The
supervisor owns the restart from that point:

  wait for the old pid to die  ->  launch scriptai2.py  ->  poll /health
     health ok        -> record restart_ok.json and exit 0
     health failed    -> kill the child, restore the sha256-verified backup,
                         relaunch once, and record rollback.json

It only ever writes inside the run directory it was given, so it never races the
application for state.json.
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def log(path, msg):
    line = "%s  %s\n" % (now(), msg)
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    sys.stderr.write(line)
    sys.stderr.flush()


# Windows has no SIGKILL; os.kill(pid, SIGTERM) already maps to TerminateProcess.
_SIGKILL = getattr(signal, "SIGKILL", None) or signal.SIGTERM


def alive(pid):
    """Is `pid` still running? Portable, and never signals the target.

    On Windows os.kill(pid, 0) is TerminateProcess, not a probe — using it here
    would kill the harness the supervisor is supposed to be babysitting.
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
            h = k32.OpenProcess(0x1000, False, pid)   # QUERY_LIMITED_INFORMATION
            if not h:
                return False
            try:
                code = wintypes.DWORD()
                if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                    return True
                return code.value == 259               # STILL_ACTIVE
            finally:
                k32.CloseHandle(h)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    # Zombie check: /proc is Linux-only, elsewhere the kill(0) answer stands.
    try:
        with open("/proc/%d/stat" % pid, "r") as f:
            fields = f.read().split()
        if len(fields) > 2 and fields[2] == "Z":
            return False
    except Exception:
        pass
    return True


def wait_pid(pid, timeout, logpath):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if not alive(pid):
            log(logpath, "pid %d exited after %.1fs" % (pid, time.time() - t0))
            return True
        time.sleep(0.25)
    log(logpath, "pid %d still alive after %ss — killing it" % (pid, timeout))
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
    t1 = time.time()
    while time.time() - t1 < 8:
        if not alive(pid):
            return True
        time.sleep(0.25)
    try:
        os.kill(pid, _SIGKILL)
    except Exception:
        pass
    return not alive(pid)


def launch(root, python, port, logpath):
    env = dict(os.environ)
    env["PORT"] = str(port)
    env.setdefault("PYTHONUNBUFFERED", "1")
    with open(logpath, "ab") as f:
        p = subprocess.Popen([python, os.path.join(root, "scriptai2.py")],
                             cwd=root, stdout=f, stderr=subprocess.STDOUT,
                             env=env, start_new_session=True, close_fds=True)
    return p


def health(port, timeout, proc=None):
    url = "http://127.0.0.1:%d/health" % port
    t0 = time.time()
    last = "no response"
    while time.time() - t0 < timeout:
        if proc is not None and proc.poll() is not None:
            return None, "harness exited with code %s after %.1fs" % (
                proc.returncode, time.time() - t0)
        try:
            with urllib.request.urlopen(url, timeout=4) as r:
                body = r.read().decode("utf-8", "replace")
            try:
                data = json.loads(body)
            except Exception:
                data = {"raw": body[:400]}
            if isinstance(data, dict) and data.get("ok"):
                return data, None
            last = "health returned: %s" % body[:200]
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            last = str(e)
        time.sleep(1.0)
    return None, "no healthy /health after %ss (%s)" % (timeout, last)


def kill(proc, logpath):
    if proc is None or proc.poll() is not None:
        return
    log(logpath, "killing child pid %d" % proc.pid)
    sigs = [signal.SIGTERM]
    if _SIGKILL != signal.SIGTERM:
        sigs.append(_SIGKILL)
    for sig in sigs:
        try:
            # POSIX: kill the whole process group so shell children die too.
            # Windows: no process groups from setpgid — terminate the child.
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(proc.pid), sig)
            else:
                proc.send_signal(sig)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        for _ in range(16):
            if proc.poll() is not None:
                return
            time.sleep(0.25)


def read_manifest(dest):
    try:
        with open(os.path.join(dest, "manifest.json"), "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def restore(dest, root, logpath):
    man = read_manifest(dest)
    out = []
    for rel, meta in sorted(man.items()):
        src = os.path.join(dest, rel)
        dst = os.path.join(root, rel)
        if not os.path.isfile(src):
            out.append({"file": rel, "ok": False, "error": "backup missing"})
            continue
        if meta.get("sha256") and sha_file(src) != meta["sha256"]:
            out.append({"file": rel, "ok": False, "error": "backup hash mismatch"})
            continue
        try:
            os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
            tmp = dst + ".selfedit-restore"
            shutil.copy2(src, tmp)
            os.replace(tmp, dst)
            out.append({"file": rel, "ok": sha_file(dst) == meta["sha256"]})
        except Exception as e:
            out.append({"file": rel, "ok": False, "error": str(e)})
    log(logpath, "restored %d/%d file(s)" % (sum(1 for r in out if r["ok"]),
                                             len(out)))
    return out


def write_json(path, payload):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=1)
        os.replace(tmp, path)
    except Exception as e:
        sys.stderr.write("cannot write %s: %s\n" % (path, e))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--wait-pid", type=int, required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--backup", required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--wait-timeout", type=int, default=120)
    a = ap.parse_args()

    rundir = os.path.join(a.root, "..", "apex_workspace", "selfedit", "runs", a.run)
    # The engine passes an absolute backup dir inside the run directory; derive
    # the run directory from it so both the app and the supervisor agree.
    rundir = os.path.dirname(os.path.abspath(a.backup))
    try:
        os.makedirs(rundir, exist_ok=True)
    except Exception:
        pass
    logpath = os.path.join(rundir, "restart.log")
    result = {"run": a.run, "started": now(), "port": a.port,
              "python": a.python, "root": a.root}

    pending_path = os.path.join(rundir, "rollback.pending.json")
    pending = None
    if os.path.isfile(pending_path):
        try:
            with open(pending_path, "r", encoding="utf-8") as f:
                pending = json.load(f) or {}
        except Exception:
            pending = {"reason": "unreadable rollback.pending.json"}

    log(logpath, "supervisor up: waiting for pid %d" % a.wait_pid)
    wait_pid(a.wait_pid, a.wait_timeout, logpath)

    child = launch(a.root, a.python, a.port, logpath)
    log(logpath, "launched harness pid %d" % child.pid)
    data, err = health(a.port, a.timeout, child)

    if data is not None:
        if pending:
            # The harness asked for a recovery relaunch, not a new code version:
            # it booted with the restored sources, which is a rollback.
            result.update({"ok": False, "phase": "rolled_back", "pid": child.pid,
                           "reason": pending.get("reason") or "rollback requested",
                           "recovered": True, "health": data, "finished": now()})
            write_json(os.path.join(rundir, "rollback.json"), result)
            write_json(os.path.join(rundir, "supervisor.json"), result)
            log(logpath, "relaunch came up on restored sources — rollback recorded")
            return 0
        result.update({"ok": True, "phase": "restarted", "pid": child.pid,
                       "health": data, "finished": now()})
        write_json(os.path.join(rundir, "restart_ok.json"), result)
        write_json(os.path.join(rundir, "supervisor.json"), result)
        log(logpath, "restart OK — new pid %d serving /health" % child.pid)
        return 0

    log(logpath, "restart FAILED: %s — rolling back" % err)
    kill(child, logpath)
    restored = restore(a.backup, a.root, logpath)
    boot_log = os.path.join(rundir, "boot_failure.log")
    try:
        with open(boot_log, "w", encoding="utf-8") as f:
            f.write("health failure: %s\n" % err)
    except Exception:
        pass

    # Record the intent before relaunching so the booting app reports a rollback
    # instead of claiming a successful change.
    write_json(pending_path, {"reason": err, "at": now(),
                              "restored": [r.get("file") for r in restored]})
    child2 = launch(a.root, a.python, a.port, logpath)
    log(logpath, "relaunched with restored sources: pid %d" % child2.pid)
    data2, err2 = health(a.port, a.timeout, child2)
    result.update({"ok": False, "phase": "rolled_back", "reason": err,
                   "restored": restored, "relaunch_pid": child2.pid,
                   "recovered": data2 is not None,
                   "health": data2, "finished": now()})
    if err2:
        result["relaunch_error"] = err2
    write_json(os.path.join(rundir, "rollback.json"), result)
    write_json(os.path.join(rundir, "supervisor.json"), result)
    log(logpath, "rollback %s" % ("recovered: harness serving previous code"
                                  if data2 is not None
                                  else "FAILED: harness still down (%s)" % err2))
    return 0 if data2 is not None else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:                              # pragma: no cover
        sys.stderr.write("supervisor crashed: %s: %s\n" % (type(e).__name__, e))
        sys.exit(2)
