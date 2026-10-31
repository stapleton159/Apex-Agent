#!/usr/bin/env python3
"""Pull the rendered dashboard's inline <script> blocks and syntax-check them.

The tab is only real if the page the server actually serves parses as
JavaScript, so this checks the rendered output rather than the template.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

BASE = os.environ.get("APEX_URL", "http://127.0.0.1:5002").rstrip("/")


def main():
    if not shutil.which("node"):
        print("SKIP: node is not installed (needed to syntax-check the JS)")
        return 0
    html = urllib.request.urlopen(BASE + "/", timeout=20).read().decode("utf-8", "replace")
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S)
    print("inline script blocks: %d" % len(blocks))
    ok = True
    for i, b in enumerate(blocks):
        if not b.strip():
            continue
        p = os.path.join(tempfile.gettempdir(), "apex_ui_block_%d.js" % i)
        with open(p, "w", encoding="utf-8") as f:
            f.write(b)
        r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
        print("block %d: %d bytes -> %s" % (i, len(b), "OK" if r.returncode == 0
                                            else "SYNTAX ERROR"))
        if r.returncode != 0:
            ok = False
            print(r.stderr.strip()[:600])
        for fn in ("seLoad", "seStart", "seRollback", "sePaint", "seStop"):
            if fn in b:
                print("   defines/calls %s" % fn)
        if "data-tab === 'selfedit'" in b or 'data-tab === "selfedit"' in b:
            print("   tab dispatch present")
    want = ("seLoad", "seStart", "seStop", "seRollback")
    joined = "\n".join(blocks)
    for fn in want:
        if ("function %s" % fn) not in joined and ("%s =" % fn) not in joined:
            print("MISSING function: %s" % fn)
            ok = False
    print("RESULT: %s" % ("pass" if ok else "fail"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
