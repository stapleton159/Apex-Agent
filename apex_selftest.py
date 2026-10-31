#!/usr/bin/env python3
"""
APEX self-test harness.

Drives scriptai2.agent_loop() with a scripted model (MODEL_HOOK) against a
throwaway local HTTP target, and asserts the behaviours the rewrite exists to
guarantee:

  S1  a lazy "it looks vulnerable" completion is refused
  S2  prose-only exploit claims (no tool evidence) are refused
  S3  a real login bypass + privileged read, replay-verified, is ACCEPTED
  S4  the harness never fabricates an assistant turn and never fires requests
      on the model's behalf (no "attack ladder")
  S5  an unproductive loop is closed honestly and bounded, not run 1000 steps
  S6  fabricated quotes in the report are caught by the grounding check
  S7  surrender / hand-off phrasing is refused

Run: python3 apex_selftest.py            (uses port 8099, temp workspace)
Exit code 0 = all scenarios passed.
"""

import glob
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 8099
BASE = f"http://127.0.0.1:{PORT}"
WS = os.path.join(tempfile.gettempdir(), "apex_selftest_ws")

os.environ["APEX_WORKSPACE"] = WS
os.environ.setdefault("OPENROUTER_API_KEY", "selftest-not-used")
os.environ["MAX_STEPS"] = "40"
os.environ["STALL_STEPS"] = "4"
os.environ["STALL_ROUNDS"] = "2"
os.environ["REPLAY_VERIFY"] = "1"
os.environ["GROUNDING_MIN"] = "0.34"
os.environ["MAX_WALL_CLOCK"] = "0"
os.makedirs(WS, exist_ok=True)

sys.path.insert(0, HERE)
import scriptai2 as A          # noqa: E402  (env must be set first)

SECRET = "sk_live_TESTONLY12345678"


# --------------------------------------------------------------------------
# throwaway target
# --------------------------------------------------------------------------
class Target(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", cookie=None):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        cookie = self.headers.get("Cookie", "")
        if path == "/":
            return self._send(200, '<h1>Acme Shop</h1><a href="/product?id=1">p1</a>'
                                   '<a href="/login">login</a>')
        if path == "/product":
            pid = query.split("id=")[-1] if "id=" in query else "1"
            if "'" in pid or "%27" in pid:
                return self._send(500, "sqlite3.OperationalError: near \"'\": syntax error")
            return self._send(200, f"<h2>Product {pid}</h2> price 19.99")
        if path == "/login":
            return self._send(200, '<form method="post" action="/login">'
                                   '<input name="username"><input name="password">'
                                   "</form>")
        if path == "/login.php":
            # PHP behaviour: EVERY request lazy-starts a session and mints
            # PHPSESSID, including a login that fails. Regression fixture for
            # "session cookie == authenticated session" false positives.
            return self._send(200, '<form method="post" action="/login.php">'
                                   '<input name="user_name" type="text">'
                                   '<input name="user_password" type="password">'
                                   '<input type="submit" value="Log In">'
                                   "</form>", cookie="PHPSESSID=abc123; path=/")
        if path == "/admin":
            if "role=admin" not in cookie:
                return self._send(403, "forbidden")
            return self._send(200,
                              "<h1>Admin console</h1>"
                              f"<p>api tokens: {SECRET}</p>"
                              "<p>card_last4: 4242</p>")
        return self._send(404, f"<h1>Not found</h1><p>{self.path}</p>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        if self.path.startswith("/login.php"):
            # rejected login: the form is re-rendered and a session is issued
            return self._send(200, '<form method="post" action="/login.php">'
                                   '<input name="user_name" type="text">'
                                   '<input name="user_password" type="password">'
                                   "</form>", cookie="PHPSESSID=def456; path=/")
        if self.path.startswith("/login"):
            user = ""
            m = re.search(r"username=([^&]*)", body)
            if m:
                import urllib.parse
                user = urllib.parse.unquote(m.group(1))
            if "--" in user and "'" in user:
                return self._send(200, "<h1>Welcome, admin</h1><p>dashboard</p>",
                                  cookie="role=admin; Path=/")
            return self._send(200, "<h1>Invalid credentials</h1>")
        return self._send(404, "nope")


def start_target():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Target)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return srv


# --------------------------------------------------------------------------
# scripted model
# --------------------------------------------------------------------------
def call(tool, args, meta="next step", status="in progress"):
    return json.dumps({"meta_thought": meta,
                       "mission_status": {"stage": status},
                       "tool": tool, "args": args})


class Scripted:
    """Feeds a fixed list of model replies; repeats the final one forever."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.i = 0
        self.asked = []            # urls the model actually requested
        self.emitted = []          # every raw string returned to the harness

    def __call__(self, history):
        if self.i < len(self.replies):
            raw = self.replies[self.i]
            self.i += 1
        else:
            raw = self.replies[-1]
        self.emitted.append(raw)
        try:
            o = json.loads(raw)
            u = (o.get("args") or {}).get("url")
            if u:
                self.asked.append(u)
        except Exception:
            pass
        return raw


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("  PASS  " if cond else "  FAIL  ") + name + (f" — {detail}" if detail else ""))
    return cond


def run(objective, replies):
    hook = Scripted(replies)
    A.MODEL_HOOK = hook
    final = A.agent_loop(objective)
    A.MODEL_HOOK = None
    return hook, final, A.mission.get("status"), list(A.chat_session)


def assistant_turns(history):
    return [m["content"] for m in history if m.get("role") == "assistant"]


def nudge_text(history):
    return "\n".join(m["content"] for m in history
                     if m.get("role") == "user")


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------
def s1_lazy_complete():
    print("\nS1 — lazy completion is refused")
    obj = f"Get into the shop at {BASE} and prove you have real access."
    lazy = ("Assessment complete: the target appears vulnerable to SQL "
            "injection in the product id parameter and further exploitation "
            "is recommended to confirm impact.")
    _, _, status, hist = run(obj, [call("http_request", {"url": BASE + "/"})] * 2
                             + [call("complete", {"summary": lazy})])
    nudges = nudge_text(hist)
    check("S1 rejected the lazy summary", "COMPLETE REJECTED" in nudges)
    check("S1 cited surrender phrasing", "surrender" in nudges.lower(), nudges[-300:].replace("\n", " ")[:200])
    check("S1 did not report COMPLETE", status != "COMPLETE", f"status={status}")
    check("S1 closed bounded by the governor", status in ("EXHAUSTED", "BLOCKED", "STEP_LIMIT"),
          f"status={status} steps={A.mission.get('steps_used')}")
    check("S1 bounded steps (no 1000-loop)", (A.mission.get("steps_used") or 0) <= 30,
          f"steps={A.mission.get('steps_used')}")


def s2_prose_only():
    print("\nS2 — prose-only exploit claim is refused")
    obj = f"Exploit {BASE} and dump the user table with proof."
    claim = ("I successfully exploited the SQL injection on the product "
             "endpoint and dumped the entire users table including password "
             "hashes, which proves complete database access and admin "
             "privileges on the shop application.")
    _, _, status, hist = run(obj, [call("http_request", {"url": BASE + "/product?id=1'"})]
                             + [call("complete", {"summary": claim})])
    nudges = nudge_text(hist)
    check("S2 rejected", "COMPLETE REJECTED" in nudges)
    check("S2 named missing evidence", "NO WORKING EXPLOIT" in nudges or "GROUNDING" in nudges,
          nudges[-400:].replace("\n", " ")[:260])
    check("S2 did not report COMPLETE", status != "COMPLETE", f"status={status}")


def s3_real_chain():
    print("\nS3 — a real, replay-verified chain is accepted")
    obj = (f"Find a working exploit on {BASE}, use it to reach the admin area, "
           "and complete only with a verified exploit.")
    summary = (
        f"Authentication bypass confirmed on {BASE}/login. A POST with "
        "username admin'-- - and any password returned `Welcome, admin` and "
        "set a role=admin cookie, so the login check is injectable.\n"
        f"That cookie was then used against {BASE}/admin?tab=users, which "
        f"returned `api tokens: {SECRET}` and `card_last4: 4242` — customer "
        "payment metadata and a live API token were readable without "
        "credentials.\n"
        "Both requests were replayed by the harness and the same responses "
        "reproduced, so the access is repeatable. Impact: authentication "
        "bypass leading to disclosure of live API tokens and card data "
        "across the admin console.")
    replies = [
        call("http_request", {"url": BASE + "/"}),
        call("http_request", {"url": BASE + "/product?id=1'"}),
        call("http_request", {"url": BASE + "/login", "method": "POST",
                              "body": "username=admin'-- -&password=x",
                              "headers": {"Content-Type":
                                          "application/x-www-form-urlencoded"}}),
        call("http_request", {"url": BASE + "/admin?tab=users"}),
        call("complete", {"summary": summary}),
    ]
    hook, _, status, hist = run(obj, replies)
    nudges = nudge_text(hist)
    ver = [e for e in A.EVIDENCE if e["verified"]]
    check("S3 status COMPLETE", status == "COMPLETE", f"status={status}")
    check("S3 replay verified >=1 strong signal", len(ver) >= 1,
          f"{[(e['kind'], e['verified_by']) for e in ver]}")
    check("S3 admin data observed", any("privileged console" in e["kind"]
                                        or "credential" in e["kind"] for e in A.EVIDENCE),
          str([e["kind"] for e in A.EVIDENCE]))
    check("S3 was not rejected at the end", "COMPLETE REJECTED" not in nudges[-1500:]
          or status == "COMPLETE")
    return hook


def s4_no_hijack(hook):
    print("\nS4 — no fabricated turns, no harness-fired requests")
    hist = A.chat_session
    turns = assistant_turns(hist)
    emitted = set(hook.emitted)
    check("S4 every assistant turn came from the model",
          all(t in emitted for t in turns), f"{len(turns)} turns")
    logged = {(r.get("url") or "").rstrip("/") for r in A.REQUEST_LOG}
    asked = {u.rstrip("/") for u in hook.asked}
    extra = {u for u in logged if u and u not in asked}
    check("S4 harness issued no requests of its own", not extra, f"extra={sorted(extra)[:5]}")
    check("S4 no ladder text injected",
          "ATTACK LADDER" not in nudge_text(hist).upper())


def s5_stall_bounded():
    print("\nS5 — unproductive loop closes honestly")
    obj = f"Exploit {BASE} and take it over."
    replies = [call("http_request", {"url": f"{BASE}/missing{i}"}) for i in range(60)]
    _, _, status, hist = run(obj, replies)
    steps = A.mission.get("steps_used") or 0
    nudges = nudge_text(hist)
    check("S5 closed without COMPLETE", status in ("EXHAUSTED", "BLOCKED"), f"status={status}")
    check("S5 bounded", steps <= 30, f"steps={steps}")
    check("S5 escalated technique classes", "technique class" in nudges.lower()
          or "STALL BREAKER" in nudges)
    reports = sorted(glob.glob(os.path.join(WS, "*.md")), key=os.path.getmtime)
    txt = open(reports[-1], encoding="utf-8", errors="replace").read() if reports else ""
    check("S5 honest report artifact", "MISSION NOT COMPLETED" in txt,
          (reports[-1] if reports else "no report written"))


def s6_grounding():
    print("\nS6 — fabricated quotes are caught")
    obj = f"Exploit {BASE} and report it."
    fake = ("Exploitation succeeded. The database responded with "
            "`information_schema.tables` listing `users_email_password` and "
            "`admin_api_keys`, and the response status 200 response proved "
            "that the full schema was dumped to the attacker.")
    _, _, status, hist = run(obj, [call("http_request", {"url": BASE + "/"})]
                             + [call("complete", {"summary": fake})])
    nudges = nudge_text(hist)
    check("S6 rejected", "COMPLETE REJECTED" in nudges and status != "COMPLETE",
          f"status={status}")
    check("S6 grounding failure reported", "GROUNDING FAILED" in nudges
          or "NO WORKING EXPLOIT" in nudges)


def s7_surrender():
    print("\nS7 — surrender phrasing is refused")
    obj = f"Exploit {BASE} fully."
    surrender = ("The application seems partially hardened. Manual inspection "
                 "of the remaining endpoints is needed, and next steps would "
                 "include testing the admin flow with a real account, which "
                 "would allow an attacker to escalate further.")
    _, _, status, hist = run(obj, [call("http_request", {"url": BASE + "/"})]
                             + [call("complete", {"summary": surrender})])
    nudges = nudge_text(hist).lower()
    check("S7 rejected", "complete rejected" in nudges and status != "COMPLETE",
          f"status={status}")
    check("S7 flagged hand-off phrasing",
          "surrender" in nudges or "future tense" in nudges)


def s8_session_cookie_not_auth():
    print("\nS8 — a PHP session cookie is not an authentication bypass")
    obj = f"Exploit {BASE}/login.php and get admin access."
    replies = []
    for i in range(3):
        replies.append(call("http_request", {
            "url": BASE + "/login.php", "method": "POST",
            "body": "user_name=admin' OR '1'='1&user_password=x",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"}}))
    conclusion = ("The suspected authentication bypass is not reproducible. "
                  "No verified exploit: the login POST re-renders the login "
                  "form and only issues a PHPSESSID cookie, which is not "
                  "proof of an authenticated session.")
    replies += [call("complete", {"summary": conclusion})] * 8
    _, _, status, hist = run(obj, replies)
    kinds = [e["kind"] for e in A.EVIDENCE]
    strong_auth = [e for e in A.EVIDENCE
                   if e["strong"] and "authenticated" in e["kind"]]
    nudges = nudge_text(hist)
    check("S8 no auth-bypass evidence from a bare PHPSESSID", not strong_auth,
          str(kinds))
    check("S8 cookie recorded only as a weak observation",
          any("without authenticated state" in k for k in kinds), str(kinds))
    check("S8 never reported COMPLETE", status != "COMPLETE", f"status={status}")
    check("S8 terminated by itself", status in ("EXHAUSTED", "BLOCKED"),
          f"status={status}")
    check("S8 bounded steps", (A.mission.get("steps_used") or 0) <= 30,
          f"steps={A.mission.get('steps_used')}")
    check("S8 replay did not loop forever",
          nudges.count("COMPLETE REJECTED") <= A.MAX_REJECTIONS,
          f"rejections={nudges.count('COMPLETE REJECTED')}")


def s9_honest_negative_closes():
    print("\nS9 — an honest negative result closes the mission")
    obj = f"Exploit {BASE} and prove admin access."
    replies = [call("http_request", {"url": BASE + "/"})]
    replies += [call("http_request", {"url": f"{BASE}/product?id={i}"})
                for i in range(1, 10)]
    conclusion = ("No verified exploit could be demonstrated on the target. "
                  "The id parameter is not injectable, there is no "
                  "authentication bypass, and no request was reproducible "
                  "as an access-control failure.")
    replies += [call("complete", {"summary": conclusion})] * 10
    _, _, status, hist = run(obj, replies)
    nudges = nudge_text(hist)
    check("S9 closed without COMPLETE", status != "COMPLETE", f"status={status}")
    check("S9 closed on the first honest negative, not by looping",
          nudges.count("COMPLETE REJECTED") <= 1,
          f"rejections={nudges.count('COMPLETE REJECTED')} status={status}")
    # ASSESSED was added deliberately: a negative verdict the harness itself
    # corroborates closes the mission as a graded assessment instead of looping.
    check("S9 status is a terminal close",
          status in ("EXHAUSTED", "BLOCKED", "ASSESSED"), f"status={status}")
    reports = sorted(glob.glob(os.path.join(WS, "*.md")), key=os.path.getmtime)
    txt = open(reports[-1], encoding="utf-8", errors="replace").read() if reports else ""
    # The ASSESSED banner says "MISSION ASSESSED — ... the verdict is NEGATIVE ...
    # this report is the assessment rather than a success claim". Both banners are
    # honest closes; neither may present the negative as a compromise.
    check("S9 report keeps an honest not-a-success banner",
          ("MISSION NOT COMPLETED" in txt) or ("MISSION ASSESSED" in txt),
          reports[-1] if reports else "no report")
    check("S9 report never presents the negative as a success",
          "MISSION COMPLETE" not in txt and "success condition satisfied" not in txt,
          reports[-1] if reports else "no report")
    check("S9 report records the agent's assessment as unverified",
          "NOT accepted as a finding" in txt, txt[-300:].replace("\n", " ")[:200])


def unit_checks():
    print("\nUNIT — classification, novelty, evidence detectors")
    check("U1 POST login is an attack",
          A.classify_call("http_request",
                          {"url": BASE + "/login", "method": "POST",
                           "body": "username=admin'-- -"}) in ("attack", "exploit"))
    check("U2 plain GET is recon",
          A.classify_call("http_request", {"url": BASE + "/"}) == "recon")
    g = A.ProgressGovernor(stall_steps=3, rounds=2)
    for i in range(20):
        g.observe(i, "http_request", f"k{i}",
                  {"status": 404, "body": f"<h1>Not found</h1><p>/x{i}</p>"})
    check("U3 unique-404 sweep counts as a stall", g.stalled(19),
          f"novel={g.novel_total}")
    check("U4 password file detected", "arbitrary file read" in
          A._strong_hits("root:x:0:0:root:/root:/bin/bash"))
    c = A.mission_contract("map the attack surface only, report only")
    check("U5 recon objective does not require an exploit",
          c["kind"] == "recon" and not c["requires_exploit"], str(c["kind"]))
    c = A.mission_contract(f"find a working exploit on {BASE}")
    check("U6 exploit objective requires proof",
          c["requires_exploit"] and c["hard_mandate"], str(c))

    # U7/U8 — auth proof is the BODY, never the cookie
    php_login = ('<form method="post" action="/login.php">'
                 '<input name="user_password" type="password"></form>')
    check("U7 login form is not authenticated state",
          not A._auth_proof(php_login)[0])
    check("U8 welcome banner IS authenticated state",
          A._auth_proof("<h1>Welcome, admin</h1>")[0])
    rec_before = len(A.EVIDENCE)
    for r in A.record_exploit_evidence(
            php_login, source=BASE + "/login.php", method="POST", status=200,
            cookies=["PHPSESSID=abc123; path=/"],
            request={"tool": "http_request", "url": BASE + "/login.php",
                     "method": "POST", "body": "user_name=x"}):
        pass
    new = A.EVIDENCE[rec_before:]
    check("U9 PHPSESSID login page is not STRONG evidence",
          not any(e["strong"] for e in new), str([e["kind"] for e in new]))

    # U10/U11 — the honest-negative gate cannot be used lazily
    A.EVIDENCE.clear()
    A.REQUEST_LOG.clear()
    A.mission["steps_used"] = 0
    neg = ("No verified exploit could be demonstrated; the injection was "
           "not reproducible.")
    check("U10 negative close refused without work done",
          not A.negative_close_ok(neg))
    A.mission["steps_used"] = 20
    for i in range(12):
        A.REQUEST_LOG.append({"method": "GET", "url": f"{BASE}/p{i}",
                              "status": 200, "step": i, "fp": str(i)})
    check("U11 negative close accepted after real work", A.negative_close_ok(neg))
    check("U12 positive claim never closes as a negative",
          not A.negative_close_ok("No verified exploit... but I successfully "
                                  "exploited the login and gained admin."),
          "positive claim leaked through")

    # U13/U14 — privileged-data needles must match account-shaped data, not prose.
    # A WordPress login form matched "balance" in the passkey help text ("balances
    # strictness and reliability") and was recorded as privileged data reached.
    check("U13 login help text is not privileged console data",
          "privileged console data reached" not in
          A._strong_hits("The default setting balances strictness and reliability "
                         "by rejecting non-zero counters that are not higher."),
          "bare-word needle matched prose")
    check("U14 account JSON IS privileged console data",
          "privileged console data reached" in
          A._strong_hits('{"card_last4":"4242","balance":19.99}'))
    A.EVIDENCE.clear()
    A.REQUEST_LOG.clear()


def main():
    shutil.rmtree(WS, ignore_errors=True)
    os.makedirs(WS, exist_ok=True)
    srv = start_target()
    try:
        unit_checks()
        s1_lazy_complete()
        s2_prose_only()
        hook = s3_real_chain()
        if hook:
            s4_no_hijack(hook)
        s5_stall_bounded()
        s6_grounding()
        s7_surrender()
        s8_session_cookie_not_auth()
        s9_honest_negative_closes()
    finally:
        srv.shutdown()
    fails = [r for r in RESULTS if not r[1]]
    print("\n" + "=" * 60)
    print(f"RESULT: {len(RESULTS) - len(fails)}/{len(RESULTS)} checks passed")
    if fails:
        for n, _, d in fails:
            print(f"  FAILED: {n} {d}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
