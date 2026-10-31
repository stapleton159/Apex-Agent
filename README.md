<div align="center">

# APEX

**An autonomous, evidence-gated penetration-testing harness with a self-editing operator console.**

[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-lightgrey?style=flat-square)](docs)
[![Tests](https://img.shields.io/badge/tests-138%20checks%20passing-brightgreen?style=flat-square)](tests)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

[Quick start](#-quick-start) · [Configuration](#-configuration) · [Self-Edit](#-self-edit) · [API](#-http-api) · [Troubleshooting](#-troubleshooting)

</div>

---

APEX drives a model through a real assessment against a target you name, one tool call at a time, and **refuses to call the job finished until the findings survive replay against the live target.** You watch it work in a browser dashboard, steer it mid-mission, and — when the harness itself is missing a capability you need — ask it to **edit its own source and restart**.

It is not a scanner wrapper. There is no step ceiling, no "report generated" step, and no way for the model to write a finding into the report that the evidence gate has not independently replayed.

APEX was built out of a need for a cheap, effective, and truly modular autonomous harness. Rather than relying on heavy, token-expensive multi-agent "swarms" that generate high API overhead, APEX uses a streamlined single-agent loop coupled with a deterministic Evidence Gate. We believe that democratizing AI security tooling requires eliminating bloat, enforcing hard exploit verification over model guesswork, and ensuring high-potency autonomous execution remains accessible and cost-effective for independent researchers.

> [!WARNING]
> **APEX is an offensive-security tool.** Run it only against systems you own or are explicitly authorized in writing to test. The dashboard has no authentication and exposes file upload, shell execution and a self-editing code path — bind it to `127.0.0.1` and treat the port as a root-equivalent interface. See [Authorized use](#-authorized-use).

---

## Table of contents

- [Why it exists](#-why-it-exists)
- [Features](#-features)
- [How it works](#-how-it-works)
  - [The loop](#the-loop)
  - [The evidence gate](#the-evidence-gate)
  - [The progress governor](#the-progress-governor)
- [Quick start](#-quick-start)
  - [Linux / macOS](#linux--macos)
  - [Windows](#windows)
  - [Termux (Android)](#termux-android)
  - [Docker](#docker)
- [API key setup](#-api-key-setup)
- [Using the console](#-using-the-console)
- [Self-Edit](#-self-edit)
- [Configuration](#-configuration)
- [HTTP API](#-http-api)
- [Project layout](#-project-layout)
- [Tests](#-tests)
- [Portability](#-portability)
- [Troubleshooting](#-troubleshooting)
- [Authorized use](#-authorized-use)
- [License](#-license)

---

## Why it exists

Most LLM pentest agents fail in one of two ways:

1. **They stall.** They loop on the same dead request, or spend forty steps trying to `pip install` a tool that was never going to exist on the host.
2. **They fabricate.** They write a confident "SQL injection confirmed — critical" from a 500 error, and the operator has to re-verify everything anyway.

APEX is built against both failure modes at the engine level, not the prompt level:

| Failure mode | Structural countermeasure |
|---|---|
| Fabricated findings | Every claimed finding is **replayed** against the target before it can be reported |
| Endless repetition | A **progress governor** measures new information per step and forces a technique change |
| Tool-install rabbit holes | Install/download patterns are intercepted in the loop and redirected at zero step cost |
| "Done" with nothing to show | Completion requires a *contract*: verified evidence, or an honest negative with enough attempts behind it |
| Hallucinated tool calls | A capability layer resolves each call against what this host actually has, and degrades instead of erroring |

---

## Features

<table>
<tr><td width="50%" valign="top">

**Autonomous loop**
- No step ceiling — bounded by *productivity*, not a counter
- Replay-verified evidence gate on every finding
- Progress governor that forces technique-class changes
- Mission queue: submit several directives, they run sequentially
- Pause / resume / steer mid-mission

**Operator console**
- Nine-tab single-page dashboard, live SSE event stream
- Chat steering while the agent is running
- Evidence browser with per-item verdicts
- Persistent memory across missions

</td><td width="50%" valign="top">

**Capability layer** (`apex_tools.py`)
- DoH resolver + local DNS stub so *binaries* resolve too
- Native port scan, TLS inspection, HTTP fingerprinting
- GitHub release fetch + `provision` for ffuf, nuclei, subfinder…
- Cloudflared quick tunnels for exposing a local listener
- Browser: playwright → CDP → agent-browser → static fetch

**Self-Edit**
- Backup → plan → patch → validate → restart → verify
- sha256 manifests, atomic writes, byte-exact rollback
- Cannot edit its own recovery path

</td></tr>
</table>

---

## How it works

```text
                      ┌──────────────────────────────────────────┐
   operator ─────────▶│  Flask dashboard  (templates/index.html)  │
   (browser)          │  console · memory · mail · phish · files  │
                      │  status  · oracle · lab  · self-edit      │
                      └───────────────┬──────────────────────────┘
                                      │  POST /chat · /queue · /stop
                                      ▼
                      ┌──────────────────────────────────────────┐
                      │  agent_loop()  —  scriptai2.py            │
                      │                                           │
                      │   prompt ─▶ model ─▶ tool call ─▶ result   │
                      │      ▲                      │             │
                      │      │        ┌─────────────┴───────────┐ │
                      │      │        │  capability layer       │ │
                      │      │        │  apex_tools · apex_ops   │ │
                      │      │        │  apex_lab  · apex_oracle │ │
                      │      │        └─────────────┬───────────┘ │
                      │      │                      │             │
                      │      │        ┌─────────────▼───────────┐ │
                      │      └────────┤ evidence gate + replay  │ │
                      │               │ governor · grounding    │ │
                      │               └─────────────┬───────────┘ │
                      └─────────────────────────────┼─────────────┘
                                                    ▼
                                          workspace/  (state, evidence,
                                          screenshots, reports, runs)
```

### The loop

Each step is one JSON decision from the model: **call a tool**, **record a finding**, or **declare completion**.

```text
  ┌─▶ build prompt (objective + tool map + memory + findings so far)
  │        │
  │        ▼
  │   model returns {"action": "tool" | "report" | "done", ...}
  │        │
  │        ├── tool   → execute, append result, measure new information
  │        ├── report → stage the finding, run the evidence gate
  │        └── done   → evaluate the mission contract
  │        │
  └────────┘  (repeat until the contract is satisfied, the governor closes
               the mission honestly, or the operator stops it)
```

### The evidence gate

A finding is only accepted when it is **replayed**: APEX re-issues the request that supposedly proved it and compares the response against what was claimed.

```text
 claim: "SQLi at /item?id=1 → boolean differential"
        │
        ▼
 replay the exact request twice, with and without the payload
        │
        ├── differential reproduces  → verified, reportable
        ├── no differential          → REFUTED (replayed at most REPLAY_MAX_TRIES)
        └── target unreachable       → unverified, retained as a lead
```

Verified and weak evidence are tracked separately and surfaced in the **Status** tab, so you can always see how much of a report is replay-confirmed.

### The progress governor

Completion is not the only thing that is bounded — *waste* is too:

- **Stall detection.** After `STALL_STEPS` steps that produced no new surface, credential, endpoint or finding, the loop forces a different technique class.
- **Honest closure.** After `STALL_ROUNDS` exhausted classes, the mission closes with a **negative report** rather than looping forever — including how many requests and attempts were made, so a negative is a real result instead of a silence.
- **Detour interception.** `pip install …`, `git clone`, `curl … | sh` and similar patterns are blocked at the loop level and redirected, so a dead download link cannot eat a mission.

---

## Quick start

**Requirements:** Python 3.9+ (this release is tested on 3.14), and an [OpenRouter](https://openrouter.ai) API key. No key is stored in this repository — you supply your own ([how](#-api-key-setup)).

### Linux / macOS

```bash
git clone <your-fork-url> apex && cd apex

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

cp .env.example apex.env     # then edit apex.env and set OPENROUTER_API_KEY
python scriptai2.py
```

Open **http://127.0.0.1:5002**.

### Windows

```powershell
git clone <your-fork-url> apex
cd apex

py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt

copy .env.example apex.env   # then edit apex.env and set OPENROUTER_API_KEY
py scriptai2.py
```

Open **http://127.0.0.1:5002**.

> [!TIP]
> **POSIX shell tools on Windows.** The agent will sometimes emit `grep`/`sed`/`curl` pipelines. APEX uses **Git Bash** if it is on `PATH`, otherwise `cmd.exe` — and in `cmd.exe` those commands simply report not-found instead of failing silently. For full-fidelity shell work, install [Git for Windows](https://git-scm.com/download/win) or run APEX inside WSL2.

> [!NOTE]
> If PowerShell refuses to activate the venv (`running scripts is disabled`), run once:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Termux (Android)

```bash
pkg update && pkg install python git
git clone <your-fork-url> apex && cd apex

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example apex.env && nano apex.env    # set OPENROUTER_API_KEY
python scriptai2.py
```

On Termux the workspace defaults to `~/apex_workspace`; elsewhere it is `./workspace` next to the scripts. Override with `APEX_WORKSPACE`.

### Docker

```bash
docker build -t apex .
docker run --rm -p 127.0.0.1:5002:5002 \
  -e OPENROUTER_API_KEY=sk-or-v1-... \
  -v "$PWD/workspace:/app/workspace" \
  apex
```

---

## API key setup

**There is no API key in this source tree.** `scriptai2.py` reads it from the environment and defaults to an empty string. Choose one of:

<table>
<tr><th>Method</th><th>Command</th><th>Best for</th></tr>
<tr><td><b>Environment variable</b></td><td>

```bash
export OPENROUTER_API_KEY=sk-or-v1-...
```

Windows (persistent):
```powershell
setx OPENROUTER_API_KEY "sk-or-v1-..."
```

</td><td>CI, containers, one-off runs</td></tr>
<tr><td><b><code>apex.env</code></b> (git-ignored)</td><td>

```bash
cp .env.example apex.env
# edit OPENROUTER_API_KEY=...
```

</td><td>Local development — recommended</td></tr>
<tr><td><b><code>~/.apex/apex.env</code></b></td><td>

```bash
mkdir -p ~/.apex && cp .env.example ~/.apex/apex.env
```

</td><td>One key for several checkouts</td></tr>
</table>

Load order: real environment → `./apex.env` → `~/.apex/apex.env`. The first value found wins, so an exported variable always beats a file.

**Without a key the console still boots.** Model calls return a clear API error, and `/health` reports `model_wired: false`, which is exactly what you want for UI work and for the operator-driven Self-Edit path.

Verify the key without starting a mission:

```bash
curl -s http://127.0.0.1:5002/status | python -m json.tool | grep model_wired
```

---

## Using the console

Nine tabs, all live over SSE:

| Tab | What it does |
|---|---|
| **Console** | Objective box, live step stream, chat steering, stop/pause |
| **Memory** | Durable knowledge across missions: surfaces, credentials, dead ends |
| **Mail** | Disposable inbox for registration/verification flows |
| **Phish** | Local capture server + tunnel, for authorized phishing simulations |
| **Files** | Workspace browser, uploads, downloads, screenshots |
| **Status** | Mission contract, gate verdict, evidence counts, tool inventory |
| **Oracle** | Second model that watches the loop and can steer or auto-steer it |
| **Lab** | Payload workspace: write, build, run, pack, inspect |
| **Self-Edit** | Rewrite the harness itself — see [below](#-self-edit) |

### Your first mission

1. Open the **Console** tab.
2. Enter an objective that names a target **and** a definition of done:
   > *"Assess https://lab.example.com. Find and prove at least one injection or auth bypass, and record the request/response pair that proves it."*
3. Press **start**. Watch the step stream; steer any time by typing in the chat box.
4. When it stops, open **Status** → the contract block tells you whether the gate opened and how many evidence items are replay-verified versus merely observed. `GET /evidence` returns the same list with a verdict per item.

A good objective has three parts: **target**, **scope** (what not to touch), and **evidence bar**. An objective without an evidence bar is what produces a report full of vibes.

---

## Self-Edit

The harness can add capabilities to itself: you describe what is missing in plain language, and it patches its own source, validates, restarts, and proves the restart.

> [!IMPORTANT]
> Self-Edit runs inside your checkout. It only ever edits a fixed allow-list — `scriptai2.py`, `templates/index.html`, `apex_selfedit.py`, `apex_ops.py`, `apex_tools.py` — and it **cannot** edit `apex_selfedit_supervisor.py`, because that file is the recovery path.

### The cycle

```text
  operator prompt
        │
        ▼
  1. BACKUP     every editable file → runs/<run_id>/backup/  + manifest.json (sha256)
        │
        ▼
  2. PLAN       model returns {"summary", "ops":[{"file","find","replace","why"}],
                               "restart": true}
        │
        ▼
  3. APPLY      in memory only — each `find` must match EXACTLY once (≥12 chars)
        │
        ▼
  4. VALIDATE   py_compile · required anchors still present · every UI tab still
        │       paired with a panel · no truncation · no Jinja delimiter growth
        │
        ├── reject ──▶ feed the exact validator errors back → next iteration (loop)
        ▼
  5. RESTART    hand off to apex_selfedit_supervisor.py, then exit
        │
        ▼
  6. VERIFY     supervisor waits for the old pid to die, relaunches, polls /health
        │
        ├── healthy   → restart_ok.json      → phase "done"
        └── unhealthy → restore backup, relaunch → rollback.json → phase "rolled_back"
```

Phases: `idle → planning → applying → validating → restarting → done`, with the terminal failure states `failed` (nothing written), `rolled_back` (restored), `stopped` (operator).

### Why you can trust the result

A process that rewrote its own source cannot honestly tell you whether it came back — once it exits, nothing it wrote afterwards is trustworthy. So the restart belongs to a **separate supervisor process**:

- It polls `/health`, and the `/health` response carries the **new pid** — a restart is not assumed, it is observed.
- On failure it restores the sha256-verified backup, relaunches once, and writes `rollback.json`.
- It leaves a `rollback.pending.json` marker so the relaunched app reports itself as a **rollback** on boot — a failed change can never be reported as a success.
- Every restore re-hashes the file after writing and fails loudly on a mismatch.

Everything a run produces lives under `workspace/selfedit/runs/<run_id>/`:

```text
runs/20261031-112440-c79ec2/
├── backup/            original files + manifest.json (sha256 per file)
├── manifest.json      what was backed up and when
├── final.diff         unified diff of the accepted change
├── supervisor.json    restart outcome as the supervisor saw it
├── restart.log        supervisor trace
├── restart_ok.json    present only on a clean, verified restart
└── rollback.json      present only on a rollback (with the reason)
```

### Driving it

**From the UI.** Self-Edit tab → type the prompt → set iterations → **start**. The panel polls the whole time and reconnects itself *across the restart*: phase, per-iteration accept/reject with the validator's errors, the ops, the validation table, files changed, and the full diff against the backup.

**From the API, without a model.** You can supply the ops yourself — no model, no credits, still fully backed up, validated, restarted and (if it fails) rolled back:

```bash
curl -s -X POST http://127.0.0.1:5002/selfedit/start \
  -H 'Content-Type: application/json' \
  -d '{
        "prompt": "add an operator note above the main block",
        "restart": true,
        "max_iters": 1,
        "ops": [{
          "file": "scriptai2.py",
          "find": "if __name__ == \"__main__\":",
          "replace": "# operator note\nif __name__ == \"__main__\":",
          "why": "demo"
        }]
      }'
```

```bash
curl -s http://127.0.0.1:5002/selfedit | python -m json.tool   # phase, history, diff
curl -s "http://127.0.0.1:5002/selfedit/diff?run=<run_id>"      # diff for any past run
curl -s -X POST http://127.0.0.1:5002/selfedit/rollback \
  -H 'Content-Type: application/json' -d '{"run": "<run_id>"}'
```

> [!TIP]
> **Roll back to a run, not to "latest".** The newest backup on disk contains the change you just made. `POST /selfedit/rollback` with `{"run": "<run_id>"}` restores the sources **as that run found them**, which is what you usually want. Omitting `run` restores the most recent backup.

> [!NOTE]
> A rollback rewrites files on disk but does not restart the process — restart the harness to unload the old code.

### What Self-Edit will not do

- It will not start while a mission is running (a restart would kill it) unless you pass `"force": true`.
- It will not touch the supervisor, paths outside the repo, or a file that is not in the allow-list.
- It will not write anything unless validation passes.
- It will not edit a file when a `find` string is ambiguous — 0 or 2+ matches is a rejection, not a guess.

---

## Configuration

Everything is environment-driven; `apex.env` is just a convenient place to keep it.

### Server & paths

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `5002` | HTTP port |
| `BIND_HOST` | `127.0.0.1` | Bind address. **`0.0.0.0` exposes an unauthenticated root-equivalent UI** |
| `APEX_WORKSPACE` | `./workspace` (Termux: `~/apex_workspace`) | State, evidence, screenshots, runs |
| `UPLOAD_MAX_MB` | — | Upload size cap |

### Model

| Variable | Default | Meaning |
|---|---|---|
| `OPENROUTER_API_KEY` | *(empty)* | **Required** for the agent loop |
| `OPENROUTER_ENDPOINT` | `https://openrouter.ai/api/v1/chat/completions` | Any OpenAI-compatible endpoint |
| `MODEL_NAME` | `deepseek/deepseek-chat-v3.1` | Primary model |
| `APEX_FALLBACK_MODELS` | — | Comma-separated fallbacks on error |
| `APEX_SELFEDIT_MODELS` | — | Model used only by the Self-Edit loop |

### Loop behaviour

| Variable | Default | Meaning |
|---|---|---|
| `MAX_STEPS` | `0` | Step ceiling; `0` = unbounded (recommended) |
| `STALL_STEPS` | `10` | Unproductive steps before forcing a technique change |
| `STALL_ROUNDS` | `7` | Technique classes before closing honestly |
| `MAX_WALL_CLOCK` | `0` | Wall-clock limit in seconds; `0` = off |
| `GROUNDING_MIN` | `0.34` | Minimum evidence grounding to accept completion |
| `REPLAY_VERIFY` | `1` | Replay findings against the target |
| `REPLAY_MAX_TRIES` | `2` | Replay attempts before a claim is refuted for good |
| `MAX_REJECTIONS` | `6` | Rejected completions before an honest negative close |
| `CMD_TIMEOUT` | `600` | Per-command timeout (seconds) |
| `MAX_OUTPUT` | `8000` | Tool output truncation |
| `MAX_HISTORY` | `100` | Prompt history window |

### Self-Edit

| Variable | Default | Meaning |
|---|---|---|
| `SELFEDIT_MAX_ITERS` | `3` | Iterations before the loop gives up |
| `SELFEDIT_HEALTH_TIMEOUT` | `60` | Seconds the supervisor waits for `/health` |
| `APEX_SELFEDIT_MODELS` | — | Model for the self-edit loop only |

### Other

| Variable | Meaning |
|---|---|
| `APEX_BROWSER` | Force a browser backend: `playwright`, `agent-browser`, `cdp` |
| `APEX_CHROME_CDP` | CDP websocket URL for an existing Chrome |
| `APEX_AB_SESSION` | `agent-browser` session name |
| `APEX_TRUST` | `0` disables trust-mode shortcuts |
| `APEX_NO_DNS_STUB` | `1` disables the local DNS stub |

---

## HTTP API

Everything the dashboard does is an HTTP call. All JSON unless noted.

<details>
<summary><b>Mission control</b></summary>

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard |
| `GET` | `/stream` | SSE event stream |
| `POST` | `/chat` | Send a directive; starts a mission if idle |
| `POST` | `/queue` | Queue missions: `{"missions": ["…", "…"]}` |
| `GET` | `/queue` | Queue depth and results |
| `POST` | `/resume` | Resume a paused mission |
| `POST` | `/stop` | Stop the current mission |
| `POST` | `/reset` | Clear state |
| `GET` | `/state` | Mission state |
| `GET` | `/mission` | Current mission contract |
| `GET` | `/status` | Dashboard summary: stats, gate verdict, tool inventory |
| `GET` | `/health` | Liveness: `pid`, `model`, `selfedit` phase, `ok` |
| `GET`/`POST` | `/mode` | Read/set operating mode |
| `GET` | `/prompt` | Current system prompt |
| `GET` | `/evidence` | Evidence items with verification verdicts |

</details>

<details>
<summary><b>Self-Edit</b></summary>

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/selfedit` | Status: phase, run id, log, history, ops, validation, diff, editable scope |
| `POST` | `/selfedit/start` | `{"prompt", "max_iters", "restart", "ops"?, "force"?}` |
| `POST` | `/selfedit/stop` | Stop the loop |
| `POST` | `/selfedit/rollback` | `{"run"?: "<run_id>"}` — restore that run's backup |
| `GET` | `/selfedit/diff` | `?run=<run_id>` — unified diff against the backup |

</details>

<details>
<summary><b>Data, memory and tooling</b></summary>

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/files` | Workspace listing (names, sizes, mtimes) |
| `GET` | `/files/<path>` | Download a workspace file |
| `POST` | `/upload` | Upload into the workspace (`files` field) |
| `GET` | `/memory` | Durable memory |
| `GET` | `/mail`, `POST /mail/create`, `GET /mail/read/<id>` | Disposable inbox |
| `GET`/`POST` | `/phish`, `/phish/build`, `/phish/start`, `/phish/stop`, `/phish/tunnel` | Capture server for authorized simulations |
| `GET`/`POST` | `/oracle`, `/oracle/chat`, `/oracle/steer`, `/oracle/auto`, `/oracle/reset` | Second-model supervisor |
| `GET`/`POST` | `/lab`, `/lab/write`, `/lab/build`, `/lab/run`, `/lab/inspect`, `/lab/pack`, `/lab/read`, `/lab/delete`, `/lab/download/<name>` | Payload workspace |

</details>

---

## Project layout

```text
apex-harness/
├── scriptai2.py                  entry point — Flask app, agent loop, routes
├── apex_tools.py                 capability layer: DNS/DoH, scanning, tunnels, browser
├── apex_ops.py                   durable memory, temp mail, capture server
├── apex_oracle.py                second-model supervisor / steering
├── apex_lab.py                   payload workspace (write, build, run, pack)
├── apex_autofire.py              multi-target sweep driver
├── apex_selfedit.py              Self-Edit engine + /selfedit* routes
├── apex_selfedit_supervisor.py   restart + rollback (never self-edited)
├── apex_selftest.py              engine self-check (49 checks)
├── templates/
│   └── index.html                the nine-tab dashboard
├── tests/
│   ├── selfedit_test.py          Self-Edit unit checks (54)
│   ├── selfedit_e2e.py           Self-Edit end-to-end, own port (35)
│   └── ui_js_check.py            syntax-check the served dashboard JS
├── requirements.txt
├── Dockerfile
├── .env.example
├── .gitignore
└── LICENSE
```

Runtime state is created next to the scripts and is **not** part of the package:

```text
workspace/
├── agent_state.json · mission.json · chat_history.json
├── memory.json · reports.json
├── screenshots/
├── downloads/
└── selfedit/runs/<run_id>/…
```

---

## Tests

```bash
python apex_selftest.py          # 49/49   engine + capability self-check
python tests/selfedit_test.py    # 54/54   Self-Edit unit checks (sandbox only)
python tests/selfedit_e2e.py     # 35/35   real restart + real rollback on port 5003
```

The end-to-end suite is the interesting one: it copies the app into a temporary directory, boots it on its own port, then drives **four** scenarios against the real HTTP surface —

| Scenario | Proves |
|---|---|
| **A** valid change | patch → validate → restart → `/health` on a **new pid** → `done` |
| **B** compiles but cannot boot | supervisor restores the backup, relaunches, `rolled_back`; the earlier good change survives |
| **C** operator rollback by run id | the file matches that run's own backup **byte for byte** |
| **D** op against the supervisor | accepted, then refused by the loop; the recovery path is untouched |

> [!NOTE]
> `tests/selfedit_e2e.py` needs port `5003` free and takes ~90 s, because it waits on real process deaths and real health polls. Unit tests never touch your live sources — they assert the live file hash is unchanged at the end.

The UI check needs a running instance:

```bash
APEX_URL=http://127.0.0.1:5002 python tests/ui_js_check.py
```

---

## Portability

Same code, four OSes, no fork:

| | Linux | macOS | Windows | Termux |
|---|:--:|:--:|:--:|:--:|
| Console + agent loop | ✅ | ✅ | ✅ | ✅ |
| Self-Edit (patch / validate / restart / rollback) | ✅ | ✅ | ✅ | ✅ |
| Port scan · TLS · DNS-over-HTTPS | ✅ | ✅ | ✅ | ✅ |
| Browser (playwright) | ✅ | ✅ | ✅ | ⚠️ heavy |
| POSIX shell tools (`grep`, `sed`) | ✅ | ✅ | ⚠️ Git Bash | ✅ |
| Process-group kill on restart | ✅ | ✅ | ✅ (per-process) | ✅ |

What was actually changed to get there:

- **Windows process probes.** `os.kill(pid, 0)` is *not* a liveness probe on Windows — it calls `TerminateProcess`. The supervisor and the tunnel manager now use `OpenProcess` + `GetExitCodeProcess` there, so "is it alive?" can never kill what it is asking about.
- **`SIGKILL` fallbacks.** Windows has no `SIGKILL`; the supervisor degrades to `SIGTERM`, and to `proc.kill()` when there is no `killpg`.
- **Shell discovery.** `/bin/bash` → `$PREFIX/bin/sh` → `shutil.which("bash")` → `COMSPEC`, so Git Bash is preferred and `cmd.exe` is the floor.
- **Console encoding.** stdout/stderr are forced to UTF-8, so a legacy Windows code page cannot kill startup with `UnicodeEncodeError` on the banner.
- **`/proc` is optional.** Memory and zombie checks read it when present and fall back cleanly when it is not.
- **No POSIX-only imports.** Nothing imports `fcntl`, `termios`, `pwd` or `resource`, so the modules import cleanly on Windows.
- **Paths.** Everything resolves from `__file__` or `HOME`; `APEX_WORKSPACE` overrides the lot.

---

## Troubleshooting

<details>
<summary><b>The console loads but every mission errors immediately</b></summary>

No API key, or no credits. Check:

```bash
curl -s http://127.0.0.1:5002/health
```

`model_wired: false` → the key never arrived. Re-check load order (exported env beats `apex.env`). An HTTP **402** from the provider means the key is valid but the account has no credits.
</details>

<details>
<summary><b>Port 5002 is already in use</b></summary>

```bash
PORT=5050 python scriptai2.py     # Linux/macOS/Termux
$env:PORT=5050; py scriptai2.py   # Windows PowerShell
```
</details>

<details>
<summary><b>Self-Edit ends in <code>failed</code> with a 402 / provider error</b></summary>

The loop needs a funded key. Your sources are untouched — nothing is written before validation. The operator path (`"ops": [...]`, no model) works with no credits at all.
</details>

<details>
<summary><b>Self-Edit says <code>rolled_back</code> — is my code gone?</b></summary>

No. `rolled_back` means the change was **restored** to the backup and the harness came back up. The reason is in `workspace/selfedit/runs/<run_id>/rollback.json` and `restart.log`; the boot failure is in `boot_failure.log`.
</details>

<details>
<summary><b>Restart worked but the old behaviour is still there</b></summary>

Files were rewritten, the process was not. Only a real restart (Self-Edit with `"restart": true`, or stop/start) unloads the old module.
</details>

<details>
<summary><b><code>python</code> not found on macOS / Debian</b></summary>

Use `python3` and `python3 -m venv .venv`. Debian/Ubuntu may need `apt install python3-venv`.
</details>

<details>
<summary><b>pip install fails building wheels</b></summary>

Upgrade pip first: `python -m pip install -U pip setuptools wheel`. On Termux, `pkg install python` (not the distro python) so binary wheels match.
</details>

<details>
<summary><b>Browser tools degrade to a plain text fetch</b></summary>

No browser backend was found. Install one:

```bash
pip install playwright && playwright install chromium
```

Then set `APEX_BROWSER=playwright` to force it.
</details>

---

## Authorized use

APEX performs active testing: it sends crafted requests, scans ports, and can deploy listeners and tunnels. That is only lawful and ethical against systems where you hold **explicit written authorization**.

- Keep `BIND_HOST=127.0.0.1` unless the dashboard sits behind an authenticating proxy or a private network. It has **no login** and grants shell execution plus source rewriting.
- Point it at scopes you own: a lab, a CTF, a signed engagement, your own staging environment.
- Evidence, screenshots and captured credentials land in `workspace/` in cleartext. Treat that directory like evidence: encrypt it, and delete it when the engagement closes.
- The **Phish** tab builds capture pages for authorized social-engineering tests only. Never target people who have not consented as part of the engagement.

You are responsible for the authorization behind every target you give it.

---

## Contributing

1. Fork, branch, and keep changes inside the allow-list of files if you plan to use Self-Edit on your own fork.
2. Run all three suites before opening a PR — `apex_selftest.py`, `tests/selfedit_test.py`, `tests/selfedit_e2e.py`.
3. If you change the loop's completion logic, add a case to `apex_selftest.py` that would fail without your change.

## License

[MIT](LICENSE) — see the file for the full text. Replace the copyright line with your own name or organisation before publishing your fork.

<div align="center">
<sub>Built for operators who would rather see one replayed request than ten confident guesses.</sub>
</div>
