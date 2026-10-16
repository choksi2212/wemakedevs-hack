# SEVER Render deployment audit — audit5/deploy-audit (2026-10-16)

Read-only audit of `srv-db8ej0jncjis73fjjnag` (`sever-console.onrender.com`,
free plan, singapore, docker runtime, repo `choksi2212/wemakedevs-hack`,
branch `develop`, autoDeploy **no** — all confirmed via the Render API).
Evidence: Render API (deploys, env-var names, logs windows), live HTTP probes,
and repo history. All timestamps UTC (IST = UTC+5:30).

## 1. Deploy history (API-verified, complete)

| deploy | commit | status | started → finished |
|---|---|---|---|
| dep-db8ej13ncjis73fjjpfg | febb6be | deactivated | Oct 15 14:56:04 → 14:58:19 (2m15s, first build) |
| dep-db8ekrnavr4c73b77eo0 | febb6be | deactivated | Oct 15 14:59:58 → 15:00:41 (43s) |
| dep-db8etvcs728c73966n1g | febb6be | deactivated | Oct 15 15:19:25 → 15:20:33 (68s) |
| dep-db8mfmfavr4c73dfu3k0 | 061f65e | deactivated | Oct 15 23:55:05 → 23:56:29 (84s; `redeploy_final.py` wiped the Cloud graph first → fresh auto-load boot) |
| dep-db8mug0n74is73c2qhd0 | 53fa606 | **update_failed** | Oct 16 00:26:40 → 00:27:37 (57s) |
| dep-db8n0ps9v7es73d5ek70 | bfe9308 | **live** | Oct 16 00:31:35 → 00:32:37 (61s) |

**The NameError rollback story is verified end-to-end.** Commit 53fa606
(socket-timeout patch) shipped without `import os` in the port module; its
deploy booted at 00:27:19, crashed at import time (`NameError: name 'os' is
not defined`, `app.py:148 → build_app`, log 00:27:30), and Render marked the
deploy `update_failed` at 00:27:37. **The old build kept serving** — a healthy
`Started server process` appears at 00:27:52 and requests never stopped. The
fix (bfe9308, 00:31) deployed clean and is live. Deploy-failure semantics on
Render: a deploy that never passes health checks is canceled (15-min window)
and traffic stays on the existing instances — the rollback worked exactly as
documented. Note: only **one** deploy failed; the other 2026-10-16 deploy
(061f65e, 23:55) succeeded and was merely superseded.

## 2. Runtime reality — the ephemeral receipts ledger

`CaseLog` writes `out/cases/<graph>.jsonl` under the process CWD (`/app` in
the container). Render's default filesystem is **ephemeral — lost on every
deploy, restart, and spin-up** (free plan has no persistent-disk option;
disks are paid-plan-only). Live evidence today: `/api/receipts` first
timestamp moved **00:32:35 (deploy) → 00:51:49 → 01:01:49 → 01:19:19 (restarts)**
— four wipes in ~47 minutes while the audit ran. Between wipes the ledger
held only post-boot rows, ~95% of them `state` probe receipts (~1 per 2-3s:
Render health checks + keepalive + client probes), drowning the 2 real demo
`finding` receipts.

Demo-story verdict: **a short post-boot ledger is survivable but not as
currently produced.** DEMO_SCRIPT beat 6 ("receipts ledger scrolling — every
action, timestamped") only works if the ledger is (a) not wiped mid-demo by
the restart loop (§4) and (b) not flooded by health-check noise. README's
"append-only / self-repairing" and "case memory survives process death"
claims hold **per-process** — and the LangGraph case memory genuinely
persists via FalkorDBSaver *in the engine* — but nothing on the free plan
makes the receipts **file** survive a restart. Docs updated accordingly.

## 3. Dockerfile / sample on this build

Build-time download verified on **this** live build: log layer
`#12 [6/6] RUN mkdir -p data/ad_sample && curl …ad_sampledata.zip` ran
during deploys at 23:55 and 00:32 UTC; both deploys succeeded (a failed
`&&` chain would have failed the build), `SEVER_SAMPLE_DIR=/app/data/ad_sample`
is set (19 chars, API-verified). The SpecterOps URL is still valid today
(HTTP 200, application/zip, 165,712 bytes) so rebuilds stay reproducible.
Auto-load timing: the empty-graph boot (23:55:47 `==> Deploying…` → 23:56:22
uvicorn listening) took **35s total** including the 16.8s-class estate load;
subsequent boots with the Cloud graph already present bind in **<1-2s**
(00:32:15 → 00:32:27).

## 4. Health check × boot interplay — the real bug

- **Boot is safe**: the auto-load runs at import time, *before* uvicorn binds
  its port, so health checks can't reach (and time out on) a mid-load boot;
  Render's 15-minute deploy window absorbs the 35s cold boot easily. The
  health check does **not** time out before the load finishes.
- **The running-instance check is the failure mode**: Render's HTTP health
  check requires **2xx within 5 seconds**, sent every few seconds. Live
  `/api/state` measured **1.04s** when the engine is quiet but
  **6.07s → 14.5s → 16.2s → 24.1s** under concurrent load (five engine queries
  per call, incl. the full reachability traversal, against the free FalkorDB
  Cloud tier). Above 5s, checks fail; 15s of failures stops routing (502s
  observed, incl. during live probe windows); 60s of failures **restarts the
  instance** — observed boots at 00:50:34, 00:51:42 and 01:01:47, i.e. a
  restart loop that wipes the ledger each time.
- **Fix (this branch)**: `/api/health` — one cheap engine query, no receipt
  write — and `healthCheckPath: /api/health` in `render.yaml` + Dockerfile
  `HEALTHCHECK`. Fail-fast semantics unchanged: a dead engine still 503s and
  still fails the check.

## 5. Secrets hygiene (live URL)

Verified clean: response headers (CSP/HSTS/nosniff/X-Frame-Options DENY, no
CORS, no server-version leak beyond `uvicorn` + `cloudflare`); `/docs`,
`/redoc`, `/openapi.json` all 404; 404/422 bodies leak-free; the 422 handler
strips the raw-input echo; 400/403/413 details interpolate only user-supplied
objectids (code+test-verified; live 400/403/413 probes were unreachable
during transient 502 windows). **One real leak, now fixed**: the 503 outage
handler returned `engine unreachable: {exc}` and the raw redis-py message
embeds the engine **host:port**; it now reports the exception class only
(`engine unreachable: ConnectionError`). Two non-code hygiene flags for the
owner: (a) the FalkorDB Cloud **password is 7 characters** — rotate it (then
update the service env; never commit it); (b) the Render API key used for
this audit exists in plaintext in local Hermes log files — keep the machine
closed or rotate the key. No secret is in the repo: `render.yaml` keeps
`sync: false` and the API env-var list contains only the six `SEVER_*` names.

## 6. Keepalive — promised but not running

README promises a "silent 10-minute keepalive keeping both warm"
(`keepalive_silent.vbs` exists in the working root). **No scheduled task, no
startup entry, no running wscript/cscript process was found on this host.**
Free tier spins down after ~15 min idle → next request pays a ~30-60s cold
start (and the Cloud free tier stops after 1 day idle). Schedule it before
the demo.

## 7. Operator actions (not doable from this branch)

1. Merge → deploy, **then** flip the Render dashboard's Health Check Path to
   `/api/health` (the dashboard value governs the running service; the
   blueprint file only applies on a blueprint sync).
2. Rotate the 7-char engine password; update `SEVER_FALKOR_PASSWORD`.
3. Actually schedule the keepalive (Task Scheduler or Startup item).
4. Keep concurrent load low during the demo: the free Cloud tier served
   `/api/state` at 6-24s under a handful of concurrent clients — sequence
   judge/probe traffic or expect 502s and ledger wipes.
5. If durable receipts are ever required on the free tier, mirror the ledger
   into the engine (the only persistent store in this architecture) —
   proposed as future work, not done here.

## 8. Changes on this branch

- `sever/console/app.py` — new `/api/health`; 503 detail sanitized
- `render.yaml`, `Dockerfile` — health path `/api/health`
- `tests/test_console_resilience.py` — health-probe + no-disclosure tests
- `README.md`, `docs/DEMO_SCRIPT.md` — ephemeral-ledger honesty, health-path
  rationale, keepalive scheduling requirement
- `docs/AUDIT_DEPLOY.md` — this report
