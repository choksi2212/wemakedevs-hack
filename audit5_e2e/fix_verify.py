"""audit5/live-e2e FIX VERIFICATION — own console on the ryzen (playwright).

Boots the FIXED worktree's console (uvicorn :8380, graph sever_audit5_e2e_own,
local engine) and drives the fixed UI in headless Chromium (1440x900):

  F1  api() HTML guard: a 502 whose body is a proxy HTML error page must
      surface as 'server error 502 (HTML error page)', never raw markup.
  F3  receipts-only failure degrades the CARD ('ledger unavailable — …')
      while the engine chip stays green — not 'engine unreachable'.
  F2/F3 recovery: once receipts answers again the ledger renders.
  F4  plan card benign_usage=None renders 'benign not measured', never
      the literal 'null'.
  F5  CONFIRM PLAN disables immediately (double-press cannot double-execute).

Run from the synced FIXED worktree dir on the ryzen, ONE ssh session:
  N:/wemakedev/venv/Scripts/python.exe fix_verify.py
"""
from __future__ import annotations

import sys as _sys
try:
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))       # <repo>/audit5_e2e
REPO = os.path.dirname(HERE)                             # the synced repo root
SHOTS = os.path.join(HERE, "fix_shots")
os.makedirs(SHOTS, exist_ok=True)
GRAPH = "sever_audit5_e2e_own"
PORT = 8380
BASE = "http://127.0.0.1:%d" % PORT
VENV_PY = r"N:\wemakedev\venv\Scripts\python.exe"
SAMPLE = r"N:\wemakedev\data\ad_sample"

results = {"checks": [], "shots": [], "console_errors": []}


def check(name, ok, detail=""):
    results["checks"].append({"check": name, "ok": bool(ok), "detail": detail[:300]})
    print(("PASS " if ok else "FAIL ") + name + (" :: " + detail[:200] if detail else ""), flush=True)


def save():
    with open(os.path.join(HERE, "fix_verify_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1)


def http(path, body=None, timeout=90):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"} if body is not None else {},
        method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode() or "null")


def drop_graph():
    try:
        from falkordb import FalkorDB
        fdb = FalkorDB(host="127.0.0.1", port=6379)
        fdb.execute_command("GRAPH.DELETE", GRAPH)
    except Exception as e:  # noqa: BLE001
        print("graph cleanup:", str(e)[:120], flush=True)


RENDER_502 = "<!DOCTYPE html>\n<html lang=\"en\">\n  <head>\n    <title>502</title>\n  </head>\n  <body><h1>Bad Gateway</h1></body>\n</html>"

log = open(os.path.join(HERE, "fix_console.log"), "w", encoding="utf-8")
proc = subprocess.Popen(
    [VENV_PY, "-m", "uvicorn", "sever.console.app:app", "--host", "127.0.0.1", "--port", str(PORT)],
    cwd=REPO, stdout=log, stderr=subprocess.STDOUT,
    env={**os.environ, "SEVER_FALKOR_HOST": "127.0.0.1", "SEVER_FALKOR_PORT": "6379",
         "SEVER_FALKOR_GRAPH": GRAPH, "SEVER_SAMPLE_DIR": SAMPLE, "PYTHONUNBUFFERED": "1"})
try:
    ready = False
    for _ in range(120):
        try:
            if http("/api/state")[0] == 200:
                ready = True
                break
        except Exception:  # noqa: BLE001
            time.sleep(1.0)
    if not ready:
        print("console did not come up", flush=True)
        sys.exit(2)

    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_context(viewport={"width": 1440, "height": 900}).new_page()
        page.on("console", lambda m: results["console_errors"].append(m.text) if m.type == "error" else None)
        page.goto(BASE, timeout=60000)
        page.wait_for_function(
            "() => { const c = document.getElementById('estate-chip');"
            " return c && c.innerText && !c.innerText.includes('loading'); }", timeout=30000)

        def shot(name):
            page.screenshot(path=os.path.join(SHOTS, name + ".png"))
            results["shots"].append(name)
            print("[shot]", name, flush=True)

        # ---- F1: HTML 502 body -> clean copy, never raw markup ----
        def html_502(route, request):
            route.fulfill(status=502, content_type="text/html", body=RENDER_502)

        page.route("**/api/finding", html_502)
        page.click("#btn-breach")
        page.wait_for_function(
            "() => document.getElementById('banner').classList.contains('show')", timeout=20000)
        time.sleep(0.3)
        banner = page.eval_on_selector("#banner", "el => el.innerText")
        shot("fix01_html_502_banner")
        check("F1 no raw HTML in banner", "<!DOCTYPE" not in banner and "<html" not in banner, banner)
        check("F1 clean server-error copy", "server error 502 (HTML error page)" in banner, banner)
        page.unroute("**/api/finding", html_502)

        # ---- F3: receipts-only failure -> card degrades, chip stays green ----
        def rec_502(route, request):
            route.fulfill(status=502, content_type="text/html", body=RENDER_502)

        page.route("**/api/receipts", rec_502)
        page.click("#btn-refresh")
        page.wait_for_function(
            "() => document.getElementById('receipts').innerText.includes('ledger unavailable')", timeout=45000)
        card = page.eval_on_selector("#receipts", "el => el.innerText")
        chip = page.eval_on_selector("#engine-label", "el => el.innerText")
        chip_cls = page.eval_on_selector("#engine-chip", "el => el.className")
        shot("fix02_ledger_degraded_card")
        check("F3 card shows ledger unavailable", "ledger unavailable" in card, card[:200])
        check("F3 chip NOT engine-unreachable", "unreachable" not in chip, chip)
        check("F3 chip stays green", chip_cls == "chip", chip_cls)
        page.unroute("**/api/receipts", rec_502)

        # ---- F3 recovery: ledger renders again ----
        page.click("#btn-refresh")
        page.wait_for_function(
            "() => document.querySelectorAll('#receipts .entry').length > 0", timeout=45000)
        shot("fix03_ledger_recovers")
        check("F3 recovery ledger renders", True,
              page.eval_on_selector("#receipts", "el => el.innerText")[:120])

        # ---- F4: benign_usage None -> 'benign not measured', never 'null' ----
        HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
        synthetic = {
            "k": 3, "method": "graph_copy_remeasure",
            "base": {"reachability": 1, "owned": [HERO], "jewels": []},
            "benign_sample_size": 25,
            "steps": [
                {"step": 1, "cut": {"src": HERO, "rel": "GENERIC_ALL",
                                    "dst": "S-1-5-21-2697957641-2271029196-387917394-512"},
                 "paths_on": 1, "benign_usage": None,
                 "projected_reachability": 0, "projected_delta": -1,
                 "projected_verdict": "collapsed"},
            ],
            "plan_completes_at_step": 1, "honesty": "honest",
        }

        def plan_none(route, request):
            route.fulfill(status=200, content_type="application/json", body=json.dumps(synthetic))

        page.route("**/api/plan", plan_none)
        page.click("#btn-plan")
        page.wait_for_function(
            "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
            " && document.getElementById('plan-body').innerText.length > 10", timeout=60000)
        body = page.eval_on_selector("#plan-body", "el => el.innerText")
        shot("fix04_benign_none_plan_card")
        check("F4 no literal 'benign null'", "benign null" not in body, body[:200])
        check("F4 honest not-measured copy", "benign not measured" in body, body[:200])
        page.unroute("**/api/plan", plan_none)

        # ---- F5: CONFIRM PLAN disables immediately (real plan, real POST) ----
        # real breach first so the own-instance estate has paths to plan against
        HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
        st, fr = http("/api/finding", {"kind": "credential_breach", "subject": HERO})
        check("own-instance breach applied", st == 200 and fr.get("reachability") == 1,
              "reach=%s" % fr.get("reachability"))
        page.click("#btn-refresh")
        page.wait_for_function("() => document.getElementById('reach').innerText.trim() === '1'", timeout=45000)
        page.click("#btn-plan")
        page.wait_for_function(
            "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
            " && document.querySelectorAll('#plan-body .prop-row').length > 0", timeout=90000)
        page.click("#btn-plan-approve")
        page.wait_for_selector("#btn-plan-confirm", timeout=10000)
        page.click("#btn-plan-confirm")
        disabled_now = page.eval_on_selector("#btn-plan-confirm", "el => el.disabled")
        shot("fix05_confirm_plan_disabled")
        check("F5 CONFIRM PLAN disabled immediately after press", disabled_now is True, "disabled=%r" % disabled_now)
        page.wait_for_function(
            "() => { const b = document.getElementById('banner'); return b && (b.innerText.includes('PLAN RECEIPT') || b.innerText.includes('plan execution failed')); }",
            timeout=120000)
        banner = page.eval_on_selector("#banner", "el => el.innerText")
        shot("fix06_plan_receipt")
        check("F5 plan executed once with receipt", "PLAN RECEIPT" in banner, banner[:200])
        st, state = http("/api/state")
        check("estate collapsed after plan (own instance)", state.get("reachability") == 0,
              "reach=%s" % state.get("reachability"))
        browser.close()
    save()
finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001
        proc.kill()
    drop_graph()
    try:
        lg = os.path.join(REPO, "out", "cases", GRAPH + ".jsonl")
        if os.path.exists(lg):
            os.remove(lg)
            print("ledger file removed", flush=True)
    except Exception as e:  # noqa: BLE001
        print("ledger cleanup:", str(e)[:80], flush=True)
    save()
    print("VERIFY DONE", flush=True)
