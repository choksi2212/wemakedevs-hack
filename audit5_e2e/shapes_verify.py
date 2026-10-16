"""audit5/live-e2e PLAN-CARD SHAPE FARM — own console on the ryzen.

Farms the deterministic plan-card shapes the shared live estate could not
guarantee under the concurrent-audit 502 storm, on a private instance of
the SAME console code (this branch) against the local FalkorDB engine:

  - breach -> plan (pristine 3-step plan) -> APPROVE PLAN -> CONFIRM PLAN
    -> completed banner ('every step matched its live re-measure') -> collapse
  - farm n=1,2,3: inject n direct hero->jewel ACE grants -> plan card shows
    EXACTLY n steps -> CONFIRM PLAN -> completed -> reach 0
  - empty plan on the collapsed surface (note + no APPROVE PLAN button)

Screenshots per shape; cleanup (GRAPH.DELETE + ledger file) in finally.
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

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SHOTS = os.path.join(HERE, "shape_shots")
os.makedirs(SHOTS, exist_ok=True)
GRAPH = "sever_audit5_e2e_own2"
PORT = 8381
BASE = "http://127.0.0.1:%d" % PORT
VENV_PY = r"N:\wemakedev\venv\Scripts\python.exe"
SAMPLE = r"N:\wemakedev\data\ad_sample"
HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
JEWELS = [
    "S-1-5-21-2697957641-2271029196-387917394-512",
    "S-1-5-21-2697957641-2271029196-387917394-519",
    "S-1-5-21-2845847946-3451170323-4261139666-512",
    "S-1-5-21-3702535222-3822678775-2090119576-512",
    "S-1-5-21-3702535222-3822678775-2090119576-519",
]

results = {"checks": [], "shots": [], "console_errors": []}


def check(name, ok, detail=""):
    results["checks"].append({"check": name, "ok": bool(ok), "detail": detail[:300]})
    print(("PASS " if ok else "FAIL ") + name + (" :: " + detail[:180] if detail else ""), flush=True)


def save():
    with open(os.path.join(HERE, "shape_results.json"), "w", encoding="utf-8") as f:
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


log = open(os.path.join(HERE, "shape_console.log"), "w", encoding="utf-8")
proc = subprocess.Popen(
    [VENV_PY, "-m", "uvicorn", "sever.console.app:app", "--host", "127.0.0.1", "--port", str(PORT)],
    cwd=REPO, stdout=log, stderr=subprocess.STDOUT,
    env={**os.environ, "SEVER_FALKOR_HOST": "127.0.0.1", "SEVER_FALKOR_PORT": "6379",
         "SEVER_FALKOR_GRAPH": GRAPH, "SEVER_SAMPLE_DIR": SAMPLE, "PYTHONUNBUFFERED": "1"})
try:
    for _ in range(120):
        try:
            if http("/api/state")[0] == 200:
                break
        except Exception:  # noqa: BLE001
            time.sleep(1.0)
    else:
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
            " return c && c.innerText && !c.innerText.includes('loading'); }", timeout=45000)

        def shot(name):
            page.screenshot(path=os.path.join(SHOTS, name + ".png"))
            results["shots"].append(name)
            print("[shot]", name, flush=True)

        def plan(n_steps=None, timeout=60000):
            page.click("#btn-plan", timeout=15000)
            cond = ("(n) => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
                    " && document.querySelectorAll('#plan-body .prop-row').length === n")
            page.wait_for_function(cond, arg=n_steps if n_steps is not None else 1, timeout=timeout)

        def confirm_expect_completed(tag):
            page.click("#btn-plan-approve", timeout=15000)
            page.wait_for_selector("#btn-plan-confirm", timeout=10000)
            page.click("#btn-plan-confirm", timeout=15000)
            page.wait_for_function(
                "() => { const b = document.getElementById('banner');"
                " return b && (b.innerText.includes('PLAN RECEIPT') || b.innerText.includes('plan execution failed')); }",
                timeout=120000)
            banner = page.eval_on_selector("#banner", "el => el.innerText")
            shot("shape_%s_receipt" % tag)
            return banner

        # ---- 0: breach + pristine plan + execute to completion ----
        http("/api/finding", {"kind": "credential_breach", "subject": HERO})
        page.click("#btn-refresh")
        page.wait_for_function("() => document.getElementById('reach').innerText.trim() === '1'", timeout=45000)
        st, pl = http("/api/plan")
        pristine_steps = len(pl.get("steps", []))
        plan(pristine_steps)
        rows = page.eval_on_selector_all("#plan-body .prop-row", "els => els.map(e => e.innerText.replace(/\\n/g,' | '))")
        shot("shape_pristine_plan")
        check("pristine plan rendered", pristine_steps >= 1,
              "steps=%d rows=%s" % (pristine_steps, [r[:80] for r in rows]))
        banner = confirm_expect_completed("pristine")
        check("pristine plan executed completed", "completed" in banner and "every step matched" in banner,
              banner.replace("\n", " | ")[:220])
        page.wait_for_function("() => document.getElementById('reach').innerText.trim() === '0'", timeout=60000)
        check("estate collapsed after pristine plan", True, "reach=0")

        # ---- farm n=1,2,3 ----
        for n, name in ((1, "onestep"), (2, "twostep"), (3, "threestep")):
            for j in JEWELS[1:1 + n]:
                http("/api/finding", {"kind": "ace_granted", "subject": HERO, "target": j, "rel": "GENERIC_ALL"})
            plan(n)
            body = page.eval_on_selector("#plan-body", "el => el.innerText.replace(/\\n/g,' | ')")
            rows = page.eval_on_selector_all("#plan-body .prop-row", "els => els.map(e => e.innerText.replace(/\\n/g,' | '))")
            shot("shape_%s_plan" % name)
            check("%s plan card shows exactly %d step(s)" % (name, n), len(rows) == n, body[:260])
            banner = confirm_expect_completed(name)
            check("%s plan executed completed" % name, "completed" in banner and "every step matched" in banner,
                  banner.replace("\n", " | ")[:200])
            page.wait_for_function("() => document.getElementById('reach').innerText.trim() === '0'", timeout=60000)
            check("collapsed after %s plan" % name, True, "reach=0")

        # ---- empty plan on the collapsed surface ----
        page.click("#btn-plan", timeout=15000)
        page.wait_for_function(
            "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
            " && document.getElementById('plan-body').innerText.includes('nothing to plan')", timeout=60000)
        empty_body = page.eval_on_selector("#plan-body", "el => el.innerText.replace(/\\n/g,' | ')")
        approve_present = page.locator("#btn-plan-approve").count()
        shot("shape_empty_plan")
        check("empty plan card renders the collapsed note",
              "surface already collapsed" in empty_body, empty_body[:260])
        check("empty plan has NO APPROVE PLAN button", approve_present == 0, "count=%d" % approve_present)

        # receipts card: plan + plan execute lines present
        page.click("#btn-refresh")
        page.wait_for_function("() => document.querySelectorAll('#receipts .entry').length > 0", timeout=45000)
        entries = page.eval_on_selector_all("#receipts .entry", "els => els.map(e => e.innerText.replace(/\\n/g,' | '))")
        plan_lines = [e for e in entries if "plan" in e.lower()]
        shot("shape_receipts_final")
        check("receipts ledger shows plan + plan execute lines", len(plan_lines) >= 6,
              "plan-ish lines=%d of %d" % (len(plan_lines), len(entries)))
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
    except Exception as e:  # noqa: BLE001
        print("ledger cleanup:", str(e)[:80], flush=True)
    save()
    print("SHAPES DONE", flush=True)
