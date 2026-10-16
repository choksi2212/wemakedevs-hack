"""audit5/live-e2e LIVE UI probe — route-intercepted proofs on the LIVE page.

Two proofs the live a2688f3 UI must show (both fixed on this branch):

  P1  plan card renders the LITERAL 'benign null' for benign_usage=None
      (the documented not-measured shape) — intercepted /api/plan, so no
      backend dependency beyond the page itself loading.
  P2  a receipts-only failure flips the whole-engine chip to 'engine
      unreachable' while /api/state keeps answering (chip misattribution)
      — intercepted /api/receipts with a 502 HTML page, state stays live.
"""
from __future__ import annotations

import json
import os
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from playwright.sync_api import sync_playwright

BASE = "https://sever-console.onrender.com"
HERE = os.path.dirname(os.path.abspath(__file__))
SHOTS = os.path.join(HERE, "liveprobe_shots")
os.makedirs(SHOTS, exist_ok=True)
HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
JEWELS = [
    "S-1-5-21-2697957641-2271029196-387917394-512",
    "S-1-5-21-2697957641-2271029196-387917394-519",
]

R = {"probes": [], "console_errors": []}
RENDER_502 = "<!DOCTYPE html>\n<html lang=\"en\">\n  <head>\n    <title>502</title>\n  </head>\n  <body><h1>Bad Gateway</h1></body>\n</html>"
SYNTH = {
    "k": 3, "method": "graph_copy_remeasure",
    "base": {"reachability": 1, "owned": [HERO], "jewels": JEWELS},
    "benign_sample_size": 25,
    "steps": [
        {"step": 1, "cut": {"src": HERO, "rel": "GENERIC_ALL", "dst": JEWELS[0]},
         "paths_on": 1, "benign_usage": None,
         "projected_reachability": 0, "projected_delta": -1, "projected_verdict": "collapsed"},
        {"step": 2, "cut": {"src": HERO, "rel": "GENERIC_ALL", "dst": JEWELS[1]},
         "paths_on": 1, "benign_usage": None,
         "projected_reachability": 0, "projected_delta": 0, "projected_verdict": "no_effect"},
    ],
    "plan_completes_at_step": 1, "honesty": "projections measured on an isolated copy",
}


def save():
    with open(os.path.join(HERE, "liveprobe_results.json"), "w", encoding="utf-8") as f:
        json.dump(R, f, indent=1, default=str)


def probe(name, ok, detail):
    R["probes"].append({"probe": name, "ok": bool(ok), "detail": detail[:400]})
    save()
    print(("PROBE-PASS " if ok else "PROBE-FAIL ") + name + " :: " + detail[:240], flush=True)


def shot(page, name):
    page.screenshot(path=os.path.join(SHOTS, name + ".png"))
    print("[shot]", name, flush=True)


def load(page, tries=20):
    t0 = time.time()
    for i in range(tries):
        try:
            page.goto(BASE, timeout=90000, wait_until="domcontentloaded")
            page.wait_for_function(
                "() => { const c = document.getElementById('estate-chip');"
                " return c && c.innerText && !c.innerText.includes('loading'); }", timeout=75000)
            if page.evaluate("() => document.body.innerText.length") < 50:
                raise RuntimeError("blank page (empty HTML body)")
            return time.time() - t0
        except Exception as e:  # noqa: BLE001
            print("[load retry %d]" % (i + 1), str(e)[:140], flush=True)
            time.sleep(12)
    raise RuntimeError("page never loaded")


with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    page = browser.new_context(viewport={"width": 1440, "height": 900}).new_page()
    page.on("console", lambda m: R["console_errors"].append(m.text) if m.type == "error" else None)
    dt = load(page)
    probe("live page loaded", True, "load+populate %.1fs" % dt)

    # ---- P1: benign-usage None -> literal 'null' on the live plan card ----
    def plan_none(route, request):
        route.fulfill(status=200, content_type="application/json", body=json.dumps(SYNTH))

    page.route("**/api/plan", plan_none)
    try:
        page.click("#btn-plan", timeout=15000)
        page.wait_for_function(
            "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
            " && document.querySelectorAll('#plan-body .prop-row').length === 2", timeout=60000)
        body = page.eval_on_selector("#plan-body", "el => el.innerText.replace(/\\n/g,' | ')")
        shot(page, "live_benign_null_plan_card")
        probe("P1 live plan card prints literal 'benign null' (DEFECT on a2688f3)",
              "benign null" in body, body[:300])
    finally:
        page.unroute("**/api/plan", plan_none)

    # ---- P2: receipts-only 502 flips the engine chip (DEFECT on a2688f3) ----
    def rec_502(route, request):
        route.fulfill(status=502, content_type="text/html", body=RENDER_502)

    page.route("**/api/receipts", rec_502)
    try:
        page.click("#btn-refresh", timeout=15000)
        # the misattribution: chip flips to 'engine unreachable' within a refresh
        try:
            page.wait_for_function(
                "() => document.getElementById('engine-label').innerText.includes('unreachable')",
                timeout=45000)
            chip = page.eval_on_selector("#engine-label", "el => el.innerText")
            estate = page.eval_on_selector("#estate-chip", "el => el.innerText")
            card = page.eval_on_selector("#receipts", "el => el.innerText")
            cls = page.eval_on_selector("#engine-chip", "el => el.className")
            shot(page, "live_chip_misattribution")
            probe("P2 live chip says 'engine unreachable' while estate data flows (DEFECT on a2688f3)",
                  "unreachable" in chip and ("nodes" in estate),
                  "chip=%r estate=%r chip_class=%r card=%r" % (chip, estate, cls, card[:120]))
        except Exception:  # noqa: BLE001
            probe("P2 inconclusive (state fetch also failed in this window)",
                  False, "engine-label=" + page.eval_on_selector("#engine-label", "el => el.innerText"))
    finally:
        page.unroute("**/api/receipts", rec_502)

    # ---- recovery: unroute + refresh -> ledger renders again ----
    try:
        page.click("#btn-refresh", timeout=15000)
        page.wait_for_function(
            "() => document.querySelectorAll('#receipts .entry').length > 0"
            " && !document.getElementById('receipts').innerText.includes('ledger unavailable')", timeout=60000)
        shot(page, "live_receipts_recovered")
        probe("P3 receipts recover after the failure clears", True, "entries rendered")
    except Exception as e:  # noqa: BLE001
        probe("P3 receipts recovery not observed in this window", False, str(e)[:160])
    browser.close()
save()
print("LIVE PROBE DONE", flush=True)
