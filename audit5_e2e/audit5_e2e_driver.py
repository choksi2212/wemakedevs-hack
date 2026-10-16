"""audit5/live-e2e — LIVE E2E journey driver (runs ON the ryzen, Playwright headless).

Drives https://sever-console.onrender.com exactly as a real operator in a real
browser (Chromium headless, 1440x900). Zero-tolerance JS console-error listener,
screenshot per state transition, timing of every action, and full DEMO_SCRIPT.md
click-path coverage incl. the APPROVE->CONFIRM human gates and every plan-card
shape (empty / 1 / 2 / 3-step / drift-stopped / benign-usage None).

Part A: initial load -> breach -> grant -> refresh toggle -> single-cut gate
        (arm / Escape / re-arm / CONFIRM) -> 15s-tick gate survival -> reload
        mid-flow -> plan #1 -> plan gate cancel -> mid-plan estate mutation ->
        CONFIRM PLAN (drift) -> re-plan -> CONFIRM PLAN (completed) ->
        collapse loop -> receipts card check.
Part B: reach==0 assert -> farm deterministic 1/2/3-step plans via authorized
        ACE grants -> empty plan card -> benign-usage None renderer probe
        (route-intercepted /api/plan) -> final receipts/chips audit.

Usage:  python audit5_e2e_driver.py --part A|B --out <dir>
Env:    PLAYWRIGHT_BROWSERS_PATH must point at the browsers (set by caller).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

BASE = "https://sever-console.onrender.com"
HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
JEWELS = [
    "S-1-5-21-2697957641-2271029196-387917394-512",
    "S-1-5-21-2697957641-2271029196-387917394-519",
    "S-1-5-21-2845847946-3451170323-4261139666-512",
    "S-1-5-21-3702535222-3822678775-2090119576-512",
    "S-1-5-21-3702535222-3822678775-2090119576-519",
]

ap = argparse.ArgumentParser()
ap.add_argument("--part", choices=["A", "B"], required=True)
ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
args = ap.parse_args()

OUT = args.out
SHOTS = os.path.join(OUT, "shots")
os.makedirs(SHOTS, exist_ok=True)


def J(path):
    return os.path.join(OUT, path)


R = {
    "meta": {"base": BASE, "part": args.part, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "viewport": "1440x900", "headless": True},
    "timings": {}, "steps": [], "console_errors": [], "console_warnings": [],
    "page_errors": [], "request_failures": [], "api_calls": [],
    "defects": [], "observations": [],
}


def save():
    with open(J("e2e_results_%s.json" % args.part), "w", encoding="utf-8") as f:
        json.dump(R, f, indent=1, default=str)


def step(name, **kw):
    R["steps"].append({"step": name, "t_utc": time.strftime("%H:%M:%SZ", time.gmtime()), **kw})
    save()
    print("[step]", name, json.dumps(kw, default=str)[:400], flush=True)


def timing(name, dt):
    R["timings"][name] = round(dt, 2)
    save()


def defect(name, evidence):
    R["defects"].append({"defect": name, "evidence": evidence, "t_utc": time.strftime("%H:%M:%SZ", time.gmtime())})
    save()
    print("[DEFECT]", name, "|", evidence, flush=True)


def observe(name, detail):
    R["observations"].append({"obs": name, "detail": detail, "t_utc": time.strftime("%H:%M:%SZ", time.gmtime())})
    save()


# ---------------- HTTP helpers (driver-side, authorized mutations) ----------------

def _http(path, body=None, tries=6, timeout=75):
    last = None
    for i in range(tries):
        req = urllib.request.Request(
            BASE + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"} if body is not None else {},
            method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", "replace")
                if not raw.strip():
                    raise RuntimeError("empty 200 body (engine stall signature)")
                return r.status, json.loads(raw)
        except Exception as e:  # noqa: BLE001 — record and retry, live deployment is unstable
            last = "%s: %s" % (type(e).__name__, str(e)[:180])
            R["api_calls"].append({"url": path, "status": "driver-retry", "error": last,
                                   "t_utc": time.strftime("%H:%M:%SZ", time.gmtime())})
            save()
            time.sleep(6)
    raise RuntimeError("HTTP %s failed after %d tries: %s" % (path, tries, last))


def api_state():
    st, body = _http("/api/state")
    return body


def inject_grant(target, rel="GENERIC_ALL"):
    """Authorized live mutation: hero -> target ACE, the 'estate mutated mid-plan' scenario."""
    st, body = _http("/api/finding", {"kind": "ace_granted", "subject": HERO,
                                       "target": target, "rel": rel})
    return body


# ---------------- browser setup ----------------

cur = {"label": "boot"}
req_t = {}


def _on_request(r):
    if "/api/" in r.url:
        req_t[id(r)] = time.time()


def _on_response(r):
    if "/api/" in r.url:
        t0 = req_t.pop(id(r), None)
        R["api_calls"].append({
            "label": cur["label"], "url": r.url.split("onrender.com")[1], "status": r.status,
            "dt_s": round(time.time() - t0, 2) if t0 else None,
            "t_utc": time.strftime("%H:%M:%SZ", time.gmtime())})
        save()


def _on_console(m):
    if m.type == "error":
        R["console_errors"].append({"label": cur["label"], "text": m.text})
        defect("JS console error (zero-tolerance)", "%s :: %s" % (cur["label"], m.text[:300]))
        save()
    elif m.type == "warning":
        R["console_warnings"].append({"label": cur["label"], "text": m.text})


def _on_pageerror(e):
    R["page_errors"].append({"label": cur["label"], "error": str(e)})
    defect("uncaught page JS exception", "%s :: %s" % (cur["label"], str(e)[:300]))
    save()


def _on_requestfailed(r):
    R["request_failures"].append({"label": cur["label"], "url": r.url, "failure": str(r.failure)})
    save()


def shot(page, name, full=False, locator=None):
    path = os.path.join(SHOTS, name + ".png")
    try:
        if locator is not None:
            page.locator(locator).screenshot(path=path)
        else:
            page.screenshot(path=path, full_page=full)
        print("[shot]", name, flush=True)
    except Exception as e:  # noqa: BLE001
        print("[shot-fail]", name, str(e)[:120], flush=True)


def wait_banner(page, contains, timeout=90000):
    t0 = time.time()
    page.wait_for_function(
        """(needle) => { const b = document.getElementById('banner');
             return b && b.classList.contains('show') && b.innerText.includes(needle); }""",
        arg=contains, timeout=timeout)
    return time.time() - t0


def wait_banner_either(page, ok, fail, timeout=120000):
    """Wait until the banner shows the success needle OR a failure line;
    returns (banner_text, ok_bool). Under live 502 storms a failed POST
    paints the banner in <1s — a success-only wait would burn the whole
    timeout per attempt."""
    t0 = time.time()
    page.wait_for_function(
        """(pair) => { const b = document.getElementById('banner');
             return b && b.classList.contains('show') &&
               (b.innerText.includes(pair[0]) || b.innerText.includes(pair[1])); }""",
        arg=[ok, fail], timeout=timeout)
    bt = banner_text(page)
    return bt, (ok in bt)


def banner_text(page):
    return (page.eval_on_selector("#banner", "el => el.innerText") or "").strip()


def reach_value(page):
    return page.eval_on_selector(
        "#reach",
        "el => el ? ({text: el.innerText, cls: el.className}) : ({text: '?', cls: ''})")


def estate_chip(page):
    return page.eval_on_selector("#estate-chip", "el => el ? el.innerText : '(missing)'")


def engine_label(page):
    return page.eval_on_selector("#engine-label", "el => el ? el.innerText : '(missing)'")


def ui_counts(page):
    return page.evaluate(
        """() => { const pc = document.getElementById('plan-card');
             return {paths: document.querySelectorAll('#paths .path-block').length,
                     proposals: document.querySelectorAll('#proposal .prop-row').length,
                     receipts: document.querySelectorAll('#receipts .entry').length,
                     plan_visible: !!pc && getComputedStyle(pc).display !== 'none',
                     plan_steps: document.querySelectorAll('#plan-body .prop-row').length}; }""")


def load_page(page, tries=12):
    """goto + tolerant wait for a NON-BLANK, populated page (live worker flaps)."""
    t0 = time.time()
    for i in range(tries):
        try:
            page.goto(BASE, timeout=90000, wait_until="domcontentloaded")
            page.wait_for_function(
                "() => { const c = document.getElementById('estate-chip');"
                " return c && c.innerText && !c.innerText.includes('loading'); }",
                timeout=75000)
            dt = time.time() - t0
            timing("load_page_s", dt)
            txt = page.evaluate("() => document.body.innerText.length")
            if txt < 50:
                raise RuntimeError("page rendered blank (empty HTML body served)")
            return dt
        except Exception as e:  # noqa: BLE001
            print("[load retry %d]" % (i + 1), str(e)[:160], flush=True)
            R["steps"].append({"step": "load_retry", "attempt": i + 1, "error": str(e)[:200]})
            save()
            time.sleep(15)
    raise RuntimeError("page never loaded after %d tries" % tries)


def wait_reach(page, want, timeout=90000):
    t0 = time.time()
    page.wait_for_function("(v) => document.getElementById('reach') && document.getElementById('reach').innerText.trim() === String(v)",
                           arg=want, timeout=timeout)
    return time.time() - t0


def plan_rows(page):
    return page.eval_on_selector_all(
        "#plan-body .prop-row",
        """els => els.map(e => ({text: e.innerText.replace(/\\n/g,' | '),
             titles: Array.from(e.querySelectorAll('[title]')).map(s => s.getAttribute('title'))}))""")


def plan_body_text(page):
    return (page.eval_on_selector("#plan-body", "el => el.innerText.replace(/\\n/g,' | ')") or "")


def confirm_plan(page, timeout=150000):
    page.click("#btn-plan-approve", timeout=15000)
    gate_dt = time.time()
    page.wait_for_selector("#btn-plan-confirm", timeout=10000)
    t0 = time.time()
    page.click("#btn-plan-confirm", timeout=15000)
    page.wait_for_function(
        "() => { const b = document.getElementById('banner');"
        "  return b && (b.innerText.includes('PLAN RECEIPT') || b.innerText.includes('plan execution failed')); }",
        timeout=timeout)
    return time.time() - t0, banner_text(page)


def api_collapse(max_cuts=12):
    """SETUP-only fallback: drive reachability to 0 via direct /api/cut calls
    (authorized mutations) when the storm starves the UI gate. The audit's
    shape evidence still renders + executes through the real UI gates."""
    for i in range(max_cuts):
        try:
            st, prop = _http("/api/proposal")
        except Exception:  # noqa: BLE001
            time.sleep(6)
            continue
        if not prop:
            try:
                if api_state()["reachability"] == 0:
                    return True
            except Exception:  # noqa: BLE001
                pass
            return False
        top = prop[0]
        try:
            _http("/api/cut", {"src": top["src"], "dst": top["dst"], "rel": top["rel"],
                               "approved": True, "approved_by": "audit5-live-e2e (setup)"})
        except Exception:  # noqa: BLE001
            time.sleep(6)
            continue
        try:
            if api_state()["reachability"] == 0:
                return True
        except Exception:  # noqa: BLE001
            time.sleep(4)
    try:
        return api_state()["reachability"] == 0
    except Exception:  # noqa: BLE001
        return False


def collapse_loop(page, max_cuts=6, label="collapse"):
    """Drive reachability to 0 through the REAL single-cut gate, verdict by verdict."""
    n = 0
    while n < max_cuts:
        try:
            page.click("#btn-refresh", timeout=15000)
        except Exception:  # noqa: BLE001
            pass
        try:
            page.wait_for_selector("#proposal button.approve", timeout=20000)
        except Exception:  # noqa: BLE001
            observe(label, "no APPROVE CUT button left (proposals exhausted) at cut %d" % n)
            break
        rv = reach_value(page)["text"]
        if rv == "0":
            break
        row = page.eval_on_selector("#proposal .prop-row", "el => el.innerText.replace(/\\n/g,' ')")
        page.click("#proposal button.approve", timeout=15000)
        page.wait_for_selector("#proposal .prop-cta .confirm", timeout=10000)
        page.click("#proposal .prop-cta .confirm", timeout=15000)
        t_cut0 = time.time()
        bt, ok = wait_banner_either(page, "INTERDICTION RECEIPT", "cut failed:", timeout=150000)
        dt = time.time() - t_cut0
        if not ok:
            step("collapse_cut_failed_%d" % (n + 1), label=label, banner=bt[:200])
            time.sleep(5)
        step("collapse_cut_%d" % (n + 1), label=label, row=row[:120], banner=bt[:200], dt_s=round(dt, 2))
        try:
            wait_reach(page, "0", timeout=60000)
            break
        except Exception:  # noqa: BLE001
            n += 1
    return reach_value(page)["text"]


# ---------------- PART A ----------------

def part_a(page):
    cur["label"] = "A0_load"
    dt = load_page(page)
    st = api_state()
    counts = ui_counts(page)
    step("A0_initial_load", nav_s=round(dt, 2), state={"reach": st["reachability"], "edges": st["edges"],
         "nodes": st["nodes"], "owned": len(st["owned"])}, ui=counts,
         engine_chip=engine_label(page), estate_chip=estate_chip(page),
         title=page.title(),
         updated_at=page.eval_on_selector("#updated-at", "el => el.innerText"))
    shot(page, "01_initial_viewport")
    shot(page, "01b_initial_full", full=True)
    # docs/DEMO_SCRIPT.md beat 1: estate panel 1,480 nodes, 5 jewels
    if "1,480 nodes" not in estate_chip(page):
        defect("estate chip does not show documented 1,480 nodes", estate_chip(page))
    if st["reachability"] == 1 and counts["paths"] == 0:
        defect("reachability 1 but Attack paths card empty", "paths=%d" % counts["paths"])

    # ---- A1 breach ----
    cur["label"] = "A1_breach"
    shot(page, "02_pre_breach")
    for attempt in range(1, 11):
        t_click = time.time()
        page.click("#btn-breach", timeout=15000)
        try:
            page.wait_for_function(
                "() => document.getElementById('banner').innerText.includes('re-scoring all attack paths')",
                timeout=8000)
            timing("breach_click_to_inflight_banner_s", round(time.time() - t_click, 3))
        except Exception:  # noqa: BLE001
            observe("breach inflight banner not observed on attempt %d" % attempt, banner_text(page)[:120])
        try:
            bt, ok = wait_banner_either(page, "SIMULATED", "failed:", timeout=120000)
            if ok:
                timing("breach_click_to_result_banner_s", round(time.time() - t_click, 2))
                step("A1_breach", banner=bt[:260], attempt=attempt)
                break
            step("A1_breach_retry", attempt=attempt, banner=bt[:200])
            defect("breach finding failed (banner)", bt[:220])
            time.sleep(5)
        except Exception:  # noqa: BLE001
            step("A1_breach_retry", attempt=attempt, banner=banner_text(page)[:200])
            time.sleep(5)
    try:
        dt_r = wait_reach(page, "1", timeout=90000)
        timing("breach_click_to_reach_metric_s", round(dt_r, 2))
    except Exception as e:  # noqa: BLE001
        defect("reach metric did not update to 1 after breach", str(e)[:120] + " reach=" + reach_value(page)["text"])
    shot(page, "03_breach_result")
    shot(page, "03b_breach_full", full=True)

    # ---- A2 grant ----
    cur["label"] = "A2_grant"
    for attempt in range(1, 11):
        t_click = time.time()
        page.click("#btn-grant", timeout=15000)
        try:
            bt, ok = wait_banner_either(page, "SIMULATED", "failed:", timeout=120000)
            if ok:
                timing("grant_click_to_result_banner_s", round(time.time() - t_click, 2))
                step("A2_grant", banner=bt[:260], attempt=attempt)
                break
            step("A2_grant_retry", attempt=attempt, banner=bt[:200])
            defect("grant finding failed (banner)", bt[:220])
            time.sleep(5)
        except Exception:  # noqa: BLE001
            step("A2_grant_retry", attempt=attempt, banner=banner_text(page)[:200])
            time.sleep(5)
    shot(page, "04_grant_result")

    # ---- A3 refresh toggle ----
    cur["label"] = "A3_toggle"
    t0 = time.time()
    page.click("#refresh-toggle", timeout=15000)
    page.wait_for_function(
        "() => document.getElementById('refresh-toggle').innerText.trim() === 'paused'"
        " && document.getElementById('refresh-toggle').getAttribute('aria-pressed') === 'false'", timeout=10000)
    paused_cls = page.eval_on_selector("#refresh-chip", "el => el.className")
    timing("toggle_pause_render_s", round(time.time() - t0, 3))
    step("A3_toggle_paused", chip_class=paused_cls)
    shot(page, "05_refresh_paused")
    t0 = time.time()
    page.click("#refresh-toggle", timeout=15000)
    page.wait_for_function(
        "() => document.getElementById('refresh-toggle').innerText.trim() === 'live · auto'"
        " && document.getElementById('refresh-toggle').getAttribute('aria-pressed') === 'true'", timeout=10000)
    timing("toggle_resume_render_s", round(time.time() - t0, 3))
    step("A3_toggle_resumed")
    if "paused" in paused_cls:
        observe("refresh chip gains .paused class while paused", paused_cls)

    # ---- A4 single-cut human gate ----
    cur["label"] = "A4_gate"
    try:
        page.click("#btn-refresh", timeout=15000)
    except Exception:  # noqa: BLE001
        pass
    try:
        page.wait_for_selector("#proposal button.approve", timeout=30000)
    except Exception:  # noqa: BLE001
        inj = inject_grant(JEWELS[0])
        step("A4_surface_reopened", inject=inj.get("finding"), reach=inj.get("reachability"))
        page.click("#btn-refresh", timeout=15000)
        page.wait_for_selector("#proposal button.approve", timeout=30000)
    row = page.eval_on_selector("#proposal .prop-row", "el => el.innerText.replace(/\\n/g,' ')")
    t0 = time.time()
    page.click("#proposal button.approve", timeout=15000)
    page.wait_for_selector("#proposal .prop-cta .confirm", timeout=10000)
    gate_dt = time.time() - t0
    timing("approve_cut_to_confirm_gate_s", round(gate_dt, 3))
    cancel_visible = page.locator("#proposal .prop-cta .cancel").count()
    step("A4_gate_armed", row=row[:140], gate_render_s=round(gate_dt, 3), cancel_buttons=cancel_visible)
    shot(page, "06_gate_armed")

    # 15s auto-refresh tick while armed: gate must survive the DOM re-render
    cur["label"] = "A4b_tick"
    tick0 = len([c for c in R["api_calls"] if c.get("label") == cur["label"]])
    time.sleep(17.0)
    still_armed = page.locator("#proposal .prop-cta .confirm").count() > 0
    state_calls = [c for c in R["api_calls"] if c["url"] == "/api/state" and c.get("label") == "A4b_tick"]
    step("A4b_gate_survives_15s_tick", still_armed=still_armed, tick_state_calls=len(state_calls))
    if not still_armed:
        defect("armed CONFIRM gate wiped by 15s auto-refresh", "screenshot 07 + api_calls")
    shot(page, "07_gate_after_tick")

    # Escape disarms
    cur["label"] = "A4c_escape"
    page.keyboard.press("Escape")
    try:
        page.wait_for_function(
            "() => document.querySelectorAll('#proposal button.approve').length > 0"
            " && document.querySelectorAll('#proposal .prop-cta .confirm').length === 0", timeout=10000)
        step("A4c_escape_disarms_gate")
    except Exception:  # noqa: BLE001
        defect("Escape does not disarm the CONFIRM gate", "screenshot 08")
    shot(page, "08_gate_disarmed")

    # re-arm and CONFIRM for real
    cur["label"] = "A4d_confirm"
    page.click("#proposal button.approve", timeout=15000)
    page.wait_for_selector("#proposal .prop-cta .confirm", timeout=10000)
    t_click = time.time()
    page.click("#proposal .prop-cta .confirm", timeout=15000)
    bt, ok = wait_banner_either(page, "INTERDICTION RECEIPT", "cut failed:", timeout=150000)
    dt_res = time.time() - t_click
    timing("confirm_cut_to_receipt_banner_s", round(dt_res, 2))
    if not ok:
        defect("CONFIRM CUT ended in failure banner", bt[:220])
    step("A4d_cut_executed", banner=bt[:260], click_to_receipt_s=round(time.time() - t_click, 2))
    shot(page, "09_cut_receipt")
    shot(page, "09b_cut_receipt_full", full=True)
    if "collapsed" in bt:
        observe("single top-proposal cut COLLAPSED the surface (docs say DEGRADED expected)", bt[:160])

    # ---- A5 reload mid-flow ----
    cur["label"] = "A5_reload"
    t0 = time.time()
    reloaded_ok = False
    for rload in range(1, 4):
        try:
            if rload == 1:
                page.reload(timeout=90000, wait_until="domcontentloaded")
            else:
                page.goto(BASE, timeout=90000, wait_until="domcontentloaded")
            page.wait_for_function(
                "() => { const c = document.getElementById('estate-chip');"
                " return c && c.innerText && !c.innerText.includes('loading'); }", timeout=75000)
            txt = page.evaluate("() => document.body.innerText.length")
            if txt < 50:
                raise RuntimeError("reload landed on a BLANK page (empty HTML body served)")
            reloaded_ok = True
            timing("reload_to_populated_s", round(time.time() - t0, 2))
            break
        except Exception as e:  # noqa: BLE001
            step("A5_reload_retry", attempt=rload, error=str(e)[:180])
            time.sleep(10)
    if not reloaded_ok:
        defect("reload mid-flow never repopulated the page (blank/502 window)",
               "see A5_reload_retry steps; live worker instability")
    counts = ui_counts(page)
    gate_gone = page.locator("#proposal .prop-cta .confirm").count() == 0
    step("A5_after_reload", ui=counts, gate_disarmed=gate_gone,
         engine_chip=engine_label(page), reach=reach_value(page))
    shot(page, "10_after_reload")
    if not gate_gone:
        defect("armed gate survived page reload (unexpected persistence)", "check 10_after_reload")
    if counts["receipts"] == 0:
        observe("receipts card empty after reload (ledger fetch failing?)", "")

    # ---- A6 plan #1 ----
    cur["label"] = "A6_plan1"
    for attempt in range(1, 4):
        t_click = time.time()
        page.click("#btn-plan", timeout=15000)
        try:
            page.wait_for_function(
                "() => document.getElementById('banner').innerText.includes('planning a k=3 cut sequence')",
                timeout=8000)
            timing("plan_click_to_inflight_banner_s", round(time.time() - t_click, 3))
        except Exception:  # noqa: BLE001
            observe("plan inflight banner not seen (attempt %d)" % attempt, banner_text(page)[:100])
        try:
            page.wait_for_function(
                "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
                " && document.getElementById('plan-body').innerText.length > 10", timeout=150000)
            dt_card = time.time() - t_click
            timing("plan_click_to_card_s", round(dt_card, 2))
            break
        except Exception:  # noqa: BLE001
            bt = banner_text(page)
            step("A6_plan_retry", attempt=attempt, banner=bt[:200])
            if "plan failed" in bt:
                defect("GET /api/plan failed (banner)", bt[:220])
            time.sleep(10)
    rows = plan_rows(page)
    if not rows:
        # surface already collapsed (e.g. the A4 cut won more than expected):
        # reopen with a fresh direct grant so the multi-step flow can proceed
        inj = inject_grant(JEWELS[0])
        step("A6_surface_reopened", inject=inj.get("finding"), reach=inj.get("reachability"))
        page.click("#btn-plan", timeout=15000)
        page.wait_for_function(
            "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
            " && document.querySelectorAll('#plan-body .prop-row').length > 0", timeout=150000)
        rows = plan_rows(page)
    meta = plan_body_text(page)[:600]
    step("A6_plan1_rendered", steps=len(rows), rows=[r["text"][:150] for r in rows], meta=meta)
    shot(page, "11_plan1_card", locator="#plan-card")
    shot(page, "11b_plan1_full", full=True)

    # ---- A7 plan gate + cancel ----
    cur["label"] = "A7_plan_gate"
    t0 = time.time()
    page.click("#btn-plan-approve", timeout=15000)
    page.wait_for_selector("#btn-plan-confirm", timeout=10000)
    timing("approve_plan_to_confirm_gate_s", round(time.time() - t0, 3))
    shot(page, "12_plan_gate_armed")
    page.click("#btn-plan-cancel", timeout=15000)
    try:
        page.wait_for_selector("#btn-plan-approve", timeout=10000)
        step("A7_plan_gate_cancel_restores_approve")
    except Exception:  # noqa: BLE001
        defect("plan gate cancel does not restore APPROVE PLAN", "screenshot 12")

    # ---- A8 mid-plan mutation -> drift ----
    cur["label"] = "A8_drift"
    drift_ok = False
    injected = set()
    for rnd in range(1, 3):
        cur_rows = plan_rows(page)
        if not cur_rows:
            page.click("#btn-plan", timeout=15000)
            try:
                page.wait_for_function(
                    "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
                    " && document.querySelectorAll('#plan-body .prop-row').length > 0", timeout=150000)
                cur_rows = plan_rows(page)
            except Exception:  # noqa: BLE001
                pass
        cur["label"] = "A8_drift_r%d" % rnd
        has_zero = any("projected reachability 0" in r["text"] for r in cur_rows)
        titles = [t for r in cur_rows for t in r["titles"]]
        used = set(titles) | injected
        j_target = next((j for j in JEWELS if j not in used), None)
        if j_target is None:
            observe("no fresh jewel target left for drift injection", "")
            break
        if not has_zero:
            observe("plan has no 0-projection step (round %d) — drift may not fire" % rnd, "")
        inj = inject_grant(j_target)
        injected.add(j_target)
        step("A8_inject_midplan_grant_r%d" % rnd, target=j_target, finding=inj.get("finding"),
             applied=inj.get("applied"), reach_after=inj.get("reachability"))
        dt_exec, bt = confirm_plan(page)
        timing("confirm_plan_drift_to_receipt_s_r%d" % rnd, round(dt_exec, 2))
        step("A8_plan_execute_after_mutation_r%d" % rnd, banner=bt[:320])
        shot(page, "13_plan_execute_r%d" % rnd)
        shot(page, "13b_drift_full_r%d" % rnd, full=True)
        if "drift" in bt:
            drift_ok = True
            step("A8_drift_confirmed_r%d" % rnd)
            break
        observe("no drift on round %d (banner shows completed)" % rnd, bt[:200])
    if not drift_ok:
        defect("mid-plan mutation never produced drift_stopped_at_step",
               "see A8 rounds in steps log; banners recorded")

    # ---- A9 re-plan + execute to completion ----
    cur["label"] = "A9_replan"
    for attempt in range(1, 4):
        page.click("#btn-plan", timeout=15000)
        try:
            page.wait_for_function(
                "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'", timeout=150000)
            page.wait_for_function(
                "() => { const n = document.querySelectorAll('#plan-body .prop-row').length;"
                "  const b = document.getElementById('banner');"
                "  return (n > 0) || (b && b.innerText.includes('plan failed')); }", timeout=20000)
            break
        except Exception:  # noqa: BLE001
            time.sleep(10)
    rows2 = plan_rows(page)
    step("A9_replan_rendered", steps=len(rows2), rows=[r["text"][:140] for r in rows2])
    shot(page, "14_replan_card", locator="#plan-card")
    if rows2:
        cur["label"] = "A9b_execute"
        dt_exec, bt = confirm_plan(page)
        timing("confirm_plan_completed_to_receipt_s", round(dt_exec, 2))
        step("A9b_plan_executed", banner=bt[:320])
        shot(page, "15_plan_completed_banner")
        shot(page, "15b_completed_full", full=True)
        if "every step matched" not in bt:
            defect("plan execute banner lacks 'every step matched its live re-measure'", bt[:240])

    # ---- A10 collapse through the single-cut gate ----
    cur["label"] = "A10_collapse"
    final_reach = collapse_loop(page)
    step("A10_collapse_loop_done", final_reach_metric=final_reach)

    # ---- A11 receipts card ----
    cur["label"] = "A11_receipts"
    try:
        page.click("#btn-refresh", timeout=15000)
        page.wait_for_function(
            "() => document.querySelectorAll('#receipts .entry').length > 0", timeout=45000)
    except Exception:  # noqa: BLE001
        pass
    counts = ui_counts(page)
    entries = page.eval_on_selector_all("#receipts .entry", "els => els.map(e => e.innerText.replace(/\\n/g,' | '))")
    step("A11_receipts_card", entries=counts["receipts"], sample=[e[:120] for e in entries[:6]],
         engine_chip=engine_label(page), estate_chip=estate_chip(page))
    shot(page, "16_receipts_card")
    lbl = engine_label(page)
    if "unreachable" in lbl and "1,480 nodes" in estate_chip(page):
        defect("engine chip says 'engine unreachable' while estate data is live (misattribution)",
               "engine=%s estate=%s — screenshot 16" % (lbl, estate_chip(page)))
    if counts["receipts"] == 0:
        defect("receipts ledger card never populated (GET /api/receipts failing server-side)",
               "screenshot 16; see api_calls in results JSON")
    save()


# ---------------- PART B ----------------

def part_b(page):
    cur["label"] = "B0_load"
    load_page(page)
    st = api_state()
    step("B0_loaded", state={"reach": st["reachability"], "edges": st["edges"]})
    if st["reachability"] != 0:
        observe("estate not collapsed at part B start; collapsing via gate first", "reach=%s" % st["reachability"])
        page.click("#btn-refresh", timeout=15000)
        fr = collapse_loop(page, label="B0_collapse")
        if fr != "0":
            observe("UI-gate collapse starved by the 502 storm; finishing setup via API cuts", "reach=%s" % fr)
            fr = "0" if api_collapse() else fr
        step("B0_collapsed", final_reach=fr)
        if fr != "0":
            defect("could not collapse estate before shape farming", "reach=%s" % fr)

    # farm deterministic n-step plans: n direct hero->jewel grants == n-step plan
    farm_jewels = JEWELS[1:4]  # J2, J3, J4
    for n, name in ((1, "onestep"), (2, "twostep"), (3, "threestep")):
        rows = []
        for farm_attempt in range(1, 3):
            cur["label"] = "B1_farm_%s_try%d" % (name, farm_attempt)
            if farm_attempt == 1:
                for j in farm_jewels[:n]:
                    inj = inject_grant(j)
                    step("B1_inject_%s" % name, target=j, applied=inj.get("applied"),
                         reach=inj.get("reachability"))
            for attempt in range(1, 4):
                page.click("#btn-plan", timeout=15000)
                try:
                    # exact row count: race-proof against the stale card
                    # (a failed re-plan leaves the previous plan rendered)
                    page.wait_for_function(
                        "(n) => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
                        " && document.querySelectorAll('#plan-body .prop-row').length === n",
                        arg=n, timeout=150000)
                    break
                except Exception:  # noqa: BLE001
                    bt = banner_text(page)
                    if "plan failed" in bt:
                        defect("plan failed while farming %s" % name, bt[:200])
                    time.sleep(10)
            rows = plan_rows(page)
            step("B1_plan_%s" % name, steps_seen=len(rows), rows=[r["text"][:130] for r in rows])
            if len(rows) != n and farm_attempt == 1:
                # concurrent mutation or leftover path: collapse, re-inject, re-plan once
                observe("farm %s attempt 1 saw %d steps (want %d) — recollapsing and retrying"
                        % (name, len(rows), n), "")
                page.click("#btn-refresh", timeout=15000)
                collapse_loop(page, label="B1_recollapse_%s" % name)
                if reach_value(page)["text"] != "0":
                    api_collapse()
                for j in farm_jewels[:n]:
                    inject_grant(j)
                continue
            break
        shot(page, "20_plan_%s" % name, locator="#plan-card")
        if len(rows) != n:
            defect("expected %d-step plan card, saw %d steps" % (n, len(rows)),
                   "screenshot 20_plan_%s; rows=%s" % (name, [r["text"][:120] for r in rows]))
        if rows:
            cur["label"] = "B1_exec_%s" % name
            dt_exec, bt = confirm_plan(page)
            step("B1_exec_%s" % name, banner=bt[:300], exec_s=round(dt_exec, 2))
            shot(page, "21_exec_%s_banner" % name)
            try:
                wait_reach(page, "0", timeout=90000)
                step("B1_collapsed_after_%s" % name)
            except Exception:  # noqa: BLE001
                defect("estate did not collapse after executing %s-step plan" % name,
                       "reach=%s banner=%s" % (reach_value(page)["text"], bt[:160]))

    # ---- B4 empty plan ----
    cur["label"] = "B4_empty_plan"
    page.click("#btn-plan", timeout=15000)
    for attempt in range(1, 4):
        try:
            page.wait_for_function(
                "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
                " && document.getElementById('plan-body').innerText.includes('nothing to plan')",
                timeout=150000)
            break
        except Exception:  # noqa: BLE001
            time.sleep(10)
    rows = plan_rows(page)
    empty_note = plan_body_text(page)[:300]
    approve_present = page.locator("#btn-plan-approve").count()
    step("B4_empty_plan_card", steps=len(rows), body=empty_note, approve_button=approve_present)
    shot(page, "26_empty_plan_card", locator="#plan-card")
    if rows:
        defect("expected EMPTY plan on collapsed surface, saw %d steps" % len(rows), empty_note)
    if approve_present:
        defect("APPROVE PLAN button present on an empty plan", empty_note)
    if "collapsed" not in empty_note:
        defect("empty-plan note copy mismatch", empty_note)

    # ---- B5 benign-usage None renderer probe (route-intercepted /api/plan) ----
    cur["label"] = "B5_benign_none"
    synthetic = {
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
        "plan_completes_at_step": 1,
        "honesty": "projections are measured on an isolated GRAPH.COPY of the live estate",
    }

    def handler(route, request):
        route.fulfill(status=200, content_type="application/json", body=json.dumps(synthetic))

    page.route("**/api/plan", handler)
    try:
        page.click("#btn-plan", timeout=15000)
        try:
            page.wait_for_function(
                "() => getComputedStyle(document.getElementById('plan-card')).display !== 'none'"
                " && document.querySelectorAll('#plan-body .prop-row').length === 2", timeout=60000)
        except Exception:  # noqa: BLE001
            pass
        body_txt = plan_body_text(page)
        step("B5_benign_none_render", body=body_txt[:600])
        shot(page, "27_benign_null_plan_card", locator="#plan-card")
        if "benign null" in body_txt:
            defect("plan card renders literal 'benign null' for benign_usage=None (copy defect)",
                   "screenshot 27 — proposal card hides null benign; plan card prints it")
        else:
            observe("benign-None plan step rendered without literal 'null'", body_txt[:200])
    finally:
        page.unroute("**/api/plan", handler)

    # ---- B6 final receipts + chips + full journey capture ----
    cur["label"] = "B6_final"
    try:
        page.click("#btn-refresh", timeout=15000)
        page.wait_for_function("() => document.querySelectorAll('#receipts .entry').length > 0", timeout=45000)
    except Exception:  # noqa: BLE001
        pass
    entries = page.eval_on_selector_all("#receipts .entry", "els => els.map(e => e.innerText.replace(/\\n/g,' | '))")
    plan_lines = [e for e in entries if "plan" in e.lower()]
    step("B6_final_receipts", entries=len(entries), plan_lines=[e[:160] for e in plan_lines[:8]],
         engine_chip=engine_label(page), estate_chip=estate_chip(page), reach=reach_value(page))
    shot(page, "28_final_receipts")
    lbl = engine_label(page)
    if "unreachable" in lbl and "1,480 nodes" in estate_chip(page):
        defect("engine chip 'engine unreachable' while estate live (final check)", "screenshot 28")
    shot(page, "29_final_full", full=True)
    save()


def main():
    print("driver part", args.part, "out:", OUT, flush=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        page.on("console", _on_console)
        page.on("pageerror", _on_pageerror)
        page.on("requestfailed", _on_requestfailed)
        page.on("request", _on_request)
        page.on("response", _on_response)
        try:
            if args.part == "A":
                part_a(page)
            else:
                part_b(page)
        finally:
            R["meta"]["ended_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            save()
            try:
                shot(page, "99_end_state", full=True)
            except Exception:  # noqa: BLE001
                pass
            browser.close()
    print("DONE part", args.part, flush=True)


if __name__ == "__main__":
    main()
