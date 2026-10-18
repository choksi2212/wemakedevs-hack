"""audit5/incident-verify: pin the UI api() resilient-parse + clean-banner contract.

Pre-fix, a stalled backend could hand the UI an EMPTY or truncated body with
any status; the blind ``res.json()`` then rendered the cryptic banner Manas hit
live ("finding failed: Failed to execute json on Response: Unexpected end of
JSON input"). The fix (53fa606) parses defensively and degrades to clean
messages. This drives the REAL page — sever/console/static/index.html served
locally, every /api/* fetch fulfilled at the network layer — in headless
Chromium, feeding it every body shape that broke the parser:

- empty 200 (the incident's exact signature)
- truncated JSON 200
- clean 503 JSON detail
- empty 503
- HTML error page (a proxy's 502)
- healthy 200 (the success receipt must still render)

…asserting the banner is always a clean human message (or the success
receipt), a JSON-parse artifact NEVER reaches the user, and the engine chip
flips to "engine unreachable" when /api/state stalls.

Engine-free: no FalkorDB, no uvicorn — a pure frontend contract, so it runs
wherever Playwright + Chromium are available; skipped otherwise.
"""
from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path

import pytest

pw_sync = pytest.importorskip("playwright.sync_api")

STATIC_ROOT = Path(__file__).resolve().parents[1] / "sever" / "console" / "static"

STATE_OK = (
    '{"backend":"falkordb","graph":"sever_demo","nodes":1480,"edges":12451,'
    '"jewels":[],"owned":["S-1-5-21-2697957641-2271029196-387917394-2110"],"reachability":1}'
)
FINDING_OK = (
    '{"finding":"F-deadbeef","kind":"credential_breach",'
    '"technique":"T1078.002 Valid Accounts: Domain Accounts",'
    '"narration":"Compromised domain account re-scored all attack paths.",'
    '"simulated":true,"applied":true,"reachability":1}'
)


@pytest.fixture(scope="module")
def static_site():
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

        def log_message(self, *args):  # keep pytest output clean
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/index.html"
    server.shutdown()


def _drive(browser, site, finding, state, click):
    """Load the real page with stubbed APIs, click a button, return (banner, chip)."""
    page = browser.new_page()

    def fulfill(route):
        url = route.request.url
        if url.endswith("/api/finding"):
            status, body = finding
            route.fulfill(status=status, body=body, content_type="text/plain")
        elif url.endswith("/api/state"):
            status, body = state
            route.fulfill(status=status, body=body, content_type="text/plain")
        elif url.endswith("/api/paths"):
            # honest shape per endpoint — the resilience guards 422 nothing,
            # but a wrong-shape 200 legitimately degrades that ONE section
            # (partial-data lane), which must never clobber an action receipt
            route.fulfill(status=200, body='{"paths":[]}', content_type="text/plain")
        else:  # proposal / receipts — array endpoints
            route.fulfill(status=200, body="[]", content_type="text/plain")

    page.route("**/api/*", fulfill)
    page.goto(site, wait_until="load")
    page.wait_for_selector("#btn-breach", timeout=15000)
    # let the initial refresh() settle so the chip reflects the stubbed state
    # (audit M74: this used to be a '|| true' tautology that could never
    # block — a REAL wait now: a healthy /api/state stub settles the
    # timestamp on 'state updated', a stalled one on 'refresh failed')
    settled = '"reachability"' in state[1]
    page.wait_for_function(
        "() => document.getElementById('updated-at').textContent.includes(%s)"
        % ("'state updated'" if settled else "'refresh failed'"),
        timeout=15000,
    )
    page.click("#btn-" + click)
    page.wait_for_function(
        "() => !document.getElementById('banner').textContent.includes('re-scoring')",
        timeout=15000,
    )
    banner = (page.text_content("#banner") or "").strip()
    chip = (page.text_content("#engine-label") or "").strip()
    page.close()
    return banner, chip


def _assert_no_parse_artifact(banner: str) -> None:
    low = banner.lower()
    assert "unexpected end of json" not in low, f"cryptic parse artifact reached the user: {banner!r}"
    assert "failed to execute" not in low, f"browser-parsing jargon reached the user: {banner!r}"
    assert "syntaxerror" not in low, f"JS internals reached the user: {banner!r}"


def test_empty_200_body_the_incident_signature_yields_clean_banner(static_site):
    """The exact incident shape: 200 OK with an EMPTY body (proxy-cut response)."""
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            banner, _ = _drive(browser, static_site, (200, ""), (200, STATE_OK), "breach")
            _assert_no_parse_artifact(banner)
            assert banner.startswith("finding failed:"), banner
            assert "empty/malformed response body" in banner, banner
        finally:
            browser.close()


def test_truncated_json_200_yields_clean_banner(static_site):
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            banner, _ = _drive(browser, static_site, (200, '{"detail": "trunc'), (200, STATE_OK), "grant")
            _assert_no_parse_artifact(banner)
            assert "empty/malformed response body" in banner, banner
        finally:
            browser.close()


def test_engine_503_surfaces_its_detail_not_a_parse_artifact(static_site):
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            banner, _ = _drive(
                browser, static_site,
                (503, '{"detail": "engine unreachable: ConnectionError: socket timeout"}'),
                (200, STATE_OK), "breach",
            )
            _assert_no_parse_artifact(banner)
            assert "finding failed: engine unreachable: ConnectionError: socket timeout" == banner
        finally:
            browser.close()


def test_empty_503_yields_backend_stalled_message(static_site):
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            banner, _ = _drive(browser, static_site, (503, ""), (200, STATE_OK), "grant")
            _assert_no_parse_artifact(banner)
            assert banner == "finding failed: empty response (backend stalled?)"
        finally:
            browser.close()


def test_html_proxy_error_page_yields_readable_text_not_parse_artifact(static_site):
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            banner, _ = _drive(
                browser, static_site,
                (502, "<html><body><h1>502 Bad Gateway</h1><p>proxy error</p></body></html>"),
                (200, STATE_OK), "breach",
            )
            _assert_no_parse_artifact(banner)
            assert banner.startswith("finding failed:"), banner
            # audit5/live-e2e union: HTML proxy pages are NAMED, not dumped —
            # the first 120 chars of "<!DOCTYPE html>..." markup is noise, the
            # honest diagnosis is "server error 502 (HTML error page)".
            assert "server error 502 (HTML error page)" in banner, banner
        finally:
            browser.close()


def test_healthy_200_still_renders_the_success_receipt(static_site):
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            banner, _ = _drive(browser, static_site, (200, FINDING_OK), (200, STATE_OK), "breach")
            _assert_no_parse_artifact(banner)
            assert banner.startswith("SIMULATED"), banner
            assert "T1078.002 Valid Accounts: Domain Accounts" in banner, banner
        finally:
            browser.close()


def test_state_stall_flips_chip_to_engine_unreachable(static_site):
    """A stalled /api/state (empty body) must show the stall message on the chip
    and leave the banner free of parse artifacts."""
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            banner, chip = _drive(browser, static_site, (200, FINDING_OK), (200, ""), "grant")
            _assert_no_parse_artifact(banner)
            assert chip == "engine unreachable", chip
        finally:
            browser.close()


def test_partial_refresh_never_clobbers_an_action_receipt(static_site):
    """audit5 merge bug (found by the ryzen gate): a refresh whose proposal/
    receipts sections come back wrong-shaped used to overwrite a FRESH action
    receipt with the 'partial data' state marker — the operator lost the
    finding result they had just been shown. The banner's own flag contract
    says an unflagged banner (an action receipt) must persist; the partial
    condition surfaces through the degraded chip + stale timestamp instead."""
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = browser.new_page()

            def fulfill(route):
                url = route.request.url
                if url.endswith("/api/finding"):
                    route.fulfill(status=200, body=FINDING_OK, content_type="text/plain")
                elif url.endswith("/api/state"):
                    route.fulfill(status=200, body=STATE_OK, content_type="text/plain")
                elif url.endswith("/api/proposal"):
                    # WRONG SHAPE: object where an array is the contract —
                    # the partial lane engages, the receipt must survive it
                    route.fulfill(status=200, body='{"oops": true}', content_type="text/plain")
                else:
                    route.fulfill(status=200, body='{"paths":[]}', content_type="text/plain")

            page.route("**/api/*", fulfill)
            page.goto(static_site, wait_until="load")
            page.wait_for_selector("#btn-breach", timeout=15000)
            page.click("#btn-breach")
            page.wait_for_function(
                "() => !document.getElementById('banner').textContent.includes('re-scoring')",
                timeout=15000,
            )
            # force refreshes (the 15s tick + manual) while the receipt shows
            for _ in range(3):
                page.click("#btn-refresh")
                page.wait_for_timeout(300)
            banner = (page.text_content("#banner") or "").strip()
            chip = (page.text_content("#engine-label") or "").strip()
            page.close()
            _assert_no_parse_artifact(banner)
            assert banner.startswith("SIMULATED"), banner  # the receipt survived
            assert "T1078.002" in banner, banner
            assert "degraded" in chip, chip  # the partial condition is still visible
        finally:
            browser.close()


# ---- fix10/console-ui: audit-fleet regressions (H17/H18, M54-M58, L53-L57) ----
# Each fix was verified live in this same headless-Chromium harness before it
# was pinned; these keep the computed styles and the flows honest.

HERO_X = "S-1-5-21-x"
TIER1_X = "S-1-5-21-t1"
PATHS_ONE = json.dumps({"paths": [{"principal": HERO_X, "hops": [
    {"src": "ATTACKER", "src_id": HERO_X, "rel": "MEMBER_OF",
     "dst": "TIER1", "dst_id": TIER1_X},
]}]})
PROPOSAL_ONE = json.dumps([{
    "src": HERO_X, "rel": "MEMBER_OF", "dst": TIER1_X, "paths_on": 5,
    "benign_usage": 0, "benign_sample": {"sampled": 25, "pool": 98},
    "src_name": "ATTACKER", "dst_name": "TIER1",
}])
PLAN_OK = json.dumps({
    "k": 3, "method": "graph_copy_remeasure", "base": {"reachability": 2},
    "benign_sample_size": 25,
    "steps": [{"step": 1, "cut": {"src": HERO_X, "rel": "MEMBER_OF", "dst": TIER1_X},
               "paths_on": 5, "benign_usage": 0,
               "projected_reachability": 1, "projected_verdict": "degraded"}],
    "honesty": "projections measured on an isolated copy",
})
PLAN_EXEC_OK = json.dumps({
    "status": "completed", "executed_steps": 1,
    "steps": [{"cut": {"src": HERO_X, "rel": "MEMBER_OF", "dst": TIER1_X},
               "before": {"reachability": 2}, "after": {"reachability": 0},
               "verdict": "collapsed", "plan_step": 1, "plan_drift": False,
               "approved_by": "op-x", "requery_ms": 2.28}],
})
RECEIPTS_FAILURES = json.dumps([
    {"step": "console_boot_failed",
     "error": "engine unreachable at bootstrap: ConnectionError", "outcome": "unknown"},
    {"step": "plan_failed", "error": "engine unreachable mid-plan", "outcome": "unknown"},
    {"step": "plan_gate_refused", "plan_step": 2,
     "cut": {"src": "S-1-5-21-a", "rel": "MEMBER_OF", "dst": "S-1-5-21-b"}},
    {"step": "cut", "ts": "2026-10-18T10:00:00+00:00", "receipt": {
        "cut": {"src": HERO_X, "rel": "MEMBER_OF", "dst": TIER1_X,
                "relationships_removed": 1},
        "before": {"reachability": 1}, "after": {"reachability": 0},
        "requery_ms": 2.28, "verdict": "collapsed", "approved_by": "op-y"}},
])


def _stub_page(browser, site, stub):
    """The real page with every /api/* fetch answered from ``stub`` (mutable
    so a test can stall or recover the engine mid-flow). Route glob is
    '**/api/**' — Playwright's '*' does not cross '/', so a '/api/plan/execute'
    POST would silently bypass '**/api/*'."""
    page = browser.new_page()

    def fulfill(route):
        url = route.request.url

        def j(body, status=200):
            route.fulfill(status=status, body=body, content_type="text/plain")

        if url.endswith("/api/state"):
            j("" if stub.get("stall") else stub.get("state", STATE_OK))
        elif url.endswith("/api/paths"):
            j(stub.get("paths", PATHS_ONE))
        elif url.endswith("/api/proposal"):
            j(stub.get("proposal", PROPOSAL_ONE))
        elif url.endswith("/api/receipts"):
            j(stub.get("receipts", "[]"))
        elif url.endswith("/api/plan/execute"):
            j(stub.get("plan_execute", PLAN_EXEC_OK))
        elif url.endswith("/api/plan"):
            j(stub.get("plan", PLAN_OK))
        else:
            route.fulfill(status=404, body="{}", content_type="text/plain")

    page.route("**/api/**", fulfill)
    page.goto(site, wait_until="load")
    page.wait_for_selector("#btn-breach", timeout=15000)
    return page


def _wait_settled(page, timeout=15000):
    page.wait_for_function(
        "() => document.getElementById('estate-detail').textContent.includes('owned:')",
        timeout=timeout,
    )


def test_h17_motion_token_resolves_and_the_universal_reset_applies(static_site):
    """H17 regression: '--motion: 150ms;' outside any rule plus a stray '}'
    merged the universal reset into one invalid qualified rule — the console
    rendered with UA margins, content-box sizing, a 40px-indented arc ribbon
    and zero motion. Pin the computed styles a merge must never lose."""
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = _stub_page(browser, static_site, {})
            _wait_settled(page)
            assert page.evaluate(
                "getComputedStyle(document.documentElement)"
                ".getPropertyValue('--motion').trim()") == "150ms"
            assert page.evaluate(
                "getComputedStyle(document.querySelector('.steps')).paddingLeft") == "0px"
            assert page.evaluate(
                "getComputedStyle(document.querySelector('.steps')).margin") == "0px"
            assert page.evaluate("getComputedStyle(document.body).boxSizing") == "border-box"
            assert page.evaluate("getComputedStyle(document.querySelector('h1')).margin") == "0px"
            # the three state-change animations resolve to their keyframes
            page.evaluate("document.getElementById('updated-at').classList.add('tick')")
            assert page.evaluate(
                "getComputedStyle(document.getElementById('updated-at')).animationName") \
                == "tick-dip"  # L53: the rule targets #updated-at, not .hint.tick
        finally:
            browser.close()


def test_engine_down_preserves_the_hero_facts_grid_and_recovers(static_site):
    """H18 + M54: the engine-down lane used to clobber #estate-chip's
    'hero-facts' class with 'chip paused' (grid mangled forever, never
    restored), and the '<facts> — last known' branch was dead because
    state.estateFacts was never assigned."""
    stub: dict = {}
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = _stub_page(browser, static_site, stub)
            _wait_settled(page)
            assert page.evaluate(
                "document.getElementById('estate-chip').className") == "hero-facts"

            stub["stall"] = True
            page.click("#btn-refresh")
            page.wait_for_function(
                "() => document.getElementById('engine-label').textContent"
                ".includes('unreachable')", timeout=15000)
            assert page.evaluate(
                "document.getElementById('estate-chip').className") == "hero-facts paused"
            assert page.evaluate(
                "getComputedStyle(document.getElementById('estate-chip')).display") == "grid"
            assert page.evaluate(
                "getComputedStyle(document.querySelector('#estate-chip .stat-value')).color") \
                == "rgb(212, 153, 63)"  # amber = stale, layout intact
            detail = page.evaluate("document.getElementById('estate-detail').textContent")
            assert "1,480 nodes" in detail and "— last known" in detail, detail

            stub["stall"] = False
            page.click("#btn-refresh")
            _wait_settled(page)
            assert page.evaluate(
                "document.getElementById('estate-chip').className") == "hero-facts"
        finally:
            browser.close()


def test_failure_ledger_steps_render_their_error_not_poll_noise(static_site):
    """M56 + M57: plan_failed / console_boot_failed / plan_gate_refused used
    to fall to the generic 'state · reachability ? · ? nodes' line — the
    outage the server ledgers for exactly those lanes was invisible."""
    stub = {"receipts": RECEIPTS_FAILURES}
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = _stub_page(browser, static_site, stub)
            _wait_settled(page)
            page.wait_for_function(
                "() => document.querySelectorAll('#receipts .entry').length >= 4",
                timeout=15000)
            lines = page.evaluate(
                "[...document.querySelectorAll('#receipts .entry .line')]"
                ".map(e => e.getAttribute('title'))")
            assert any("plan failed · engine unreachable mid-plan · outcome unknown" in l
                       for l in lines), lines
            assert any("console boot failed · engine unreachable at bootstrap: "
                       "ConnectionError · outcome unknown" in l for l in lines)
            assert any("plan gate refused · step 2 · the human gate was not satisfied,"
                       " nothing was executed" in l and "S-1-5-21-a" in l for l in lines)
            assert not any(l and l.startswith("state · reachability ?") for l in lines)
            # the honest-failure accent and the boot event's sys badge
            assert page.evaluate(
                "document.querySelectorAll('#receipts .entry.failed').length") >= 3
            assert page.evaluate("""(() => {
                const e = [...document.querySelectorAll('#receipts .entry')]
                    .find(x => x.textContent.includes('console boot failed'));
                return e ? e.querySelector('.badge').className : null; })()""") \
                == "badge sys"
            # M57: the measured delta chip is state-colored and the operator
            # attribution renders as its own chip
            delta = page.evaluate("""(() => {
                const d = document.querySelector('#receipts .delta.d-down');
                const o = document.querySelector('#receipts .op');
                if (!d || !o) return null;
                return [getComputedStyle(d).color, d.textContent.trim(), o.textContent.trim()];
            })()""")
            assert delta and delta[0] == "rgb(126, 208, 140)" and delta[1] == "1 → 0" \
                and delta[2] == "by op-y", delta
        finally:
            browser.close()


def test_plan_flow_one_banner_one_armed_gate_focus_kept(static_site):
    """M58 + L56 + L57 + M57: executePlan used to render the banner twice
    (the dead first call's byte string was the one the demo script quoted),
    cut CONFIRM and CONFIRM PLAN could be armed at once, and the plan gate's
    cancel dropped keyboard focus to <body>."""
    stub: dict = {}
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = _stub_page(browser, static_site, stub)
            _wait_settled(page)
            page.click("#btn-plan")
            page.wait_for_function(
                "() => !document.getElementById('banner').textContent"
                ".includes('planning')", timeout=15000)
            page.click("#btn-plan-approve")
            page.wait_for_selector("#btn-plan-confirm", timeout=15000)

            # L56: arming the single-cut gate disarms the plan gate
            page.click("#proposal button.approve")
            page.wait_for_selector("#proposal .prop-cta .confirm", timeout=15000)
            assert page.query_selector("#btn-plan-confirm") is None

            # re-arm the plan gate, then cancel — focus must be restored
            page.click("#btn-plan-approve")
            page.wait_for_selector("#btn-plan-confirm", timeout=15000)
            page.click("#btn-plan-cancel")
            page.wait_for_function(
                "() => document.activeElement && document.activeElement.id"
                " === 'btn-plan-approve'", timeout=15000)
            assert page.evaluate("document.querySelectorAll('.btn.confirm').length") == 0

            # M58: execute once — the surviving banner is the verdict hierarchy
            page.click("#btn-plan-approve")
            page.wait_for_selector("#btn-plan-confirm", timeout=15000)
            page.click("#btn-plan-confirm")
            page.wait_for_function(
                "() => document.getElementById('banner').textContent"
                ".includes('PLAN RECEIPT')", timeout=15000)
            banner_html = page.evaluate("document.getElementById('banner').innerHTML")
            banner_txt = page.evaluate("document.getElementById('banner').textContent")
            assert '<span class="technique">PLAN RECEIPT</span>' in banner_html
            assert "PLAN RECEIPT · " not in banner_txt  # the dead string stays dead
            assert "completed" in banner_txt and "every step matched its live re-measure" \
                in banner_txt
            # M57: the verdict is the hero line, state-colored via the class map
            verdict = page.evaluate("""(() => {
                const v = document.querySelector('#banner .verdict');
                const cs = getComputedStyle(v);
                return [v.className, cs.fontSize, cs.fontWeight, cs.color];
            })()""")
            assert verdict == ["verdict v-ok", "15px", "700", "rgb(126, 208, 140)"], verdict
        finally:
            browser.close()


def test_bare_static_query_flag_pauses_auto_refresh(static_site):
    """L54: a bare '?static' (no value) used to leave the 15s auto-polling
    enabled — URLSearchParams.get('') is falsy, .has() is not."""
    with pw_sync.sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            page = _stub_page(browser, static_site + "?static", {})
            _wait_settled(page)
            assert page.evaluate(
                "document.getElementById('refresh-toggle')"
                ".getAttribute('aria-pressed')") == "false"
            assert "paused" in page.evaluate(
                "document.getElementById('refresh-toggle').textContent")
        finally:
            browser.close()
