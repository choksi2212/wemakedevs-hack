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
    page.wait_for_function("() => !document.getElementById('updated-at').textContent.includes('updated') || true")
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
