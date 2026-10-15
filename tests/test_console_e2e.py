"""audit3/console-logic live-browser regressions (Playwright, engine-gated).

Spawns its OWN console (uvicorn, SEVER_E2E_PORT default 8165) against graph
``sever_audit3_cl_e2e``, then drives headless Chromium:

- ``test_confirm_click_survives_the_refresh_dom_swap``: the pending human
  gate must stay armed + focused across the 15s auto-refresh re-render, and
  a CONFIRM pressed on the old button and released on its post-swap
  replacement must still execute the cut (the press/release pairing added in
  audit3/console-logic; without it delivery was 8/10..10/10 by scheduling
  luck, measured live).
- ``test_xss_payloads_never_execute_on_any_render_surface``: script tags,
  img onerror, quote escapes and backticks fed through kind, subject, target,
  rel and approved_by must never execute and never break an attribute.

Skipped unless the engine is reachable and playwright + Chromium are
available (PLAYWRIGHT_BROWSERS_PATH must point at the browsers when they
are not in the default location).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tests.conftest import requires_engine, requires_sample, drop_graph
from sever.core.falkor_port import FalkorGraphPort

pw_any = pytest.importorskip("playwright")

pytestmark = [requires_engine, requires_sample]

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
GMSA = "S-1-5-21-2697957641-2271029196-387917394-2102"
PORT = int(os.environ.get("SEVER_E2E_PORT", "8165"))
GRAPH = "sever_audit3_cl_e2e"
REPO = Path(__file__).resolve().parents[1]

FETCH_GATE_JS = """
() => {
  window.__gateRelease = null;
  window.__holdNext = false;
  const orig = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    if (url.includes('/api/proposal') && window.__holdNext) {
      window.__holdNext = false;
      return orig(input, init).then((res) => new Promise((resolve) => {
        window.__gateRelease = () => resolve(res);
      }));
    }
    return orig(input, init);
  };
  window.__holdProposal = () => { window.__holdNext = true; };
  window.__releaseProposal = () => {
    const r = window.__gateRelease; window.__gateRelease = null; if (r) r();
  };
}
"""


def _api(path, body=None, base=None):
    req = urllib.request.Request(
        (base or f"http://127.0.0.1:{PORT}") + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"} if body is not None else {},
        method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, None


def _cut_count(base=None) -> int:
    st, rec = _api("/api/receipts", base=base)
    return sum(1 for e in rec if e.get("step") == "cut") if st == 200 else -1


@pytest.fixture(scope="module")
def console_url():
    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=GRAPH,
    )
    drop_graph(port, GRAPH)  # fresh, deterministic proposals
    env = os.environ.copy()
    env["SEVER_FALKOR_GRAPH"] = GRAPH
    env["PYTHONUNBUFFERED"] = "1"
    log = open(REPO / "audit3_e2e_console.log", "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "sever.console.app:app",
         "--host", "127.0.0.1", "--port", str(PORT)],
        cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{PORT}"
    try:
        ready = False
        for _ in range(90):
            try:
                if _api("/api/state", base=base)[0] == 200:
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(1.0)
        if not ready:
            pytest.skip(f"e2e console did not come up on {base} (port busy?)")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        log.close()
        drop_graph(port, GRAPH)


@pytest.fixture()
def fresh_gate(console_url, page):
    """Reachability may be zeroed by a prior test's cut: re-grant a direct
    hero->jewel edge, refresh, and leave one APPROVE-able proposal."""
    _ensure_proposal(console_url)
    page.click("#btn-refresh")
    page.wait_for_selector("#proposal button.approve", timeout=20000)


@pytest.fixture(scope="module")
def browser():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        try:
            b = pw.chromium.launch(headless=True)
        except Exception as e:  # browsers not installed
            pytest.skip(f"Chromium not available: {e}")
        yield b
        b.close()


@pytest.fixture()
def page(browser, console_url):
    p = browser.new_page()
    errors: list[str] = []
    p.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    p.goto(console_url + "/")
    p.wait_for_selector("#reach", timeout=30000)
    p.evaluate(FETCH_GATE_JS)
    yield p
    assert not errors, f"page errors leaked: {errors[:5]}"
    p.close()


def _ensure_proposal(console_url) -> None:
    """Guarantee an armable proposal:
    1. on a fresh graph nothing is OWNED -> breach the hero (the sample's
       own paths then light up reachability);
    2. if a prior test's cut zeroed reachability, re-grant a DIRECT
       hero->jewel edge."""
    st, s = _api("/api/state", base=console_url)
    if st != 200 or not s:
        return
    if HERO not in s.get("owned", []):
        _api("/api/finding", {"kind": "credential_breach", "subject": HERO}, base=console_url)
        st, s = _api("/api/state", base=console_url)
    if s["reachability"] == 0:
        jewel = s["jewels"][0] if s.get("jewels") else GMSA
        _api("/api/finding", {"kind": "cross_domain_trust", "subject": HERO,
                              "target": jewel, "rel": "TRUSTED_BY"}, base=console_url)


def _engineered_swap_click(page, console_url) -> dict:
    """Arm the gate, hold the refresh's proposal response, mouse-down on the
    old CONFIRM, release the response mid-press (DOM swap), mouse-up on the
    replacement, and check the cut actually executed."""
    r: dict = {}
    _ensure_proposal(console_url)
    page.click("#btn-refresh")
    page.wait_for_selector("#proposal button.approve", timeout=20000)
    page.click("#proposal button.approve")       # arm the gate
    page.wait_for_selector("#proposal .prop-cta .confirm", timeout=5000)
    page.evaluate("window.__holdProposal()")
    page.click("#btn-refresh")                    # refresh; proposal held
    held = False
    for _ in range(100):
        if page.evaluate("window.__gateRelease !== null"):
            held = True
            break
        page.wait_for_timeout(100)
    r["proposal_held"] = held
    if not held:
        return r
    box = page.locator("#proposal .prop-cta .confirm").bounding_box()
    before = _cut_count(console_url)
    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    page.mouse.down()
    page.evaluate("window.__releaseProposal()")   # the swap lands mid-press
    page.wait_for_timeout(150)
    r["confirm_alive_after_swap"] = page.evaluate(
        "!!document.querySelector('#proposal .prop-cta .confirm')")
    page.mouse.up()
    for _ in range(25):
        if _cut_count(console_url) > before:
            r["cut_executed"] = True
            return r
        page.wait_for_timeout(200)
    r["cut_executed"] = False
    return r


def test_confirm_click_survives_the_refresh_dom_swap(page, console_url, fresh_gate):
    for i in range(3):
        r = _engineered_swap_click(page, console_url)
        assert r.get("proposal_held"), f"attempt {i}: proposal response never held"
        assert r.get("confirm_alive_after_swap"), f"attempt {i}: gate died on the swap"
        assert r.get("cut_executed"), (
            f"attempt {i}: a CONFIRM pressed across the refresh DOM swap was lost")


def test_pending_gate_survives_the_natural_15s_refresh(page, console_url, fresh_gate):
    page.click("#proposal button.approve")
    page.wait_for_selector("#proposal .prop-cta .confirm", timeout=5000)
    stamp = page.text_content("#updated-at")
    swapped = False
    for _ in range(50):  # the real 15s auto-refresh tick
        if page.text_content("#updated-at") != stamp:
            swapped = True
            break
        page.wait_for_timeout(400)
    assert swapped, "the 15s auto-refresh never re-rendered"
    assert page.evaluate("!!document.querySelector('#proposal .prop-cta .confirm')"), \
        "the pending gate must stay armed across the auto-refresh re-render"
    assert page.evaluate(
        "document.activeElement && document.activeElement.classList.contains('confirm')"), \
        "CONFIRM must keep keyboard focus across the auto-refresh re-render"
    before = _cut_count(console_url)
    page.click("#proposal .prop-cta .confirm")
    for _ in range(25):
        if _cut_count(console_url) > before:
            break
        page.wait_for_timeout(200)
    assert _cut_count(console_url) > before, "armed-gate cut did not execute"


PAYLOADS = [
    "<script>window.__severXSS=1</script>",
    '<img src=x onerror="window.__severXSS=1">',
    '"><svg onload=window.__severXSS=1>',
    "`-onerror=${window.__severXSS=1}`",
]


def test_xss_payloads_never_execute_on_any_render_surface(page, console_url):
    def post(path, body):
        return page.evaluate(
            """async ([path, body]) => {
              const r = await fetch(path, {method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body)});
              return [r.status, (await r.text()).slice(0, 200)];
            }""", [path, body])

    for p in PAYLOADS:
        # hostile kind/subject/target/rel die at the schema/estate gates
        assert post("/api/finding", {"kind": p, "subject": HERO})[0] == 422
        assert post("/api/finding", {"kind": "credential_breach", "subject": p})[0] == 400
        assert post("/api/finding", {"kind": "ace_granted", "subject": HERO,
                                     "target": p, "rel": "GENERIC_ALL"})[0] == 400
        # accepted-but-rendered surfaces: ghost-edge cut + approved_by
        assert post("/api/cut", {"src": p, "dst": HERO, "rel": "MEMBER_OF",
                                 "approved": True, "approved_by": "xss-probe"})[0] == 200
        assert post("/api/cut", {"src": HERO, "dst": GMSA, "rel": "GENERIC_ALL",
                                 "approved": True, "approved_by": p})[0] == 200

    page.click("#btn-refresh")
    page.wait_for_timeout(2500)

    assert page.evaluate("typeof window.__severXSS === 'undefined'"), \
        "a payload executed"
    assert page.evaluate("document.querySelectorAll('script').length") == 1
    assert page.evaluate(
        "Array.from(document.querySelectorAll('*'))"
        ".filter(e => Array.from(e.attributes)"
        ".some(a => a.name.toLowerCase().startsWith('on')"
        " && a.value.includes('__severXSS'))).length") == 0, \
        "an event-handler attribute broke out"
    html = page.evaluate("document.documentElement.outerHTML")
    assert "<script>window.__severXSS" not in html, "raw script markup in the DOM"
    assert "&lt;script&gt;window.__severXSS" in html, \
        "the payload must render, escaped, as text"
    titles = page.evaluate(
        "Array.from(document.querySelectorAll('#receipts .entry .line'))"
        ".map(e => e.getAttribute('title') || '')")
    carrying = [t for t in titles if "__severXSS" in t]
    assert carrying, "the approved_by payload should be visible in the ledger"
    # every attribute carries its payload WITHOUT an early quote breakout:
    # the full marker is still inside the quoted value
    assert all(t.count("__severXSS") >= 1 for t in carrying)
    assert page.evaluate(
        "document.getElementById('receipts').textContent"
        ".includes('<script>window.__severXSS')"), \
        "the payload must be present as TEXT (escaped), i.e. escaped everywhere"
