"""Console UI a11y contract — DB-free static-HTML pin (audit2/ui-ux fix).

The audit2 UI/UX + a11y hardening (AA contrast tokens, keyboard gate flow,
a11y attributes, engine-down containment) landed with NO test of any kind —
it was only ever verified by eyeball in a live browser. This module pins the
attributes that make the console operable with a screen reader and a
keyboard, so a regression that strips them fails here (fleet-3 negative
coverage: the fix was positive-only).

It reads sever/console/static/index.html directly — no engine, no FastAPI.
(The fix10/console-ui shard later added the N29 body-cap pins at the bottom:
the one server-side exception, engine-free via build_app(port=...) exactly
like tests/test_console_resilience.py.)
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

UI = Path(__file__).resolve().parents[1] / "sever" / "console" / "static" / "index.html"
HTML = UI.read_text(encoding="utf-8")


def _static_markup() -> str:
    """The served markup without the <script> body (JS templates are pinned
    by string containment in the tests below)."""
    return HTML.split("<script>")[0]


def test_document_declares_its_language():
    assert re.search(r'<html\s+lang="[a-zA-Z-]+"', HTML), "screen readers need lang"


def test_every_visible_button_has_an_accessible_name():
    class _Buttons(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self._in_button = False
            self._text = ""
            self._label: str | None = None
            self.buttons: list[tuple[str | None, str]] = []

        def handle_starttag(self, tag, attrs):
            if tag == "button":
                self._in_button = True
                self._text = ""
                self._label = dict(attrs).get("aria-label")

        def handle_endtag(self, tag):
            if tag == "button" and self._in_button:
                self.buttons.append((self._label, self._text.strip()))
                self._in_button = False

        def handle_data(self, data):
            if self._in_button:
                self._text += data

    p = _Buttons()
    p.feed(_static_markup())
    assert p.buttons, "no buttons found in the static markup"
    for label, text in p.buttons:
        assert label or text, f"button with no accessible name: {label!r} / {text!r}"
    # the three headline actions are explicitly labelled
    for expect in (
        "Simulate a credential breach finding",
        "Simulate a new ACE grant, mutating the graph live",
        "Refresh state",
    ):
        assert any(label == expect for label, _ in p.buttons), expect


def test_status_regions_are_announced_to_assistive_tech():
    # engine state, estate facts and the finding banner are polite live
    # regions — updates are spoken without stealing focus
    for fragment in (
        'id="engine-chip" role="status"',
        'id="estate-chip" role="status"',
        'id="banner" role="status"',
    ):
        assert fragment in _static_markup(), fragment
    assert _static_markup().count('aria-live="polite"') >= 3


def test_auto_refresh_toggle_exposes_pressed_state():
    markup = _static_markup()
    assert 'id="refresh-toggle"' in markup
    assert 'aria-pressed="true"' in markup
    # the JS keeps the state truthful on toggle (audit2 fix: keyboard flow)
    assert "setAttribute('aria-pressed', String(on))" in HTML


def test_icon_svgs_are_hidden_from_assistive_tech():
    svgs = re.findall(r"<svg\b[^>]*>", _static_markup())
    assert svgs, "expected the decorated action buttons to carry icons"
    assert all('aria-hidden="true"' in s and 'focusable="false"' in s for s in svgs)


def test_keyboard_gate_flow_templates_are_labelled():
    # the JS-generated gate buttons (APPROVE -> CONFIRM/cancel) must carry
    # aria-labels too — both the proposal render AND the disarm-restore path
    # (the pending gate must survive an auto-refresh re-render)
    assert HTML.count('aria-label="Approve cutting this edge"') >= 2
    assert 'aria-label="Confirm the cut"' in HTML
    assert 'aria-label="Cancel the cut"' in HTML
    assert "'Escape'" in HTML, "Escape must cancel an armed gate"
    assert ":focus-visible" in HTML, "visible keyboard focus affordance"
    # focus management: confirm/cancel keep or restore focus (keyboard operable)
    assert "cf.focus()" in HTML
    assert "nb.focus()" in HTML


def test_engine_down_state_is_contained_and_announced():
    # engine-down containment: the failure path flips the live engine chip,
    # it never leaves a blank/stale page
    assert "engineDown" in HTML
    assert "engine unreachable" in HTML


def _hex_to_lum(hexcolor: str) -> float:
    r, g, b = (int(hexcolor[i : i + 2], 16) / 255 for i in (1, 3, 5))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def _contrast(a: str, b: str) -> float:
    la, lb = _hex_to_lum(a), _hex_to_lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def test_text_tokens_meet_aa_contrast_on_their_surfaces():
    """The audit2 AA-contrast fix, quantified: every text token used on a
    surface must clear WCAG AA (>= 4.5) — computed, not eyeballed."""
    tokens = dict(
        re.findall(r"--(text[\w-]*|danger|warn|success|focus):\s*(#[0-9A-Fa-f]{6})", HTML)
    )
    surfaces = dict(
        re.findall(r"--(bg|surface|surface-2):\s*(#[0-9A-Fa-f]{6})", HTML)
    )
    assert "text" in tokens and "bg" in surfaces, "tokens not found in CSS"
    pairs = [
        ("text", "bg"),          # body copy on the page background
        ("text-2", "surface"),   # secondary copy on cards
        ("text-3", "surface"),   # hints/labels on cards
        ("danger", "bg"),        # reachability metric / jewel markers
        ("warn", "bg"),          # ATT&CK technique banner
    ]
    for fg, bg in pairs:
        ratio = _contrast(tokens[fg], surfaces[bg])
        assert ratio >= 4.5, f"--{fg} on --{bg}: {ratio:.2f} < 4.5 (WCAG AA)"


# ---- audit5/live-e2e: proxy-error and per-card degradation copy ----


def test_api_never_surfaces_raw_html_error_pages():
    """A reverse-proxy 502 body is a full HTML error page (Render's branded
    page, live-observed Oct 16: the banner rendered "finding failed:
    <!DOCTYPE html> <html lang=\"en\">..."). The api() helper must detect
    HTML bodies and say what happened instead of echoing markup."""
    assert "HTML error page" in HTML, "the HTML-body guard must exist in api()"
    assert "server error ' + res.status" in HTML
    # the raw-echo path survives only for genuinely plain-text bodies
    assert "text.slice(0, 120)" in HTML


def test_receipts_failure_degrades_the_card_not_the_engine_chip():
    """/api/receipts is a pure file route: its failure must not flip the
    whole-engine chip to "unreachable" while /api/state still answers
    (live-observed: chip lied for minutes while estate data kept flowing).
    The receipts card gets its own honest degraded line instead."""
    assert "ledger unavailable" in HTML
    # the receipts fetch must sit AFTER the engine-backed catch (own lane),
    # in its own try — never inside the engine's try/catch. audit5/resilience
    # union: the fetch is shape-guarded via need(...) but stays in its own lane.
    eng_catch = HTML.index("engineDown();")
    rec_try = HTML.index("rec = need(await api('/api/receipts')")
    assert rec_try > eng_catch, "receipts fetch must live in its own try, after the engine lane"
    assert "renderReceipts" not in HTML  # renderer stays inline in the sink (dom_escape pins)
    assert "engineDown" in HTML and "engine unreachable" in HTML  # state-failure lane intact


def test_plan_card_never_prints_a_literal_null_benign_usage():
    """benign_usage null = NOT measured (fast-path proposal shape): the plan
    card must render 'benign not measured', never the literal 'null'
    (the proposal card already hides it; audit5/live-e2e found the plan card
    printed it raw)."""
    assert "benign not measured" in HTML
    # the OLD unconditional byte pattern (literal directly concatenating the
    # unguarded value) must be gone; the guarded ternary still contains
    # "benign ' + esc(s.benign_usage)" INSIDE its measured branch, which is
    # exactly the fix.
    assert "occurrences \u00b7 benign ' + esc(s.benign_usage)" not in HTML, \
        "unconditional benign render must be gone"


def test_confirm_plan_disables_during_execution():
    """CONFIRM PLAN must disable during the multi-second /api/plan/execute
    POST exactly like the single-cut gate's CONFIRM CUT (double-press must
    never fire a second plan execution)."""
    assert HTML.count("cf.disabled") >= 1
    assert "if (cf) cf.disabled = true;" in HTML
    assert "if (cn) cn.disabled = true;" in HTML


# ---- fix10/console-ui: audit-fleet CSS/JS regression pins --------------------
# Every fix in this section was verified live in headless Chromium first
# (computed styles + full stubbed flows, see test_console_ui_resilience.py);
# these are the byte-level pins so a future merge cannot silently re-break
# the shipped stylesheet or script.


def test_motion_token_lives_inside_root_and_the_reset_survives():
    """H17: '--motion: 150ms;' used to sit at stylesheet top level followed
    by a stray '}' — the parser merged it with the universal reset into one
    invalid qualified rule, silently killing BOTH (every * reset gone, all
    three state-change animations animation:none). The computed-style half
    of this pin lives in test_console_ui_resilience."""
    assert re.search(r":root\s*\{[^{}]*--motion:\s*150ms;", HTML), \
        "--motion must be declared inside the :root block"
    assert HTML.count("--motion:") == 1, "exactly one --motion declaration"
    # the stray top-level 'declaration + }' fragment must be gone
    assert not re.search(r"/\* base \*/\n\s+--motion: 150ms;\n\s*\}", HTML)
    # the universal reset rule is intact, and the arc ribbon resets its own
    # padding (the <ol> UA indent survives the reset's margin:0)
    assert "* { box-sizing: border-box; margin: 0; }" in HTML
    assert ".steps { list-style: none; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; padding: 0; }" in HTML


def test_wcag_comment_splits_approve_and_confirm_border_ratios():
    """L50: 'approve/confirm border 5.8' was one claim, but the confirm
    button's solid danger fill computes its border to 4.49 — the comment
    must not overclaim."""
    assert "approve border 5.8, confirm border 4.49" in HTML
    assert "approve/confirm border 5.8" not in HTML


def test_stylesheet_carries_one_generation_of_every_core_rule():
    """L51: two merged design-system generations left ~15 dead or duplicate
    rule sets — the earlier generation shadowed the later property-for-
    property while dead rules accumulated. Exactly one generation of each
    core rule must remain (matched on its full text so the legitimate
    responsive media-query variants do not count), and the surviving .ledger
    rule must keep the thin-scrollbar properties the naked dedupe would
    have dropped."""
    for live in (
        "header { display: flex; align-items: center; gap: 16px; padding: 12px 20px;",
        ".wordmark { font-family: var(--mono); font-weight: 700; letter-spacing: .18em; font-size: 14px; }",
        ".chip { display: inline-flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: var(--fs-s);",
        ".ledger { max-height: 320px; overflow-y: auto; scrollbar-width: thin; scrollbar-color: var(--border-strong) transparent; }",
        ".entry { display: flex; gap: 10px; padding: 7px 16px;",
        ".badge { font-family: var(--mono); font-size: 10px;",
        ".entry .line { color: var(--text-2); font-family: var(--mono); font-size: 11.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; flex: 1; }",
        ".entry .ts { color: var(--text-3); font-size: 10.5px; flex-shrink: 0; margin-left: auto; }",
    ):
        assert HTML.count(live) == 1, (live, HTML.count(live))
    # the dead first-generation rule texts must stay gone
    for dead in (
        "header { display: flex; align-items: center; gap: var(--sp-3);",
        ".chip { display: inline-flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: 11px;",
        ".ledger { max-height: 300px;",
        ".entry { display: flex; gap: 10px; padding: 8px 16px;",
        ".badge { font-family: var(--mono); font-size: var(--fs-xs);",
    ):
        assert dead not in HTML, dead
    # the .idle dot is part of the documented chip grammar and survives the
    # dedupe (it existed only in the first generation's set)
    assert ".chip.idle .dot { background: var(--text-3); }" in HTML


def test_hop_chain_keeps_one_color_generation():
    """M53: the stale second .hops/.hop block rendered the crown-jewel text
    danger-red on a green chip and the attacker amber on a red chip,
    crossing the page's fixed state-color semantics."""
    assert ".hop .jewel { color: var(--danger); }" not in HTML
    assert ".hop .node.mut { color: var(--warn); }" not in HTML
    # the surviving chip generation: red-tinted attacker, green-tinted jewel
    assert ".hop .node.mut { border-color: #5E2A2E; background: #1D1215; }" in HTML
    assert ".hop .jewel { border-color: #2E5138; background: #121D15; }" in HTML
    assert ".hop .jewel::before { background: var(--success); }" in HTML


def test_receipt_classes_the_js_renders_have_stylesheet_backing():
    """M57: the verdict/narration/delta/op chips were rendered by the JS
    with zero CSS — the measured verdict read as small uncolored secondary
    text and every delta chip looked identical."""
    for rule in (
        ".banner .verdict {",
        ".verdict.v-ok { color: var(--success-strong); }",
        ".verdict.v-warn { color: var(--warn); }",
        ".verdict.v-idle { color: var(--text-2); }",
        ".banner .narration {",
        ".delta {",
        ".delta.d-down { border-color: #2E5138; color: #7ED08C; }",
        ".delta.d-up { border-color: #5E2A2E; color: var(--danger); }",
        ".delta.d-flat { border-color: var(--border); color: var(--text-3); }",
        ".op {",
        ".btn.restore { animation: arrive var(--motion) ease; }",
    ):
        assert rule in HTML, rule


def test_confirm_hover_guard_and_tick_rule_target_the_right_selectors():
    # L52: the disabled irreversible button must not brighten on hover
    assert ".btn.confirm:not([disabled]):hover" in HTML
    assert ".btn.confirm:hover" not in HTML
    # L53: tickText() adds .tick to the #updated-at span (which carries no
    # class of its own) — .hint.tick could never match any element
    assert "#updated-at.tick" in HTML
    assert ".hint.tick" not in HTML


def test_bare_static_flag_disables_auto_refresh():
    # L54: a bare '?static' (no value) used to leave auto-polling enabled
    assert "has('static')" in HTML
    assert "get('static')" not in HTML


def test_wait_note_reflects_post_fold_expectations():
    """L55: the honest-wait note set expectations with the pre-fold '~15s on
    the free-tier engine' figure, stale since the 197->11 round-trip fold."""
    assert "note.textContent = '(this can take ~15s on the free-tier engine)'" not in HTML
    assert "note.textContent = '(if this exceeds 10s the engine may be cold or stalled)'" in HTML


def test_logo_comments_describe_the_shipped_inline_mark():
    """L49: the logo/favicon comments pointed at a pending
    docs/assets/logo_v4.svg that never existed, and the .logo-slot rule
    could match no element (the img is styled by .logo)."""
    assert "logo_v4" not in HTML
    assert ".logo-slot {" not in HTML
    assert "docs/assets/favicon.svg" in HTML  # comments now name real assets


def test_engine_down_toggles_paused_never_replaces_the_layout_class():
    """H18: the engine-down lane clobbered #estate-chip's 'hero-facts' class
    with 'chip paused' — the 4-stat grid was mangled into a tiny inline chip
    and never restored. The toggle must be classList-only, cleared on the
    next successful refresh."""
    assert "$('estate-chip').className = 'chip paused'" not in HTML
    assert "ec.classList.add('paused')" in HTML
    assert "ec.classList.remove('paused')" in HTML
    assert ".hero-facts.paused .stat-value { color: var(--warn); }" in HTML


def test_last_known_estate_facts_are_captured_on_success():
    # M54: state.estateFacts was read on the engine-down lane but never
    # assigned — the '… — last known' branch was dead code
    assert "state.estateFacts =" in HTML


def test_nested_receipt_dereferences_are_optional_chained():
    """M55: steps[0].before / lastStep.after / plan.k / plan.method escaped
    the need() shape guard — a torn or partial ledger entry crashed the
    receipts render with a JS stack fragment instead of rendering '?'."""
    assert "steps[0]?.before?.reachability" in HTML
    assert "lastStep?.after?.reachability" in HTML
    assert "esc(plan.k ?? '?')" in HTML
    assert "esc(plan.method ?? '?')" in HTML


def test_failure_ledger_steps_have_renderer_branches():
    """M56: plan_failed / console_boot_failed / plan_gate_refused used to
    fall to the generic 'state · reachability ? · ? nodes' poll-noise line,
    hiding the error/outcome the server ledgers for exactly those lanes."""
    assert "step === 'plan_failed' || step === 'console_boot_failed'" in HTML
    assert "plan gate refused · step '" in HTML
    assert "const failedEv = /_failed$/.test(step) || step === 'plan_gate_refused';" in HTML
    # console_boot_failed earns the sys badge, not the empty badge class
    assert "s === 'console_boot_failed' ? 'sys'" in HTML


def test_plan_receipt_banner_renders_once():
    """M58: executePlan used to render the receipt banner twice back-to-back
    — the first call was dead merge debris and its 'PLAN RECEIPT · ' byte
    string was the one docs/DEMO_SCRIPT.md quoted as verbatim."""
    assert "PLAN RECEIPT · " not in HTML
    assert HTML.count('<span class="technique">PLAN RECEIPT</span>') == 1
    assert "'completed' ? 'v-ok' : 'v-warn'" in HTML


def test_armed_gates_are_disarmed_across_cards():
    """L56: 'at most ONE armed gate in the DOM' excluded the plan gate —
    cut CONFIRM and CONFIRM PLAN used to be armable simultaneously."""
    assert "if (document.querySelector('#plan-body .confirm')) renderPlan();" in HTML
    assert re.search(r"function armPlanGate\(\) \{[^}]*cancelGate\(\);", HTML, re.S)


def test_plan_gate_cancel_restores_focus():
    # L57: the cancel handler rebuilds #plan-body, destroying the focused
    # cancel button — focus must land back on the re-rendered APPROVE PLAN
    assert "const b = $('btn-plan-approve');\n      if (b) b.focus();" in HTML


def test_plan_card_is_a_labelled_region():
    # N19: #plan-card was the only card region without an accessible name
    assert '<section class="card" id="plan-card" style="display:none" aria-labelledby="plan-card-title">' \
        in _static_markup()
    assert "</section>\n    <section class=\"card\" id=\"sec-receipts\"" in _static_markup()


# ---- N29: the 413 body-cap lane and the security headers ---------------------

CAP = 1_000_000  # sever/console/security.py MAX_BODY_BYTES


class _BootlessPort:
    """Engine-free stand-in for build_app(port=...): node_count() nonzero
    skips the sample auto-load, and nothing else is touched before the 413
    short-circuits in the middleware (the same injection pattern as
    tests/test_console_resilience.py)."""

    graph_name = "sever_test_ui_413"

    def node_count(self) -> int:
        return 5


@pytest.fixture()
def capped_console(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # the CaseLog root lands in the tmp dir
    monkeypatch.setenv("SEVER_CONSOLE_NO_BOOTSTRAP", "1")
    monkeypatch.setenv("SEVER_FALKOR_GRAPH", "sever_test_ui_413")
    from fastapi.testclient import TestClient

    import sever.console.app as appmod

    tc = TestClient(appmod.build_app(port=_BootlessPort()))
    yield tc
    # anything the boot ledged in the tmp dir must stay valid JSONL
    ledger = tmp_path / "out" / "cases" / "sever_test_ui_413.jsonl"
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if line.strip():
                json.loads(line)


def test_oversize_post_is_refused_413_by_the_body_cap(capped_console):
    """N29 (the half that must hold on this branch): a >1MB POST dies at the
    body-cap middleware before any buffering — the 413 lane exists."""
    r = capped_console.post(
        "/api/finding", content=b"9" * (CAP + 1),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413
    assert "too large" in r.json()["detail"]


@pytest.mark.xfail(
    strict=False,
    reason="M47 middleware order (fix10/console-api): BodySizeLimitMiddleware is "
           "added last and so sits OUTERMOST — its 413 bypasses _security_headers "
           "on this branch. The pin documents the contract and flips to XPASS "
           "(still green) the moment that fix merges; drop the marker then.",
)
def test_413_body_cap_response_carries_the_security_headers(capped_console):
    """N29: 'security headers on every response' must include the one
    response class the outermost body-cap middleware answers itself."""
    r = capped_console.post(
        "/api/finding", content=b"9" * (CAP + 1),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Strict-Transport-Security"] == "max-age=31536000"
