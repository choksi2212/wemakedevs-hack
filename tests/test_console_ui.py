"""Console UI a11y contract — DB-free static-HTML pin (audit2/ui-ux fix).

The audit2 UI/UX + a11y hardening (AA contrast tokens, keyboard gate flow,
a11y attributes, engine-down containment) landed with NO test of any kind —
it was only ever verified by eyeball in a live browser. This module pins the
attributes that make the console operable with a screen reader and a
keyboard, so a regression that strips them fails here (fleet-3 negative
coverage: the fix was positive-only).

It reads sever/console/static/index.html directly — no engine, no FastAPI.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

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
    # in its own try — never inside the engine's try/catch
    eng_catch = HTML.index("} catch (e) { engineDown(); }")
    rec_try = HTML.index("try { rec = await api('/api/receipts'); }")
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
