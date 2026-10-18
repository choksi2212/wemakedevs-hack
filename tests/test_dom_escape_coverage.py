"""Byte-level DOM XSS regression for the console UI (audit3/pentest-internal).

Fleet-2 added esc() coverage over banner/paths/proposal/ledger title
attributes; this re-verifies it mechanically so a future edit cannot silently
drop an escape:

INVARIANT — in every ``.innerHTML =`` sink statement of index.html, every
dynamic operand concatenated with a literal that carries HTML structure bytes
(``<`` or a ``title="`` attribute) is either ``esc(...)``-wrapped or a member
of the trusted set (server-generated ints / server-fixed literal words — the
append-only case ledger's ``step`` values are server-written literals, and
receipt numerics come from interdict(), never from request text).
"""
from __future__ import annotations

import re
from pathlib import Path

INDEX = Path(__file__).resolve().parents[1] / "sever" / "console" / "static" / "index.html"

TRUSTED = {
    # server-written ledger step names and derived badge classes
    "badge", "step",
    # server-generated receipt numerics / fixed verdict words (scoring.interdict)
    "r.cut.relationships_removed", "r.before.reachability", "r.after.reachability",
    "r.requery_ms", "r.verdict",
    # proposal path-coverage count (rank_cut_candidates: server int)
    "c.paths_on",
    # '' or 'SIMULATED · ' literal; fire() call-site literals
    "sim", "kind",
    # plan-card fragment (renderPlan): composed exclusively of esc()-wrapped
    # operands and server-fixed literals — each plan step's src/rel/dst/note
    # is escaped at construction inside renderPlan()
    "body",
}


def _sink_statements(js: str) -> list[str]:
    """Every innerHTML assignment statement, terminated by a top-level ``;``
    (string-aware, paren-aware)."""
    sinks = []
    i = 0
    while True:
        k = js.find("innerHTML", i)
        if k == -1:
            return sinks
        start = js.rfind("\n", 0, k) + 1
        depth, j, in_str = 0, k, ""
        while j < len(js):
            c = js[j]
            if in_str:
                j += 2 if c == "\\" else 1
                if js[j - 1] == in_str:
                    in_str = ""
                continue
            if c in "'\"":
                in_str = c
            elif c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == ";" and depth == 0:
                break
            j += 1
        sinks.append(js[start:j + 1])
        i = j + 1


def _split_operands(expr: str) -> list[str]:
    """Top-level `+`-separated operands (string-aware, paren-aware)."""
    parts, buf, depth, i, in_str = [], [], 0, 0, ""
    while i < len(expr):
        c = expr[i]
        if in_str:
            buf.append(c)
            if c == "\\" and i + 1 < len(expr):
                buf.append(expr[i + 1])
                i += 2
                continue
            if c == in_str:
                in_str = ""
            i += 1
            continue
        if c in "'\"":
            in_str = c
            buf.append(c)
        elif c in "([{":
            depth += 1
            buf.append(c)
        elif c in ")]}":
            depth -= 1
            buf.append(c)
        elif c == "+" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    parts.append("".join(buf))
    return parts


def _is_string_literal(op: str) -> bool:
    op = op.strip()
    return op.startswith(("'", '"')) and op.endswith(("'", '"')) and not op[-2:] == "\\'"


def _is_escaped(op: str) -> bool:
    stripped = re.sub(r"^\s*", "", op)
    return stripped.startswith(("esc(", "CSS.escape("))


def _trusted_reference(op: str) -> bool:
    ref = re.match(r"^\s*([A-Za-z_$][\w.$]*)\s*(\(|$)", op)
    if not ref:
        return False
    return ref.group(1) in TRUSTED


def _carries_html(op: str) -> bool:
    return "<" in op or 'title="' in op


def test_every_innerhtml_sink_escapes_or_trusts_html_adjacent_operands():
    src = INDEX.read_text(encoding="utf-8")
    js = re.search(r"<script>(.*)</script>", src, re.S).group(1)
    sinks = _sink_statements(js)
    # the console has exactly these ten sinks today (audit4 added the plan
    # card + plan gate; audit5/live-e2e added the receipts-card degraded
    # line when the pure-file /api/receipts route fails independently of the
    # engine; the armed-gate invariant sweep added the cta APPROVE-restore
    # sink — the disarmGate and renderGate sweeps are textually identical
    # but are BOTH collected (the extractor does no dedupe), so the count
    # stays 10); a new sink must extend this test consciously, not slip
    # through
    assert len(sinks) == 10, [s[:60] for s in sinks]

    violations = []
    for stmt in sinks:
        # unwrap: statement text may contain an assignment 'x.innerHTML = RHS'
        # (drop the statement terminator first so a literal operand that ends
        # the statement is still recognized as a literal)
        rhs = stmt.rstrip(";\n ").split("=", 1)[1] if "=" in stmt else stmt
        operands = _split_operands(rhs)
        for idx, op in enumerate(operands):
            op = op.strip()
            if not op or _is_string_literal(op):
                continue
            neighbors = [operands[k] for k in (idx - 1, idx + 1) if 0 <= k < len(operands)]
            if not any(_is_string_literal(n) and _carries_html(n) for n in neighbors):
                continue  # operand not adjacent to structural HTML bytes
            if not (_is_escaped(op) or _trusted_reference(op)):
                violations.append((stmt[:80], op))
    assert not violations, violations


def test_no_untrusted_field_appears_raw_in_any_sink():
    """Every untrusted dynamic value must appear only inside esc(...) — the
    receipts ledger-line build is exempt (its output feeds esc(line))."""
    src = INDEX.read_text(encoding="utf-8")
    js = re.search(r"<script>(.*)</script>", src, re.S).group(1)
    sinks = _sink_statements(js)
    untrusted = ["p.principal", "h.src", "h.dst", "h.rel", "c.src", "c.dst",
                 "c.rel", "e.message", "recErr.message", "r.technique",
                 "r.narration", "p.src", "p.dst", "p.rel", "e.ts",

                 # plan surfaces (audit4): every dynamic plan field must be
                 # esc()-wrapped at its sink too
                 "s.cut.src", "s.cut.dst", "s.cut.rel", "plan.note",
                 "plan.honesty", "plan.method"]
    for stmt in sinks:
        stripped = stmt
        # remove balanced esc(...) call spans, string-aware
        out, i, n = [], 0, len(stripped)
        while i < n:
            c = stripped[i]
            if c in "'\"":
                j = i + 1
                while j < n and stripped[j] != c:
                    j += 2 if stripped[j] == "\\" else 1
                out.append(stripped[i:j + 1])
                i = j + 1
                continue
            if re.match(r"esc\s*\(", stripped[i:]):
                depth, k = 0, i
                while k < n:
                    ck = stripped[k]
                    if ck in "'\"":
                        k += 1
                        while k < n and stripped[k] != ck:
                            k += 2 if stripped[k] == "\\" else 1
                        k += 1
                        continue
                    if ck == "(":
                        depth += 1
                    elif ck == ")":
                        depth -= 1
                        if depth == 0:
                            k += 1
                            break
                    k += 1
                out.append("''")
                i = k
                continue
            out.append(c)
            i += 1
        residue = "".join(out)
        residue = re.sub(r"'(?:[^'\\]|\\.)*'", "''", residue)
        for field in untrusted:
            assert field not in residue, (field, stmt[:80])
    # pinned byte patterns: the receipts sink timestamp and ledger line escapes
    # (audit5/live-e2e: two sinks now touch #receipts — the degraded-card line
    # and the ledger render; the pins target the RENDER sink)
    receipts_stmt = next(s for s in sinks if "slice(-40)" in s)
    # audit5/judge-experience: ts is now rendered via new Date(...).toLocaleTimeString
    # (local clock) — the invariant pinned here is that e.ts only ever reaches
    # the DOM through esc(...).
    assert "esc(e.ts" in receipts_stmt

    assert receipts_stmt.count("esc(line)") == 2  # title attribute AND text node
    # trusted ledger-literal placement pinned: badgeFor(step) drives the class,
    # step is the raw trusted ledger literal (audit3/console-logic markup)
    pinned = '<span class="badge \' + badgeFor(step) + \'">\' + step + \'</span>'
    assert pinned in receipts_stmt


def test_esc_function_covers_all_html_metacharacters_and_quotes():
    src = INDEX.read_text(encoding="utf-8")
    m = re.search(r"const esc = \(s\) => String\(s\)\.replace\(/\[\&<>\"'\]/g", src)
    assert m, "esc() charset must include & < > double and single quotes"
    # the full statement runs to the end of the line (&amp; itself contains a ;)
    body = src[m.start():src.index("\n", m.start())]
    for pair in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
        assert pair in body
