"""audit5/incident-verify: undefined-name gate over sever/ (the bfe9308 lesson).

The socket-timeout patch shipped `os.environ.get(...)` without `import os`.
Every DB-free test passed (the graph client is stubbed there); the NameError
only fired on a REAL boot, killing the Render deploy at ~08:25 IST. This gate
wraps scripts/check_missing_imports.py — a conservative AST check that flags
any name READ in a module that is never bound anywhere in it (import, def,
class, assignment, loop/with/except/comprehension target, parameter) and is
not a builtin. Zero false positives by construction; it can only under-report.

test_no_undefined_names_in_sever  — the gate: sever/ must be clean.
test_checker_flags_the_bfe9308_bug_class — sensitivity pin: the exact shape
    that caused the incident MUST be flagged, and the fixed shape MUST pass.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]


def _load_checker():
    path = _REPO / "scripts" / "check_missing_imports.py"
    spec = importlib.util.spec_from_file_location("check_missing_imports", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_undefined_names_in_sever():
    checker = _load_checker()
    findings = checker.check_tree(_REPO / "sever")
    assert not findings, (
        "undefined names in sever/ (the NameError-on-boot class the stubbed "
        "DB-free suite cannot see):\n"
        + "\n".join(
            f"{path}:{lineno}: {name!r} — {snippet}"
            for path, hits in findings.items()
            for lineno, name, snippet in hits
        )
    )


def test_checker_flags_the_bfe9308_bug_class(tmp_path):
    checker = _load_checker()
    # the exact incident shape: os.environ read, os never imported
    bad = tmp_path / "bad_port.py"
    bad.write_text(
        "def boot():\n"
        "    return os.environ.get('SEVER_FALKOR_SOCKET_TIMEOUT', '30')\n",
        encoding="utf-8",
    )
    hits = checker.check_file(bad)
    assert any(name == "os" for _lineno, name, _snippet in hits), (
        "checker lost sensitivity to the bfe9308 bug class"
    )
    # the fixed shape (import present) must stay silent
    good = tmp_path / "good_port.py"
    good.write_text(
        "import os\n\n\ndef boot():\n"
        "    return os.environ.get('SEVER_FALKOR_SOCKET_TIMEOUT', '30')\n",
        encoding="utf-8",
    )
    assert checker.check_file(good) == []
