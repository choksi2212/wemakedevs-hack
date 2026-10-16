"""Static undefined-name check — the bfe9308 lesson as a gate (audit5/incident-verify).

The socket-timeout patch shipped `os.environ.get(...)` without `import os`.
Every DB-free test passed because the graph client is stubbed there; the bug
only fired on a REAL boot (Render deploy -> update_failed). pyflakes would have
caught it, but nothing ran pyflakes — so this script is the check, wired into
the suite as tests/test_static_imports.py.

Approach (deliberately conservative, zero-config, stdlib-only):
for each .py file, collect every name BOUND anywhere in the module (imports,
def/class names, assignment and loop targets, `with`/`except`/comprehension
targets, parameters, global/nonlocal declarations) and every name READ; any
read name that is bound nowhere in the module and is not a Python builtin is
reported with file:line — the exact NameError class that only bites at boot.

Conservative means it can only under-report (a name bound in one function and
misused in another slips through), never false-positive — the right bias for a
suite gate.

Usage:
    python scripts/check_missing_imports.py [paths ...]   # default: sever/
Exit code 1 if any undefined name is found (CI-friendly).
"""
from __future__ import annotations

import ast
import builtins
import sys
from pathlib import Path

_BUILTINS = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__builtins__"}

# A `from x import *` makes the bound-name set unknowable — skip such modules
# rather than guess (none exist in sever/ today; fail loudly if one appears).


def _targets(node: ast.AST, out: set[str]) -> None:
    """Collect every name a node binds (all flavours of assignment target)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del)):
            out.add(sub.id)
        elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(sub.name)
        elif isinstance(sub, ast.MatchAs) and sub.name:
            out.add(sub.name)
        elif isinstance(sub, ast.MatchStar) and sub.name:
            out.add(sub.name)
        elif isinstance(sub, ast.MatchMapping) and sub.rest:
            out.add(sub.rest)
        elif isinstance(sub, ast.arg):
            out.add(sub.arg)
        elif isinstance(sub, ast.ExceptHandler) and sub.name:
            out.add(sub.name)
        elif isinstance(sub, ast.Global) or isinstance(sub, ast.Nonlocal):
            out.update(sub.names)
        elif isinstance(sub, ast.alias):
            out.add(sub.name.split(".")[0])
            if sub.asname:
                out.add(sub.asname)


def check_file(path: Path) -> list[tuple[int, str, str]]:
    """Return [(line, name, snippet)] for every read of a nowhere-bound name."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as e:
        return [(e.lineno or 0, f"<syntax error: {e.msg}>", "")]
    if any(
        isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
        for n in ast.walk(tree)
    ):
        return []  # star import: bound names unknowable — skip, never guess

    # Bind-anywhere-in-module (conservative): one walk collects every binding
    # flavor anywhere — imports, def/class names, parameters (self included),
    # assignment/loop/with/except/comprehension targets, global/nonlocal.
    # _targets() walks each node's whole subtree, so a single call over the
    # module root sees every nested scope's bindings too.
    bound: set[str] = set()
    _targets(tree, bound)
    reads: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            reads.append((node.lineno, node.id, node.id))
    out = []
    lines = None
    for lineno, name, _ in reads:
        if name in bound or name in _BUILTINS:
            continue
        if lines is None:
            lines = path.read_text(encoding="utf-8").splitlines()
        snippet = lines[lineno - 1].strip() if lineno - 1 < len(lines) else ""
        out.append((lineno, name, snippet))
    return out


def check_tree(root: Path) -> dict[str, list[tuple[int, str, str]]]:
    findings: dict[str, list[tuple[int, str, str]]] = {}
    if root.is_file():  # a single-file argument must be checked, not globbed away
        hits = check_file(root)
        if hits:
            findings[str(root)] = hits
        return findings
    for path in sorted(root.rglob("*.py")):
        hits = check_file(path)
        if hits:
            findings[str(path)] = hits
    return findings


def main(argv: list[str]) -> int:
    roots = [Path(a) for a in argv[1:]] or [Path(__file__).resolve().parents[1] / "sever"]
    for root in roots:
        if not root.exists():
            print(f"ERROR: path does not exist: {root}")
            return 2
    findings: dict[str, list[tuple[int, str, str]]] = {}
    for root in roots:
        findings.update(check_tree(root))
    if not findings:
        print("OK: no undefined names in", ", ".join(str(r) for r in roots))
        return 0
    total = 0
    for path, hits in findings.items():
        for lineno, name, snippet in hits:
            total += 1
            print(f"UNDEFINED NAME {path}:{lineno}: '{name}' — {snippet[:100]}")
    print(f"FAIL: {total} undefined name(s)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
