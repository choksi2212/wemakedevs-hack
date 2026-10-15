"""CaseLog JSONL ledger — append-only, atomic, crash-tolerant (audit3/console-logic).

DB-free: exercises the receipts ledger directly. The live counterparts ran
against a real console: 20-thread concurrent /api/finding bursts and a
500-finding growth soak (prefix-hash prove no line was ever rewritten).
"""
from __future__ import annotations

import json
import threading

import pytest

from sever.memory.flow import CaseLog


def test_concurrent_appends_interleave_only_whole_lines(tmp_path):
    """20 threads x 25 appends: every receipt survives, byte-exact — a line
    can never be split or merged by concurrent writers."""
    log = CaseLog("sever_audit3_cl_caselog", root=tmp_path)

    def worker(tid: int) -> None:
        for i in range(25):
            log.append({"step": "finding", "tid": tid, "i": i, "pad": "x" * 512})

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    events = log.read()
    assert len(events) == 500
    seen = {(e["tid"], e["i"]) for e in events}
    assert len(seen) == 500, "no receipt may be lost or duplicated by interleaving"


def test_append_never_rewrites_earlier_lines(tmp_path):
    log = CaseLog("t", root=tmp_path)
    log.append({"step": "a", "v": 1})
    prefix = log.path.read_bytes()
    for i in range(50):
        log.append({"step": "b", "i": i, "pad": "y" * 1024})
    assert log.path.read_bytes().startswith(prefix), "appends only — no rewrite"
    assert log.read()[0]["v"] == 1


def test_torn_trailing_line_is_tolerated_and_repaired(tmp_path):
    """A writer killed mid-line leaves a torn tail: read() must keep working
    (skip the fragment), and the next append must terminate the fragment so
    it can never MERGE with the new receipt line."""
    log = CaseLog("t", root=tmp_path)
    log.append({"step": "a", "v": 1})
    with log.path.open("ab") as f:
        f.write(b'{"step": "torn", "v": ')  # crash window: no trailing newline

    events = log.read()  # must not raise — the tail is skipped, not fatal
    assert [e["v"] for e in events] == [1]

    log.append({"step": "c", "v": 3})  # repair: fragment terminated + stamped
    events = log.read()
    assert [e["step"] for e in events] == ["a", "ledger_repair", "c"]
    # and further appends keep the ledger healthy
    log.append({"step": "d", "v": 4})
    assert [e["step"] for e in log.read()] == ["a", "ledger_repair", "c", "d"]


def test_corrupt_midfile_line_surfaces_loudly(tmp_path):
    """A COMPLETE line that does not parse and is not repair-stamped is real
    corruption: read() raises — corruption is never silently dropped."""
    log = CaseLog("t", root=tmp_path)
    log.append({"step": "a"})
    with log.path.open("ab") as f:
        f.write(b'{"step": "CORRUPT\n')  # complete line, unparseable
    log.append({"step": "b"})
    with pytest.raises(RuntimeError):
        log.read()


def test_torn_tail_that_parses_is_recovered_not_dropped(tmp_path):
    """A writer that died after the JSON but before the newline: the receipt
    is complete — read() recovers it instead of warning it away."""
    log = CaseLog("t", root=tmp_path)
    log.append({"step": "a"})
    with log.path.open("ab") as f:
        f.write(json.dumps({"step": "complete", "v": 2}).encode())  # no \n
    assert [e["step"] for e in log.read()] == ["a", "complete"]


def test_legacy_crlf_ledger_stays_compatible(tmp_path):
    """Files written by the pre-fix text-mode append carry \r\n endings —
    read() must parse them and new appends must not corrupt the mix."""
    p = tmp_path / "t.jsonl"
    p.write_bytes(b'{"step": "legacy"}\r\n')
    log = CaseLog("t", root=tmp_path)
    assert log.read()[0]["step"] == "legacy"
    log.append({"step": "new"})
    assert [e["step"] for e in log.read()] == ["legacy", "new"]


def test_lone_surrogate_cannot_poison_the_file(tmp_path):
    """append() writes ensure_ascii=True bytes: even a hostile event object
    can never land raw surrogates in the file and break a future read."""
    log = CaseLog("t", root=tmp_path)
    log.append({"step": "weird", "v": "\ud800"})
    raw = log.path.read_bytes()
    assert b'{"ts":' in raw[:8]
    assert b"\\ud800" in raw, "surrogates are written escaped, never raw"
    assert log.read()[0]["step"] == "weird"
