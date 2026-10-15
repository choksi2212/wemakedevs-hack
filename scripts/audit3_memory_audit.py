"""audit3/memory-flow live receipts — the adversarial Track-2 substrate audit.

Every beat runs against the LIVE engine, and every process boundary that the
audit is ABOUT is a real OS process boundary (subprocess / Popen / hard
taskkill), never a thread:

    python scripts/audit3_memory_audit.py isolate --graph sever_audit3_mem
        Multi-THREAD isolation: start A, start B, resume A, resume B via
        scripts/case_memory_live.py --thread on ONE graph + checkpointer;
        each resume's remembered finding/subject/proposal is compared
        against its own stored checkpoint; plus the fleet-2 resume-safety
        rules re-verified live (double-resume no-op, truthy-stand-in gate,
        refuse-non-gate) and the per-thread checkpoint rows in the DB.

    python scripts/audit3_memory_audit.py durability --graph sever_audit3_mem --port 8183
        Pause at the gate, hard-kill the operator console (a uvicorn
        instance) AND the paused case holder (taskkill /F), restart the
        console, then resume the case from a FRESH process — the remembered
        state must equal the pre-kill checkpoint.

    python scripts/audit3_memory_audit.py delfail --graph sever_audit3_mem
        Pause at the gate, DEL the checkpoints key mid-case, then resume:
        must fail-closed with a clear error, never resume a wrong/empty
        state, never mint a new investigation.

    python scripts/audit3_memory_audit.py caselog-live --graph sever_audit3_mem --ports 8181 8182
        Two CONSOLE PROCESSES appending to the same tenant CaseLog
        concurrently (real parallel, not threads): every line valid JSON,
        no interleaved partials, no lost events.

    python scripts/audit3_memory_audit.py cleanup --graph sever_audit3_mem
        Delete every sever_audit3_mem* graph key and verify KEYS is empty.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()

from falkordb import FalkorDB
from langchain_falkordb.checkpoint import FalkorDBSaver

from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import parse_ad_dir
from sever.memory.flow import build_flow, resume_investigation

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"  # T1_TONYMONTANA@PHANTOM.CORP
SCRIPT = Path(__file__).resolve().parent / "case_memory_live.py"
OUT = Path("out") / "audit3_mem"


# ---------------------------------------------------------------- helpers ----


def _port(graph: str) -> FalkorGraphPort:
    return FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=graph,
        username=os.environ.get("SEVER_FALKOR_USER"),
        password=os.environ.get("SEVER_FALKOR_PASSWORD"),
    )


def _saver(graph: str) -> FalkorDBSaver:
    return FalkorDBSaver(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        username=os.environ.get("SEVER_FALKOR_USER"),
        password=os.environ.get("SEVER_FALKOR_PASSWORD"),
        database=f"{graph}_checkpoints",
    )


def _client(graph: str):
    fdb = FalkorDB(host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
                   port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")))
    return fdb.select_graph(graph).client


def _hard_reset(graph: str) -> dict:
    """Fresh graph + fresh checkpoint store; ignore missing-key raises."""
    client = _client(graph)
    reset = {}
    for key in (graph, f"{graph}_checkpoints"):
        try:
            client.execute_command("GRAPH.DELETE", key)
            reset[key] = "deleted"
        except Exception as exc:  # missing key raises — idempotent reset
            reset[key] = f"absent ({type(exc).__name__})"
    port = _port(graph)
    loaded = port.node_count()
    if loaded == 0:
        normalized = parse_ad_dir(os.environ.get(
            "SEVER_SAMPLE_DIR", str(Path(__file__).resolve().parents[1] / "data" / "ad_sample")))
        port.load(normalized)
        loaded = port.node_count()
    return {"reset": reset, "nodes": loaded, "edges": port.edge_count()}


def _snapshot_thread(graph: str, thread: str) -> dict:
    """Read-only view of one thread's case memory straight from the DB."""
    flow = build_flow(_port(graph), checkpointer=_saver(graph))
    snap = flow.get_state({"configurable": {"thread_id": thread}})
    return {"thread": thread, "values": snap.values, "next": list(snap.next)}


def _sub(args: list[str], timeout: int = 300) -> dict:
    """Run a real subprocess (case_memory_live.py beat) with full capture."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
    )
    return {"args": args, "returncode": proc.returncode,
            "stdout": proc.stdout, "stderr": proc.stderr[-4000:]}


def _write_receipt(name: str, payload: dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print(f"[audit3] receipts -> {path}")
    return path


def _check(cond: bool, label: str, failures: list[str]) -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"[audit3] {mark}: {label}")
    if not cond:
        failures.append(label)


def _launch_console(graph: str, port: int, logname: str):
    env = {**os.environ, "SEVER_FALKOR_GRAPH": graph}
    OUT.mkdir(parents=True, exist_ok=True)
    logfile = open(OUT / logname, "wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "sever.console.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(Path(__file__).resolve().parents[1]),
        env=env, stdout=logfile, stderr=subprocess.STDOUT,
    )
    _wait_http(port, 45.0)
    return proc


def _wait_http(port: int, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=5) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"console on 127.0.0.1:{port} never became ready")


def _get_state(port: int) -> dict:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def _get_receipts(port: int) -> list:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/receipts", timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def _taskkill(pid: int) -> dict:
    proc = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True, text=True)
    return {"pid": pid, "returncode": proc.returncode,
            "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}


def _pick_subject_b(port: FalkorGraphPort, hero: str) -> tuple[str | None, dict]:
    """A principal in ANOTHER domain that already reaches a jewel — so case
    B's remembered state is provably distinct from case A's."""
    tried = 0
    for prefix in ("S-1-5-21-2845847946", "S-1-5-21-3702535222"):
        rows = port.graph.query(
            "MATCH (u:User) WHERE u.objectid STARTS WITH $p RETURN u.objectid AS o "
            "ORDER BY o LIMIT 40", {"p": prefix}).result_set
        for row in rows:
            oid = str(row[0])
            tried += 1
            if oid != hero and port.paths_to_jewels(oid):
                return oid, {"mode": "inherent_path", "candidates_tried": tried}
    # fallback: grant a breach edge (the finding-stream's own semantics)
    jewels = [j for j in port.crown_jewels() if j.startswith("S-1-5-21-2845847946")]
    rows = port.graph.query(
        "MATCH (u:User) WHERE u.objectid STARTS WITH $p RETURN u.objectid AS o "
        "ORDER BY o LIMIT 1", {"p": "S-1-5-21-2845847946"}).result_set
    if jewels and rows:
        subject = str(rows[0][0])
        granted = port.add_edge(subject, jewels[0], "GENERIC_ALL", {"source": "F-B-grant"})
        return subject, {"mode": "granted_edge", "jewel": jewels[0], "granted": granted,
                         "candidates_tried": tried}
    return None, {"mode": "none", "candidates_tried": tried}


# ------------------------------------------------------------------ beats ----


def do_isolate(args: argparse.Namespace) -> int:
    failures: list[str] = []
    receipt: dict = {"beat": "multi-thread isolation + fleet-2 resume-safety (live)",
                     "graph": args.graph}
    OUT.mkdir(parents=True, exist_ok=True)  # subprocess receipts land here too
    receipt["setup"] = _hard_reset(args.graph)
    port = _port(args.graph)

    subject_b, how = _pick_subject_b(port, HERO)
    receipt["subject_b"] = {"objectid": subject_b, **how}
    print(f"[audit3] case-B subject: {subject_b} ({how})")
    if subject_b is None:
        print("[audit3] FAIL: no distinct subject for case-B")
        return 1

    # ---- start A, start B: each its own process via the case script ----
    start_a = _sub(["start", "--thread", "case-A", "--graph", args.graph,
                    "--finding-id", "F-A", "--subject", HERO])
    start_b = _sub(["start", "--thread", "case-B", "--graph", args.graph,
                    "--finding-id", "F-B", "--subject", subject_b])
    receipt["start_a"] = start_a
    receipt["start_b"] = start_b
    _check(start_a["returncode"] == 0, "start A exited 0", failures)
    _check(start_b["returncode"] == 0, "start B exited 0", failures)

    s_a = _snapshot_thread(args.graph, "case-A")
    s_b = _snapshot_thread(args.graph, "case-B")
    receipt["paused_case_A"] = s_a
    receipt["paused_case_B"] = s_b
    _check(s_a["values"].get("step") == "awaiting_approval", "case-A paused at the gate", failures)
    _check(s_b["values"].get("step") == "awaiting_approval", "case-B paused at the gate", failures)
    _check(s_a["values"].get("triage", {}).get("finding") == "F-A", "case-A checkpoint carries F-A", failures)
    _check(s_b["values"].get("triage", {}).get("finding") == "F-B", "case-B checkpoint carries F-B", failures)
    _check(s_a["values"].get("proposal") != [], "case-A has a ranked proposal", failures)
    _check(s_b["values"].get("proposal") != [], "case-B has a ranked proposal", failures)

    # ---- resume A, resume B: fresh processes, mandated interleave order ----
    resume_a = _sub(["resume", "--thread", "case-A", "--graph", args.graph,
                     "--approved-by", "A-op", "--out", "out/audit3_mem/receipt_case-A.json"])
    resume_b = _sub(["resume", "--thread", "case-B", "--graph", args.graph,
                     "--approved-by", "B-op", "--out", "out/audit3_mem/receipt_case-B.json"])
    receipt["resume_a"] = resume_a
    receipt["resume_b"] = resume_b
    _check(resume_a["returncode"] == 0, "resume A exited 0", failures)
    _check(resume_b["returncode"] == 0, "resume B exited 0", failures)

    r_a = _snapshot_thread(args.graph, "case-A")
    r_b = _snapshot_thread(args.graph, "case-B")
    receipt["resumed_case_A"] = r_a
    receipt["resumed_case_B"] = r_b

    # remembered finding/subject/proposal vs each thread's OWN checkpoint
    for label, resumed, paused, fid, subj in (
        ("A", r_a, s_a, "F-A", HERO), ("B", r_b, s_b, "F-B", subject_b),
    ):
        vals = resumed["values"]
        _check(vals.get("triage", {}).get("finding") == fid,
               f"resume {label} remembered ITS finding {fid}", failures)
        _check(vals.get("subject") == subj,
               f"resume {label} remembered ITS subject", failures)
        _check(vals.get("proposal") == paused["values"].get("proposal"),
               f"resume {label} proposal == its own stored checkpoint", failures)
        cut = vals.get("receipt", {}).get("cut", {})
        top = (paused["values"].get("proposal") or [{}])[0]
        _check(cut.get("src") == top.get("src") and cut.get("dst") == top.get("dst")
               and cut.get("rel") == top.get("rel"),
               f"resume {label} executed ITS OWN stored top proposal", failures)
    # cross-contamination: A must not remember B's identity and vice versa
    _check(r_a["values"].get("triage", {}).get("finding") != "F-B",
           "no cross-contamination: A does not remember B's finding", failures)
    _check(r_b["values"].get("triage", {}).get("finding") != "F-A",
           "no cross-contamination: B does not remember A's finding", failures)
    _check(r_a["values"].get("subject") != subject_b,
           "no cross-contamination: A does not remember B's subject", failures)

    receipt["verdicts"] = {
        "A": r_a["values"].get("receipt", {}).get("verdict"),
        "B": r_b["values"].get("receipt", {}).get("verdict"),
        "B_cut_removed": r_b["values"].get("receipt", {}).get("cut", {}).get("relationships_removed"),
    }
    print(f"[audit3] verdicts: {receipt['verdicts']}")

    # ---- fleet-2 rule 3: double-resume is a fail-closed no-op ----
    reach_after_b = port.reachability()
    flow = build_flow(port, checkpointer=_saver(args.graph))
    try:
        resume_investigation(flow, "case-A", approve=True, approved_by="evil-twin")
        double_resume = {"raised": False}
        _check(False, "double-resume on completed case-A raised", failures)
    except ValueError as exc:
        double_resume = {"raised": True, "type": type(exc).__name__, "message": str(exc)}
        _check("not paused at the gate" in str(exc),
               "double-resume raises the not-paused-at-gate error", failures)
    receipt["double_resume_case_A"] = double_resume
    after_double = _snapshot_thread(args.graph, "case-A")
    receipt["case_A_after_double_resume"] = after_double
    _check(after_double["values"] == r_a["values"],
           "double-resume mutated NOTHING (state identical)", failures)
    _check(port.reachability() == reach_after_b,
           "double-resume executed NO second cut (reachability unchanged)", failures)

    # ---- fleet-2 rule 1: truthy stand-in closes the gate (live re-verify) ----
    start_c = _sub(["start", "--thread", "case-C", "--graph", args.graph,
                    "--finding-id", "F-C", "--subject", subject_b])
    receipt["start_c"] = {k: start_c[k] for k in ("returncode", "stdout")}
    _check(start_c["returncode"] == 0, "start C (stand-in pin) exited 0", failures)
    before_stand = port.reachability()
    cfg = {"configurable": {"thread_id": "case-C"}}
    flow.update_state(cfg, {"approved": "yes"})  # truthy, NOT the bool True
    flow.invoke(None, config=cfg)
    r_c = flow.get_state(cfg).values
    receipt["standin_case_C"] = {"step": r_c.get("step"), "receipt_present": "receipt" in r_c,
                                 "proposal_len": len(r_c.get("proposal", []))}
    _check(r_c.get("step") == "gate_closed", "truthy stand-in 'yes' closes the gate", failures)
    _check("receipt" not in r_c, "truthy stand-in executed no cut", failures)
    _check(port.reachability() == before_stand, "reachability unchanged by the stand-in", failures)

    # ---- fleet-2 rule 2: refuse a thread not paused at the gate ----
    try:
        resume_investigation(flow, "audit3-never-started", approve=True)
        refuse = {"raised": False}
        _check(False, "resume of never-started thread raised", failures)
    except ValueError as exc:
        refuse = {"raised": True, "type": type(exc).__name__, "message": str(exc)}
        _check("not paused at the gate" in str(exc), "never-started thread refused", failures)
    receipt["refuse_never_started"] = refuse

    # ---- substrate: per-thread rows in the checkpoint graph ----
    fdb = FalkorDB(host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
                   port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")))
    ck = fdb.select_graph(f"{args.graph}_checkpoints")
    ck_rows = [list(r) for r in ck.query(
        "MATCH (c:Checkpoint) RETURN c.thread_id AS t, count(c) AS n ORDER BY t").result_set]
    blob_rows = [list(r) for r in ck.query(
        "MATCH (b:CheckpointBlob) RETURN b.thread_id AS t, count(b) AS n ORDER BY t").result_set]
    receipt["checkpoint_graph"] = {"checkpoints": ck_rows, "blobs": blob_rows}
    threads = {row[0] for row in ck_rows}
    _check({"case-A", "case-B", "case-C"} <= threads,
           "each thread has its OWN checkpoint rows", failures)

    receipt["failures"] = failures
    receipt["all_pass"] = not failures
    _write_receipt("receipts_isolation.json", receipt)
    print(f"[audit3] isolate: {'ALL PASS' if not failures else 'FAILURES: ' + str(failures)}")
    return 0 if not failures else 1


def do_durability(args: argparse.Namespace) -> int:
    failures: list[str] = []
    receipt: dict = {"beat": "kill-the-console durability + fresh-process resume (live)",
                     "graph": args.graph, "port": args.port}
    receipt["setup"] = _hard_reset(args.graph)
    port = _port(args.graph)

    # my own console instance, running while the case is opened
    console = _launch_console(args.graph, args.port, "console_durability_1.log")
    receipt["console_pid"] = console.pid
    prekill_events = [_get_state(args.port) for _ in range(3)]  # ledger appends
    receipts_before = _get_receipts(args.port)
    receipt["console_prekill"] = {"state_events": len(prekill_events),
                                  "ledger_events": len(receipts_before),
                                  "reachability": prekill_events[-1]["reachability"]}
    _check(len(receipts_before) >= 3, "console appended >=3 ledger events pre-kill", failures)

    # pause at the gate and HOLD (a real operator session with the case open)
    OUT.mkdir(parents=True, exist_ok=True)
    pidfile = "out/audit3_mem/holder_case-DUR.pid"
    holder_log = open(OUT / "holder_case-DUR.log", "wb")
    holder = subprocess.Popen(
        [sys.executable, str(SCRIPT), "start", "--thread", "case-DUR", "--graph", args.graph,
         "--finding-id", "F-DUR", "--subject", HERO, "--hold-seconds", "900",
         "--pidfile", pidfile],
        cwd=str(Path(__file__).resolve().parents[1]),
        stdout=holder_log, stderr=subprocess.STDOUT,
    )
    pid_path = Path(__file__).resolve().parents[1] / pidfile
    deadline = time.time() + 240
    while not pid_path.exists() and time.time() < deadline:
        time.sleep(1)
    _check(pid_path.exists(), "holder paused at the gate and published its pid", failures)
    holder_pid = int(pid_path.read_text(encoding="ascii").strip())
    receipt["holder_pid"] = holder_pid

    s_dur = _snapshot_thread(args.graph, "case-DUR")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "paused_case-DUR.json").write_text(
        json.dumps(s_dur, indent=2, default=str), encoding="utf-8")
    receipt["paused_case_DUR"] = {
        "step": s_dur["values"].get("step"),
        "finding": s_dur["values"].get("triage", {}).get("finding"),
        "proposal_top": (s_dur["values"].get("proposal") or [{}])[0],
        "reachability": port.reachability(),
    }
    _check(s_dur["values"].get("step") == "awaiting_approval", "case-DUR paused at the gate", failures)

    # ---- hard-kill BOTH the console and the paused case holder ----
    receipt["kill_console"] = _taskkill(console.pid)
    receipt["kill_holder"] = _taskkill(holder_pid)
    _check(receipt["kill_console"]["returncode"] == 0, "console hard-killed (taskkill /F /T)", failures)
    _check(receipt["kill_holder"]["returncode"] == 0, "holder hard-killed (taskkill /F)", failures)
    _check(pid_path.exists(), "holder pidfile survived the hard kill (no cleanup ran)", failures)
    rekill = _taskkill(holder_pid)
    receipt["rekill_holder"] = rekill
    _check(rekill["returncode"] != 0, "holder process is GONE (second taskkill fails)", failures)

    # ---- restart the console, then resume from a FRESH process ----
    console2 = _launch_console(args.graph, args.port, "console_durability_2.log")
    receipt["console2_pid"] = console2.pid
    receipts_after = _get_receipts(args.port)
    receipt["console_post_restart"] = {"ledger_events": len(receipts_after),
                                        "reachability": _get_state(args.port)["reachability"]}
    _check(len(receipts_after) >= len(receipts_before),
           "console restart: pre-kill ledger events all survived", failures)

    resume = _sub(["resume", "--thread", "case-DUR", "--graph", args.graph,
                   "--approved-by", "night-shift",
                   "--out", "out/audit3_mem/receipt_case-DUR.json"])
    receipt["resume_fresh_process"] = resume
    _check(resume["returncode"] == 0, "fresh process resumed the killed case", failures)

    r_dur = _snapshot_thread(args.graph, "case-DUR")
    receipt["resumed_case_DUR"] = r_dur
    _check(r_dur["values"].get("triage", {}).get("finding") == "F-DUR",
           "resume remembered finding F-DUR from the pre-kill checkpoint", failures)
    _check(r_dur["values"].get("proposal") == s_dur["values"].get("proposal"),
           "resume remembered the EXACT pre-kill stored proposal", failures)
    top = (s_dur["values"].get("proposal") or [{}])[0]
    cut = r_dur["values"].get("receipt", {}).get("cut", {})
    _check(cut.get("src") == top.get("src") and cut.get("dst") == top.get("dst")
           and cut.get("rel") == top.get("rel"),
           "resume executed the pre-kill stored top proposal", failures)
    _check(r_dur["values"].get("receipt", {}).get("verdict") == "collapsed",
           "kill-console resume collapsed the breach", failures)
    _check(port.reachability() == 0, "reachability collapsed to 0 after resume", failures)

    receipt["failures"] = failures
    receipt["all_pass"] = not failures
    _write_receipt("receipts_durability.json", receipt)
    # leave the restarted console running? no — this beat owns it
    receipt["stop_console2"] = _taskkill(console2.pid)
    print(f"[audit3] durability: {'ALL PASS' if not failures else 'FAILURES: ' + str(failures)}")
    return 0 if not failures else 1


def do_delfail(args: argparse.Namespace) -> int:
    failures: list[str] = []
    receipt: dict = {"beat": "DEL checkpoints key mid-case -> resume must fail-closed (live)",
                     "graph": args.graph}
    receipt["setup"] = _hard_reset(args.graph)
    port = _port(args.graph)
    client = _client(args.graph)

    start = _sub(["start", "--thread", "case-DEL", "--graph", args.graph,
                  "--finding-id", "F-DEL", "--subject", HERO])
    receipt["start_case_DEL"] = start
    _check(start["returncode"] == 0, "case-DEL paused at the gate", failures)
    s_del = _snapshot_thread(args.graph, "case-DEL")
    receipt["paused_case_DEL"] = {
        "step": s_del["values"].get("step"),
        "finding": s_del["values"].get("triage", {}).get("finding"),
        "proposal_top": (s_del["values"].get("proposal") or [{}])[0],
    }
    _check(s_del["values"].get("step") == "awaiting_approval", "case-DEL really paused", failures)
    _check(s_del["values"].get("proposal") != [], "case-DEL has a stored proposal", failures)

    edges_before, reach_before = port.edge_count(), port.reachability()

    # ---- DEL the checkpoint store mid-case ----
    ckpt_key = f"{args.graph}_checkpoints"
    receipt["del"] = {"key": ckpt_key,
                     "response": client.execute_command("DEL", ckpt_key),
                     "exists_after": client.execute_command("EXISTS", ckpt_key)}
    _check(receipt["del"]["exists_after"] == 0, "checkpoints key DELted mid-case", failures)

    # ---- fresh-process resume: must fail-closed with a clear error ----
    resume = _sub(["resume", "--thread", "case-DEL", "--graph", args.graph,
                   "--approved-by", "night-shift",
                   "--out", "out/audit3_mem/receipt_case-DEL.json"])
    receipt["resume_after_del"] = resume
    _check(resume["returncode"] != 0, "resume after DEL exited non-zero (fail-closed)", failures)
    _check("not paused at the gate" in resume["stderr"],
           "fresh-process resume failed with the CLEAR not-paused-at-gate error", failures)
    _check("Traceback" in resume["stderr"], "error surfaced as a traceback, not silence", failures)

    # in-process probe of the exact error path
    try:
        resume_investigation(build_flow(port, checkpointer=_saver(args.graph)),
                             "case-DEL", approve=True, approved_by="night-shift")
        receipt["in_process_resume"] = {"raised": False}
        _check(False, "in-process resume after DEL raised", failures)
    except Exception as exc:
        receipt["in_process_resume"] = {"raised": True, "type": type(exc).__name__,
                                        "message": str(exc)}
        _check(isinstance(exc, ValueError) and "not paused at the gate" in str(exc),
               "exact error path: ValueError('thread ... is not paused at the gate')", failures)

    # ---- never resume a WRONG/EMPTY state; never mint; never mutate ----
    edges_after, reach_after = port.edge_count(), port.reachability()
    receipt["no_mutation"] = {"edges": [edges_before, edges_after],
                              "reachability": [reach_before, reach_after]}
    _check(edges_after == edges_before, "no edge was cut by the failed resume", failures)
    _check(reach_after == reach_before, "reachability unchanged by the failed resume", failures)
    post = _snapshot_thread(args.graph, "case-DEL")
    receipt["case_DEL_after_del"] = post
    _check(post["values"] == {} and post["next"] == [],
           "case-DEL was NOT minted/rewritten: empty snapshot, no pending node", failures)

    # the failed resume re-created an EMPTY checkpoints graph (index-only) — record it
    fdb = FalkorDB(host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
                   port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")))
    ck = fdb.select_graph(ckpt_key)
    receipt["checkpoints_graph_recreated"] = {
        "node_count": ck.query("MATCH (n) RETURN count(n)").result_set[0][0]}
    _check(receipt["checkpoints_graph_recreated"]["node_count"] == 0,
           "re-created checkpoints graph is EMPTY (no case state was fabricated)", failures)

    # ---- the substrate is not wedged: a fresh start mints a new case ----
    post_start = _sub(["start", "--thread", "case-POST", "--graph", args.graph,
                       "--finding-id", "F-POST", "--subject", HERO])
    receipt["start_case_POST"] = {"returncode": post_start["returncode"],
                                  "stdout_tail": post_start["stdout"][-300:]}
    _check(post_start["returncode"] == 0, "fresh start still works after the fail-closed resume", failures)
    s_post = _snapshot_thread(args.graph, "case-POST")
    _check(s_post["values"].get("step") == "awaiting_approval",
           "case-POST paused at the gate on the re-created store", failures)

    receipt["failures"] = failures
    receipt["all_pass"] = not failures
    _write_receipt("receipts_delfail.json", receipt)
    print(f"[audit3] delfail: {'ALL PASS' if not failures else 'FAILURES: ' + str(failures)}")
    return 0 if not failures else 1


def do_caselog_live(args: argparse.Namespace) -> int:
    failures: list[str] = []
    receipt: dict = {"beat": "CaseLog under two CONSOLE PROCESSES (live)", "graph": args.graph}
    port = _port(args.graph)
    if port.node_count() == 0:  # consoles auto-load, but keep the beat honest
        _hard_reset(args.graph)

    ledger = Path(__file__).resolve().parents[1] / "out" / "cases" / f"{args.graph}.jsonl"
    for stale in (ledger, Path(str(ledger) + ".lock")):
        if stale.exists():
            stale.unlink()

    p1, p2 = args.ports
    console1 = _launch_console(args.graph, p1, f"console_caselog_{p1}.log")
    console2 = _launch_console(args.graph, p2, f"console_caselog_{p2}.log")
    receipt["console_pids"] = [console1.pid, console2.pid]

    # the readiness poll itself appends state events — start the ledger fresh
    # NOW, with both console processes already live and healthy
    for stale in (ledger, Path(str(ledger) + ".lock")):
        if stale.exists():
            stale.unlink()

    def hammer(portno: int) -> list[int]:
        codes = []
        for _ in range(args.requests):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{portno}/api/state", timeout=30) as r:
                    codes.append(r.status)
            except Exception as exc:
                codes.append(str(exc)[:80])
        return codes

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut1 = pool.submit(hammer, p1)
        fut2 = pool.submit(hammer, p2)
        codes1, codes2 = fut1.result(), fut2.result()
    receipt["requests"] = {"port1": {"count": len(codes1), "all_200": all(c == 200 for c in codes1)},
                           "port2": {"count": len(codes2), "all_200": all(c == 200 for c in codes2)}}
    _check(all(c == 200 for c in codes1 + codes2), "all console requests 200", failures)

    receipt["stop_consoles"] = [_taskkill(console1.pid), _taskkill(console2.pid)]

    # verify with BOTH readers: the product's own CaseLog reader and raw text
    from sever.memory.flow import CaseLog

    events = CaseLog(args.graph).read()
    raw_lines = ledger.read_text(encoding="utf-8").splitlines()
    receipt["ledger"] = {"path": str(ledger), "raw_lines": len(raw_lines),
                         "events_read": len(events)}
    _check(len(raw_lines) == 2 * args.requests,
           f"ledger holds exactly {2 * args.requests} lines (no loss, no dup)", failures)
    _check(len(events) == len(raw_lines), "CaseLog.read() parses EVERY line", failures)
    bad = [i for i, ev in enumerate(events)
           if ev.get("step") != "state" or "ts" not in ev or "reachability" not in ev]
    _check(not bad, "every ledger line is a complete valid state event", failures)
    receipt["ledger_first_last"] = {"first": events[0], "last": events[-1]}

    receipt["failures"] = failures
    receipt["all_pass"] = not failures
    _write_receipt("receipts_caselog.json", receipt)
    print(f"[audit3] caselog-live: {'ALL PASS' if not failures else 'FAILURES: ' + str(failures)}")
    return 0 if not failures else 1


def do_cleanup(args: argparse.Namespace) -> int:
    client = _client(args.graph)
    patterns = (f"{args.graph}*", f"telemetry{{{args.graph}*")  # + engine sidecar keys
    keys: list[str] = []
    for pattern in patterns:
        keys += [k.decode() if isinstance(k, bytes) else str(k)
                 for k in client.execute_command("KEYS", pattern)]
    print(f"[audit3] keys before cleanup: {keys}")
    for key in keys:
        try:
            client.execute_command("GRAPH.DELETE", key)
            print(f"[audit3] GRAPH.DELETE {key} -> done")
        except Exception as exc:
            try:
                client.execute_command("DEL", key)
                print(f"[audit3] DEL {key} -> done")
            except Exception as exc2:
                print(f"[audit3] {key}: GRAPH.DELETE raised {type(exc).__name__}; "
                      f"DEL raised {type(exc2).__name__} — ignored")
    remaining: list[str] = []
    for pattern in patterns:
        remaining += [k.decode() if isinstance(k, bytes) else str(k)
                      for k in client.execute_command("KEYS", pattern)]
    print(f"[audit3] keys after cleanup: {remaining}")
    print("[audit3] cleanup verified" if not remaining else "[audit3] CLEANUP INCOMPLETE")
    return 0 if not remaining else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="audit3/memory-flow live receipts")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, fn in (("isolate", do_isolate), ("durability", do_durability),
                     ("delfail", do_delfail), ("caselog-live", do_caselog_live),
                     ("cleanup", do_cleanup)):
        p = sub.add_parser(name)
        p.add_argument("--graph", default="sever_audit3_mem")
        if name == "durability":
            p.add_argument("--port", type=int, default=8183,
                           help="port for this audit's own console instance")
        if name == "caselog-live":
            p.add_argument("--ports", nargs=2, type=int, default=[8181, 8182],
                           help="ports for the two concurrent console processes")
            p.add_argument("--requests", type=int, default=40,
                           help="GET /api/state requests per console process")
        p.set_defaults(fn=fn)
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
