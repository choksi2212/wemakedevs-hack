"""Cross-process case memory on LIVE FalkorDB — the T2 hero beat.

Run as TWO separate processes (the "kill -9 / night-shift handoff" story):

    # process 1 — on-call analyst starts the investigation, goes home at the gate
    python scripts/case_memory_live.py start --thread case-T2-live --graph sever_t2

    # process 2 — a FRESH process resumes from shared case memory and executes
    python scripts/case_memory_live.py resume --thread case-T2-live --graph sever_t2 --approved-by night-shift

Case memory lives IN FalkorDB via FalkorDBSaver (langchain-falkordb): the
interrupted thread state — triage results, ranked proposal, everything — is
graph nodes, so any process (or agent) that connects picks the case up.

Multi-case isolation (audit3/memory-flow): ``start`` accepts ``--finding-id``
and ``--subject`` so several threads (case-A, case-B) can run interleaved on
the SAME graph + checkpointer with distinguishable case states;
``--hold-seconds`` keeps the process alive at the gate (writing its pid to
``--pidfile``) so the durability beat can hard-kill the "operator console"
mid-case; ``resume`` accepts ``--out`` so parallel cases keep their own
receipt files.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()  # .env at the repo root, if present — real environment always wins

from langchain_falkordb.checkpoint import FalkorDBSaver

from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import parse_ad_dir
from sever.findings.stream import Finding
from sever.memory.flow import build_flow, resume_investigation, start_investigation

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"  # T1_TONYMONTANA@PHANTOM.CORP


def _checkpointer(graph: str):
    return FalkorDBSaver(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        username=os.environ.get("SEVER_FALKOR_USER"),
        password=os.environ.get("SEVER_FALKOR_PASSWORD"),
        database=f"{graph}_checkpoints",
    )


def _port(graph: str) -> FalkorGraphPort:
    return FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=graph,
        username=os.environ.get("SEVER_FALKOR_USER"),
        password=os.environ.get("SEVER_FALKOR_PASSWORD"),
    )


def _ensure_loaded(port: FalkorGraphPort) -> None:
    if port.node_count() == 0:
        normalized = parse_ad_dir(os.environ.get(
            "SEVER_SAMPLE_DIR",
            str(Path(__file__).resolve().parents[1] / "data" / "ad_sample")))
        port.load(normalized)


def do_start(args: argparse.Namespace) -> int:
    port = _port(args.graph)
    _ensure_loaded(port)
    flow = build_flow(port, checkpointer=_checkpointer(args.graph))
    pending = start_investigation(
        flow, Finding(args.finding_id, "credential_breach", args.subject), args.thread
    )
    print("[t2] investigation paused at the HUMAN GATE (process 1 exiting)")
    print("[t2] thread:", args.thread)
    print("[t2] finding:", args.finding_id, "| subject:", args.subject)
    print("[t2] pending proposal (from shared case memory):")
    for cand in pending.get("proposal", [])[:3]:
        print(f"        {cand['src']} -[{cand['rel']}]-> {cand['dst']} (on {cand['paths_on']} paths)")
    print("[t2] reachability at pause:", pending.get("triage", {}).get("after", {}).get("reachability"))
    if args.hold_seconds > 0:
        pidfile = Path(args.pidfile) if args.pidfile else None
        if pidfile:
            pidfile.parent.mkdir(parents=True, exist_ok=True)
            pidfile.write_text(str(os.getpid()), encoding="ascii")
        print(f"[t2] HOLDING at the gate for {args.hold_seconds}s (pid={os.getpid()}) — kill me")
        print(f"[t2] holding state: step={pending.get('step')} finding={args.finding_id}")
        try:
            time.sleep(args.hold_seconds)
        except KeyboardInterrupt:
            pass
        finally:
            if pidfile and pidfile.exists():
                pidfile.unlink()
        print("[t2] hold expired")
    print("[t2] a FRESH process can resume this case from FalkorDB case memory")
    return 0


def do_resume(args: argparse.Namespace) -> int:
    port = _port(args.graph)
    flow = build_flow(port, checkpointer=_checkpointer(args.graph))
    before = port.reachability()
    result = resume_investigation(flow, args.thread, approve=True, approved_by=args.approved_by)
    receipt = result.get("receipt", {})
    print(f"[t2] resumed in a FRESH process — thread {args.thread}")
    print(f"[t2] triage was remembered from case memory: finding={result.get('triage', {}).get('finding')}")
    print(f"[t2] subject was remembered from case memory: subject={result.get('subject')}")
    remembered = result.get("proposal", [])
    if remembered:
        top = remembered[0]
        print(f"[t2] remembered proposal top: {top.get('src')} -[{top.get('rel')}]-> {top.get('dst')}")
    print(f"[t2] cut executed: {receipt.get('cut')}")
    print(f"[t2] reachability {receipt.get('before', {}).get('reachability')} -> "
          f"{receipt.get('after', {}).get('reachability')} | requery {receipt.get('requery_ms')}ms | "
          f"verdict={receipt.get('verdict')}")
    out = {
        "beat": "cross-process case memory (FalkorDBSaver)",
        "thread": args.thread,
        "graph": args.graph,
        "approved_by": args.approved_by,
        "resume_reachability_before": before,
        "receipt": receipt,
        "state_step": result.get("step"),
        "remembered": {
            "finding": result.get("triage", {}).get("finding"),
            "subject": result.get("subject"),
            "proposal": remembered,
        },
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"[t2] receipts written to {out_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SEVER cross-process case-memory beat")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_start = sub.add_parser("start")
    p_start.add_argument("--thread", required=True)
    p_start.add_argument("--graph", default="sever_t2")
    p_start.add_argument("--finding-id", default="F-T2",
                         help="distinct finding id so interleaved threads stay distinguishable")
    p_start.add_argument("--subject", default=HERO,
                         help="principal the finding is about (default: the T1 hero breach)")
    p_start.add_argument("--hold-seconds", type=int, default=0,
                         help="stay alive at the gate this long (durability kill beat)")
    p_start.add_argument("--pidfile", default=None,
                         help="write os.getpid() here once paused (used with --hold-seconds)")
    p_start.set_defaults(fn=do_start)
    p_resume = sub.add_parser("resume")
    p_resume.add_argument("--thread", required=True)
    p_resume.add_argument("--graph", default="sever_t2")
    p_resume.add_argument("--approved-by", default="on-call-analyst")
    p_resume.add_argument("--out", default="out/receipts_T2_live.json",
                           help="receipt file for this resume (parallel cases keep their own)")
    p_resume.set_defaults(fn=do_resume)
    args = parser.parse_args()

    # Quickstart guard (F309, scripts slice — mirrors sever/eval/ablation.py):
    # the falkordb client constructor eagerly sends INFO, so a dead engine (or
    # a non-FalkorDB RESP server) raises here, before any thread work. One
    # actionable line + exit 2 (distinct from a measurement failure) beats the
    # raw redis traceback for a judge who skipped `docker compose up -d` (§9).
    try:
        _port(args.graph).node_count()
    except Exception as exc:
        print(
            f"engine unreachable ({type(exc).__name__}) — "
            "run `docker compose up -d` (README §9) first"
        )
        return 2
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
