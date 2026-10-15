"""Cross-process case memory on LIVE FalkorDB — the T2 hero beat.

Run as TWO separate processes (the "kill -9 / night-shift handoff" story):

    # process 1 — on-call analyst starts the investigation, goes home at the gate
    python scripts/case_memory_live.py start --thread case-T2-live --graph sever_t2

    # process 2 — a FRESH process resumes from shared case memory and executes
    python scripts/case_memory_live.py resume --thread case-T2-live --graph sever_t2 --approved-by night-shift

Case memory lives IN FalkorDB via FalkorDBSaver (langchain-falkordb): the
interrupted thread state — triage results, ranked proposal, everything — is
graph nodes, so any process (or agent) that connects picks the case up.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
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
        database=f"{graph}_checkpoints",
    )


def _port(graph: str) -> FalkorGraphPort:
    return FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=graph,
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
    pending = start_investigation(flow, Finding("F-T2", "credential_breach", HERO), args.thread)
    print("[t2] investigation paused at the HUMAN GATE (process 1 exiting)")
    print("[t2] thread:", args.thread)
    print("[t2] pending proposal (from shared case memory):")
    for cand in pending.get("proposal", [])[:3]:
        print(f"        {cand['src']} -[{cand['rel']}]-> {cand['dst']} (on {cand['paths_on']} paths)")
    print("[t2] reachability at pause:", pending.get("triage", {}).get("after", {}).get("reachability"))
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
    }
    out_path = Path("out") / "receipts_T2_live.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"[t2] receipts written to {out_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SEVER cross-process case-memory beat")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_start = sub.add_parser("start")
    p_start.add_argument("--thread", required=True)
    p_start.add_argument("--graph", default="sever_t2")
    p_start.set_defaults(fn=do_start)
    p_resume = sub.add_parser("resume")
    p_resume.add_argument("--thread", required=True)
    p_resume.add_argument("--graph", default="sever_t2")
    p_resume.add_argument("--approved-by", default="on-call-analyst")
    p_resume.set_defaults(fn=do_resume)
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
