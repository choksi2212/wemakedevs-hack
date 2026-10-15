"""SEVER rehearsal — runs the entire demo beat end-to-end on the live engine.

    python scripts/rehearse.py            # FalkorDB at SEVER_FALKOR_HOST (default 127.0.0.1:6379)

Requires the engine (docker compose up -d). The receipts this script prints
are the same JSON the demo video and README show: before/after reachability,
the cut proposal, the human-gated execution, and re-query timing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()  # .env at the repo root, if present — real environment always wins

from sever.agent.investigator import Investigator
from sever.agent.llm import build_llm
from sever.etl.ad_collectors import parse_ad_dir
from sever.findings.stream import FindingStream, default_timeline

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"  # T1_TONYMONTANA@PHANTOM.CORP
SAMPLE_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR",
    str(Path(__file__).resolve().parents[1] / "data" / "ad_sample"),
)


def _name(port, oid: str) -> str:
    res = port.graph.query(
        "MATCH (n {objectid: $o}) RETURN n.name AS name LIMIT 1", {"o": oid})
    if res.result_set and res.result_set[0][0]:
        return str(res.result_set[0][0])
    return oid


def main() -> int:
    parser = argparse.ArgumentParser(description="SEVER demo rehearsal (live engine)")
    parser.add_argument("--graph", default="sever_demo", help="FalkorDB graph key (tenant)")
    parser.add_argument("--sample-dir", default=SAMPLE_DIR)
    args = parser.parse_args()

    print(f"[sever] parsing collectors from {args.sample_dir} ...")
    t0 = time.perf_counter()
    normalized = parse_ad_dir(args.sample_dir)
    print(f"[sever] {normalized.stats['node_count']} nodes, {normalized.stats['edge_count']} edges "
          f"({time.perf_counter()-t0:.2f}s)")

    from sever.core.falkor_port import FalkorGraphPort

    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=args.graph,
        username=os.environ.get("SEVER_FALKOR_USER"),
        password=os.environ.get("SEVER_FALKOR_PASSWORD"),
    )
    if port.node_count() == 0:
        t0 = time.perf_counter()
        port.load(normalized)
        print(f"[sever] loaded into FalkorDB graph '{args.graph}' ({time.perf_counter()-t0:.2f}s)")
    backend = f"falkordb:{args.graph}"

    inv = Investigator(port, llm=build_llm())
    jewels = port.crown_jewels()
    print(f"[sever] backend={backend} | crown jewels: {len(jewels)}")
    for j in jewels:
        print(f"        - {_name(port, j)}")

    # build the timeline with REAL objectids from the loaded graph
    GMSA_GROUP = "S-1-5-21-2697957641-2271029196-387917394-2102"  # GMSA_SHS_PWD@PHANTOM.CORP
    timeline = default_timeline(HERO, ace_target=GMSA_GROUP, jewel=jewels[0])
    stream = FindingStream(timeline)

    print("\n[sever] == findings stream ==")
    for finding in stream:
        report = inv.triage(finding)
        line = (f"[{finding.id}] {finding.kind:22s} {report.narration_technique} | "
                f"reachability {report.before['reachability']}->{report.after['reachability']}")
        print(line)

    print("\n[sever] == interdiction rounds (greedy; each cut human-gated) ==")
    for round_no in range(1, 4):
        proposal = inv.propose(limit=3)
        if not proposal or port.reachability() == 0:
            break
        print(f"\n[sever] -- round {round_no}: proposals --")
        for cand in proposal:
            print(f"        {_name(port, cand['src'])} -[{cand['rel']}]-> {_name(port, cand['dst'])} "
                  f"(on {cand['paths_on']} of all owned->jewel paths)")
        top = proposal[0]
        print(f"[sever] human gate: APPROVED (on-call-analyst) -> cutting "
              f"{_name(port, top['src'])} -[{top['rel']}]-> {_name(port, top['dst'])}")
        receipt = inv.approve_and_cut(top["src"], top["dst"], top["rel"], approved_by="on-call-analyst")
        print(f"[sever] removed={receipt['cut']['relationships_removed']} | "
              f"reachability {receipt['before']['reachability']} -> {receipt['after']['reachability']} | "
              f"requery {receipt['requery_ms']}ms | verdict={receipt['verdict']}")

    final = port.reachability()
    print(f"\n[sever] final reachability: {final} "
          f"({'COLLAPSED — no owned principal can reach a crown jewel' if final == 0 else 'residual paths remain; investigate'})")

    out = {
        "backend": backend,
        "graph": args.graph,
        "hero": HERO,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "case_log": inv.case_log,
    }
    out_path = Path("out") / f"receipts_{backend.replace(':', '_')}.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"\n[sever] receipts written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
