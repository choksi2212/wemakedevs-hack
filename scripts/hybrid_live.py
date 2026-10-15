"""Hybrid estate beat — the on-prem <-> Entra cross-world story, LIVE.

    python scripts/hybrid_live.py --graph sever_hybrid

Loads the merged AD+Entra estate (bidirectional SYNCED_TO bridges), then:
  1. compromise the CLOUD identity of synced user ANDY (AZUser)
  2. reachability: the cloud identity pivots across the bridge into
     on-prem chains -> Domain Admins (MGM / Storm-0558 shape)
  3. interdiction: cutting the cross-world SYNCED_TO bridge collapses it
Receipts -> out/receipts_hybrid_live.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sever.agent.investigator import Investigator
from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import parse_ad_dir
from sever.etl.entra_collectors import merge_entra, parse_entra_file
from sever.findings.stream import Finding

AZ_ANDY = "3892f15b-2264-4927-8366-74b0f7f49761"   # Andy (Entra identity)
AD_ANDY = "S-1-5-21-2697957641-2271029196-387917394-2187"  # ANDY@PHANTOM.CORP


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graph", default="sever_hybrid")
    repo = Path(__file__).resolve().parents[1]
    parser.add_argument("--ad-dir", default=os.environ.get(
        "SEVER_SAMPLE_DIR", str(repo / "data" / "ad_sample")))
    parser.add_argument("--entra-file", default=os.environ.get(
        "SEVER_ENTRA_FILE",
        str(repo / "data" / "entra_sample" / "azurehound_example.json")))
    args = parser.parse_args()

    print("[hybrid] parsing AD + Entra collectors ...")
    ad = parse_ad_dir(args.ad_dir)
    az = parse_entra_file(args.entra_file)
    merged = merge_entra(ad, az)
    print(f"[hybrid] merged estate: {merged.stats['node_count']} nodes / {merged.stats['edge_count']} edges "
          f"| bridges: {merged.stats['entra_bridges']} (bidirectional)")

    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=args.graph,
    )
    t0 = time.time()
    port.load(merged)
    print(f"[hybrid] loaded into '{args.graph}' in {time.time()-t0:.1f}s | jewels: {len(port.crown_jewels())}")

    inv = Investigator(port)
    report = inv.triage(Finding("F-H1", "credential_breach", AZ_ANDY))
    reach = report.after["reachability"]
    print(f"[hybrid] compromised the CLOUD identity of synced user Andy -> reachability 0->{reach}")
    print("[hybrid] the identity pivots the SYNCED_TO bridge into on-prem Domain Admin chains")

    # interdiction: sever the cross-world bridge (cloud -> on-prem direction)
    receipt = inv.approve_and_cut(AZ_ANDY, AD_ANDY, "SYNCED_TO", approved_by="console-operator")
    print(f"[hybrid] cut the cross-world bridge: removed={receipt['cut']['relationships_removed']} "
          f"| reachability {receipt['before']['reachability']} -> {receipt['after']['reachability']} "
          f"| requery {receipt['requery_ms']}ms | verdict={receipt['verdict']}")

    out = {
        "beat": "hybrid cross-world interdiction",
        "graph": args.graph,
        "merged_nodes": merged.stats["node_count"],
        "merged_edges": merged.stats["edge_count"],
        "bridges": merged.stats["entra_bridges"],
        "cloud_identity_compromised": AZ_ANDY,
        "reachability_after_breach": reach,
        "bridge_cut_receipt": receipt,
    }
    out_path = Path("out") / "receipts_hybrid_live.json"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"[hybrid] receipts written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
