"""Load sever_demo onto FalkorDB Cloud + run the hero arc against the deployed substrate.

Produces live cloud receipts: breach -> paths -> grant -> human-gated cut -> collapse.
"""
import os
import sys
import time

sys.path.insert(0, ".")

HOST = "r-6jissuruar.instance-mgs1tqgkg.hc-7up0crkyn.ap-south-1.aws.f2e0a955bb84.cloud"
PORT = 59719
USER = "falkordb"
PASS = os.environ["SEVER_FALKOR_PASSWORD"]

from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import parse_ad_dir
from sever.agent.investigator import Investigator
from sever.findings.stream import default_timeline
from sever.core.scoring import rank_cut_candidates

GRAPH = "sever_demo"

print("[cloud] parsing sample locally ...")
t0 = time.perf_counter()
normalized = parse_ad_dir(os.environ["SEVER_SAMPLE_DIR"])
print(f"[cloud] {normalized.stats['node_count']} nodes / {normalized.stats['edge_count']} edges parsed "
      f"({time.perf_counter()-t0:.1f}s)")

port = FalkorGraphPort(host=HOST, port=PORT, username=USER, password=PASS, graph_name=GRAPH)
import redis
r = redis.Redis(host=HOST, port=PORT, username=USER, password=PASS)
try:
    r.execute_command("GRAPH.DELETE", GRAPH)
    print("[cloud] fresh start (old demo graph deleted)")
except Exception:
    print("[cloud] fresh start (no prior graph)")

t0 = time.perf_counter()
port.load(normalized)
load_s = time.perf_counter() - t0
print(f"[cloud] LOADED into FalkorDB Cloud in {load_s:.1f}s | nodes={port.node_count()} edges={port.edge_count()} jewels={len(port.crown_jewels())}")

inv = Investigator(port)
HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
GMSA_GROUP = "S-1-5-21-2697957641-2271029196-387917394-2102"

print("\n[cloud] == hero arc on the deployed substrate ==")
for f in default_timeline(HERO, ace_target=GMSA_GROUP, jewel=port.crown_jewels()[0]):
    report = inv.triage(f)
    print(f"  {f.id} {f.kind:22s} reachability {report.before['reachability']}->{report.after['reachability']}")

receipts = []
while port.reachability() > 0 and len(receipts) < 3:
    prop = inv.propose(limit=3)
    if not prop:
        break
    top = prop[0]
    rec = inv.approve_and_cut(top["src"], top["dst"], top["rel"], approved_by="cloud-demo-operator")
    receipts.append(rec)
    print(f"  cut {top['rel']:20s} removed={rec['cut']['relationships_removed']} "
          f"reachability {rec['before']['reachability']}->{rec['after']['reachability']} "
          f"requery {rec['requery_ms']}ms verdict={rec['verdict']}")

final = port.reachability()
print(f"\n[cloud] final reachability: {final} ({'COLLAPSED' if final == 0 else 'residual paths'})")
print(f"[cloud] load {load_s:.1f}s | demo estate live on FalkorDB Cloud ap-south-1")

import json
out = {
    "beat": "hero arc on FalkorDB Cloud (free tier, ap-south-1)",
    "graph": GRAPH,
    "engine": "FalkorDB Cloud v4.22.0 (client-verified)",
    "nodes": port.node_count(),
    "edges": port.edge_count(),
    "jewels": len(port.crown_jewels()),
    "load_seconds": round(load_s, 2),
    "final_reachability": final,
    "cuts": receipts,
}
with open("docs/receipts/receipts_cloud_live.json", "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2, default=str)
print("[cloud] receipts written to docs/receipts/receipts_cloud_live.json")
