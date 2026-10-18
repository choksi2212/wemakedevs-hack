"""Load sever_demo onto FalkorDB Cloud + run the hero arc against the deployed substrate.

Produces live cloud receipts: breach -> paths -> grant -> human-gated cut -> collapse.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # audit9/L34: anchored on the repo root, not CWD

from dotenv import load_dotenv

load_dotenv()  # README §8: every entry point loads a root .env — real environment always wins

HOST = os.environ["SEVER_FALKOR_HOST"]  # cloud instance endpoint: env-only, never hardcoded (audit3/pentest-internal)
PORT = int(os.environ.get("SEVER_FALKOR_PORT", "6379"))
USER = os.environ.get("SEVER_FALKOR_USER", "falkordb")  # audit9/L34: env, with the documented default
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


def _engine_label(client) -> str:
    """MEASURED, not asserted (audit9/M40): probe MODULE LIST at runtime and
    write the deployed module version into the receipt. The old hardcoded
    'FalkorDB Cloud v4.22.0 (client-verified)' presented an unmeasured
    constant as a verification — if the cloud engine were upgraded, the
    receipt would still have asserted 4.22.0."""
    try:
        mods = client.execute_command("MODULE", "LIST")
    except Exception as exc:
        return f"FalkorDB Cloud (version unverified: {type(exc).__name__})"
    for m in mods if isinstance(mods, list) else []:
        if isinstance(m, dict):
            d = {(k.decode() if isinstance(k, bytes) else k): v for k, v in m.items()}
        elif isinstance(m, (list, tuple)) and m:
            d = {(m[i].decode() if isinstance(m[i], bytes) else m[i]):
                 (m[i + 1].decode() if isinstance(m[i + 1], bytes) else m[i + 1])
                 for i in range(0, len(m) - 1, 2)}
        else:
            continue
        name = d.get("name")
        if name != "graph":
            continue
        ver = d.get("ver")
        if isinstance(ver, int):
            major, rest = divmod(ver, 10000)
            minor, patch = divmod(rest, 100)
            return (f"FalkorDB Cloud v{major}.{minor}.{patch} "
                    f"(client-verified, MODULE LIST ver {ver})")
        return f"FalkorDB Cloud v{ver} (client-verified, MODULE LIST)"
    return "FalkorDB Cloud (module 'graph' not found in MODULE LIST)"


engine_label = _engine_label(r)
print(f"[cloud] engine: {engine_label}")
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

out = {
    "beat": "hero arc on FalkorDB Cloud (free tier, ap-south-1)",
    "graph": GRAPH,
    "engine": engine_label,
    "nodes": port.node_count(),
    "edges": port.edge_count(),
    "jewels": len(port.crown_jewels()),
    "load_seconds": round(load_s, 2),
    "final_reachability": final,
    "cuts": receipts,
}
out_path = Path(__file__).resolve().parents[1] / "docs" / "receipts" / "receipts_cloud_live.json"
out_path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
print(f"[cloud] receipts written to {out_path}")
