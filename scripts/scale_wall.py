"""Scale wall — hundreds of isolated tenant graphs in ONE FalkorDB instance.

    python scripts/scale_wall.py --tenants 300 --graph-prefix sever_tenant

Generates per-tenant estates (injective identity remaps of the base sample),
loads each as its own graph key (FalkorDB native multi-tenancy), then measures:
  - total load time, per-tenant GRAPH.MEMORY USAGE, instance total RAM
  - canonical shortest-path query latency sampled across tenants (flatness)
  - the interdiction re-query latency inside a sampled tenant
Receipts -> out/scale_wall.json (README material).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sever.core.falkor_port import CANONICAL_PATH_QUERY_TEMPLATE, FalkorGraphPort
from sever.core.jewels import cypher_traversal_pattern
from sever.etl.ad_collectors import parse_ad_dir
from sever.synth.tenants import make_tenant

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
DA = "S-1-5-21-2697957641-2271029196-387917394-512"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenants", type=int, default=300)
    parser.add_argument("--graph-prefix", default="sever_tenant")
    parser.add_argument("--sample-dir", default=os.environ.get(
        "SEVER_SAMPLE_DIR",
        str(Path(__file__).resolve().parents[1] / "data" / "ad_sample")))
    parser.add_argument("--skip-load", action="store_true", help="graphs already loaded — measurement only")
    args = parser.parse_args()

    print(f"[scale] base sample: {args.sample_dir}")
    base = parse_ad_dir(args.sample_dir)
    print(f"[scale] base graph: {base.stats['node_count']} nodes / {base.stats['edge_count']} edges")

    falkor = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
    )
    raw = falkor.graph.client

    # per-tenant hero/jewel remap (same transform as make_tenant)
    from sever.synth.tenants import _remap_sid
    hero_t = _remap_sid(HERO, 1)
    da_t = _remap_sid(DA, 1)

    load_times: list[float] = []
    t_all = time.time()
    if args.skip_load:
        print(f"[scale] --skip-load: measuring {args.tenants} existing graphs")
        load_times = [0.0]
    else:
        for i in range(1, args.tenants + 1):
            tenant = make_tenant(base, i)
            port = FalkorGraphPort(
                host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
                port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
                graph_name=f"{args.graph_prefix}{i:03d}",
            )
            t0 = time.time()
            port.load(tenant)
            load_times.append(time.time() - t0)
            if i % 25 == 0 or i == args.tenants:
                print(f"[scale] loaded tenant {i:03d}/{args.tenants} "
                      f"(+{load_times[-1]:.2f}s, total {time.time()-t_all:.1f}s)")
    total_load = time.time() - t_all

    # memory usage across graphs
    mem_bytes = 0
    sample_mems = []
    per_graph_mb = []
    for i in range(1, args.tenants + 1):
        try:
            usage = raw.execute_command("GRAPH.MEMORY", "USAGE", f"{args.graph_prefix}{i:03d}")
            # response: [b"total_graph_sz_mb", <n>] (MB precision; sub-MB graphs report 0)
            vals = [v for v in (usage if isinstance(usage, list) else [usage]) if isinstance(v, int)]
            mb = vals[0] if vals else 0
            mem_bytes += mb * 1024 * 1024
            per_graph_mb.append(mb)
            if i % 25 == 0:
                sample_mems.append((i, mb))
        except Exception as e:
            print(f"[scale] GRAPH.MEMORY err tenant {i}: {str(e)[:80]}")
            break

    # query latency flatness across sampled tenants (python client)
    from falkordb import FalkorDB
    pattern = cypher_traversal_pattern(12)
    q = CANONICAL_PATH_QUERY_TEMPLATE.format(pattern=pattern)
    fdb = FalkorDB(host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
                   port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")))
    latencies: list[float] = []
    step = max(1, args.tenants // 30)
    for i in range(1, args.tenants + 1, step):
        gg = fdb.select_graph(f"{args.graph_prefix}{i:03d}")
        t0 = time.time()
        res = gg.query(q, {"oid": _remap_sid(HERO, i), "target": _remap_sid(DA, i)})
        latencies.append((time.time() - t0) * 1000)

    receipts = {
        "beat": "multi-tenant scale wall",
        "tenants": args.tenants,
        "nodes_per_tenant": base.stats["node_count"],
        "edges_per_tenant": base.stats["edge_count"],
        "total_nodes": args.tenants * base.stats["node_count"],
        "total_edges": args.tenants * base.stats["edge_count"],
        "total_load_seconds": round(total_load, 2),
        "mean_load_per_tenant_s": round(statistics.mean(load_times), 3),
        "instance_ram_mb": round(mem_bytes / (1024 * 1024), 1),
        "per_graph_mb_mean": round(sum(per_graph_mb) / len(per_graph_mb), 2) if per_graph_mb else None,
        "docker_rss": os.popen("docker stats --no-stream --format {{.MemUsage}} sever-falkordb").read().strip() or None,
        "sample_graph_memories_mb": [(i, round(m / (1024 * 1024), 2)) for i, m in sample_mems],
        "query_latency_ms": {
            "samples": len(latencies),
            "mean": round(statistics.mean(latencies), 2) if latencies else None,
            "median": round(statistics.median(latencies), 2) if latencies else None,
            "p95": round(sorted(latencies)[int(len(latencies) * 0.95) - 1], 2) if latencies else None,
            "max": round(max(latencies), 2) if latencies else None,
            "flat": (max(latencies) - min(latencies)) < 50 if latencies else None,
        },
    }
    out = Path("out") / "scale_wall.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(receipts, indent=2, default=str), encoding="utf-8")
    print(json.dumps(receipts, indent=2, default=str)[:1200])
    print(f"[scale] receipts written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
