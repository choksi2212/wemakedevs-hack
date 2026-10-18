"""Scale wall — hundreds of isolated tenant graphs in ONE FalkorDB instance.

    python scripts/scale_wall.py --tenants 300 --graph-prefix sever_tenant

Generates per-tenant estates (injective identity remaps of the base sample),
loads each as its own graph key (FalkorDB native multi-tenancy), then measures:
  - total load time, per-tenant GRAPH.MEMORY USAGE, instance total RAM
  - canonical shortest-path query latency sampled across tenants (flatness)
  - the interdiction re-query latency inside a sampled tenant
Receipts -> out/scale_wall.json (README material).

Precision note (audit9/M44): GRAPH.MEMORY USAGE reports integer MB —
sub-MB graphs read 0 on falkordb 6.0.0 (audit5's cross-engine parity note),
so the receipt records the RAW MB values and also carries the engine's
INFO used_memory bytes as the precise instance figure; docker stats RSS is
the third, host-side view.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()  # .env at the repo root, if present — real environment always wins

from sever.core.falkor_port import CANONICAL_PATH_QUERY_TEMPLATE, FalkorGraphPort
from sever.core.jewels import cypher_traversal_pattern
from sever.etl.ad_collectors import parse_ad_dir
from sever.synth.tenants import make_tenant

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
DA = "S-1-5-21-2697957641-2271029196-387917394-512"


def _docker_rss(container: str | None = None) -> str | None:
    """RSS of the engine container (audit9/M43): docker-compose.yml declares
    service ``falkordb`` with NO container_name, so the old hardcoded
    'sever-falkordb' matched nothing a ``docker compose up -d`` creates and
    the receipt's docker_rss was unreproducible via README §9. Resolve the
    container from compose first, then any falkordb-named container, then a
    --container override; subprocess.run, never the deprecated os.popen."""
    try:
        cid = container or None
        if not cid:
            out = subprocess.run(
                ["docker", "compose", "ps", "-q", "falkordb"],
                capture_output=True, text=True, timeout=60,
                cwd=str(Path(__file__).resolve().parents[1]))
            if out.returncode == 0 and out.stdout.strip():
                cid = out.stdout.strip().splitlines()[0].strip()
        if not cid:
            out = subprocess.run(
                ["docker", "ps", "--filter", "name=falkordb", "--format", "{{.ID}}"],
                capture_output=True, text=True, timeout=60)
            if out.returncode == 0 and out.stdout.strip():
                cid = out.stdout.strip().splitlines()[0].strip()
        if not cid:
            print("[scale] docker stats: no falkordb container resolved "
                  "(docker absent, or engine not compose-booted) — docker_rss omitted")
            return None
        out = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", cid],
            capture_output=True, text=True, timeout=120)
        return out.stdout.strip() or None
    except Exception as exc:
        print(f"[scale] docker stats unavailable ({type(exc).__name__}: {str(exc)[:60]})")
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenants", type=int, default=300)
    parser.add_argument("--graph-prefix", default="sever_tenant")
    parser.add_argument("--sample-dir", default=os.environ.get(
        "SEVER_SAMPLE_DIR",
        str(Path(__file__).resolve().parents[1] / "data" / "ad_sample")))
    parser.add_argument("--skip-load", action="store_true", help="graphs already loaded — measurement only")
    parser.add_argument("--container", default=None,
                        help="engine container id/name for docker stats (default: resolved from compose)")
    args = parser.parse_args()

    print(f"[scale] base sample: {args.sample_dir}")
    base = parse_ad_dir(args.sample_dir)
    print(f"[scale] base graph: {base.stats['node_count']} nodes / {base.stats['edge_count']} edges")

    # Quickstart guard (F309, scripts slice — mirrors sever/eval/ablation.py):
    # falkordb's client constructor eagerly sends INFO, so a dead engine (or a
    # non-FalkorDB RESP server) raises before the scale wall starts. One
    # actionable line + exit 2 (distinct from a measurement failure) beats the
    # raw redis traceback for a judge who skipped `docker compose up -d` (§9).
    try:
        falkor = FalkorGraphPort(
            host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
            port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
            username=os.environ.get("SEVER_FALKOR_USER"),
            password=os.environ.get("SEVER_FALKOR_PASSWORD"),
        )
        falkor.node_count()  # probe: 0 on an empty/missing graph, raises on a dead/non-FalkorDB engine
    except Exception as exc:
        print(
            f"engine unreachable ({type(exc).__name__}) — "
            "run `docker compose up -d` (README §9) first"
        )
        return 2
    raw = falkor.graph.client

    # per-tenant hero/jewel remap for the latency sample (same transform as
    # make_tenant). sever/synth/tenants.py is owned by the agent-loop shard,
    # so the public wrapper lives HERE (audit9/N14) instead of reaching for
    # the underscore name at every call site.
    from sever.synth.tenants import _remap_sid as _tenant_remap_sid

    def remap_sid(oid: str, tenant_index: int) -> str:
        """Public in-script alias for the tenant identity remap (see make_tenant)."""
        return _tenant_remap_sid(oid, tenant_index)

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
                username=os.environ.get("SEVER_FALKOR_USER"),
                password=os.environ.get("SEVER_FALKOR_PASSWORD"),
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
                   port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
                   username=os.environ.get("SEVER_FALKOR_USER"),
                   password=os.environ.get("SEVER_FALKOR_PASSWORD"))
    latencies: list[float] = []
    step = max(1, args.tenants // 30)
    for i in range(1, args.tenants + 1, step):
        gg = fdb.select_graph(f"{args.graph_prefix}{i:03d}")
        t0 = time.time()
        gg.query(q, {"oid": remap_sid(HERO, i), "target": remap_sid(DA, i)})
        latencies.append((time.time() - t0) * 1000)

    # precise instance memory from the engine itself (INFO used_memory) —
    # GRAPH.MEMORY's integer-MB sums under-report (audit9/M44)
    try:
        instance_used_memory_bytes = raw.info("memory")["used_memory"]
    except Exception:
        instance_used_memory_bytes = None

    receipts = {
        "beat": "multi-tenant scale wall",
        "tenants": args.tenants,
        "nodes_per_tenant": base.stats["node_count"],
        "edges_per_tenant": base.stats["edge_count"],
        "total_nodes": args.tenants * base.stats["node_count"],
        "total_edges": args.tenants * base.stats["edge_count"],
        "total_load_seconds": round(total_load, 2),
        "mean_load_per_tenant_s": round(statistics.mean(load_times), 3),
        "instance_ram_mb": round(mem_bytes / (1024 * 1024), 1),  # GRAPH.MEMORY integer-MB sum — precision-limited (audit9/M44)
        "instance_used_memory_bytes": instance_used_memory_bytes,  # engine INFO — the precise figure
        "per_graph_mb_mean": round(sum(per_graph_mb) / len(per_graph_mb), 2) if per_graph_mb else None,
        "docker_rss": _docker_rss(args.container),
        # raw GRAPH.MEMORY MB values, NOT divided again (audit9/M44: the old
        # code divided MB figures by 1MiB a second time and every sample
        # recorded as 0.0 — a field that could never show a real number)
        "sample_graph_memories_mb": list(sample_mems),
        "query_latency_ms": {
            "samples": len(latencies),
            "mean": round(statistics.mean(latencies), 2) if latencies else None,
            "median": round(statistics.median(latencies), 2) if latencies else None,
            # nearest-rank p95 (audit9/M45): the old int(n*0.95)-1 index
            # under-reported (30 samples -> index 27 = the 90th percentile;
            # the shipped receipt's 4.81ms p95 came from that off-by-one)
            "p95": round(sorted(latencies)[math.ceil(0.95 * len(latencies)) - 1], 2) if latencies else None,
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
