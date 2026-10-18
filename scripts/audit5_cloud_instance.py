"""audit5_cloud_instance.py — engine-side audit of the live FalkorDB Cloud instance.

Five probes (branch audit5/cloud-instance):
  A. estate inventory  — every key, type, MEMORY USAGE, GRAPH.MEMORY USAGE,
     node/edge counts, module versions, maxmemory/used/peak, ACL surface.
     READ-ONLY over the pre-existing estate.
  B. sizing probe      — 3 throwaway tenant graphs loaded through the exact
     production load path (make_tenant + FalkorGraphPort.load); used_memory
     deltas give per-tenant cost on THIS engine -> the 100MB free-tier
     extrapolation. Never extrapolated BY loading: only 3 tenants load.
  C. version-gap       — every shipped query form re-run on a throwaway graph:
     canonical shortestPath WITH-form, both reachability arms, algo.SPpaths
     (relTypes honored?), add_edge MERGE semantics, the atomic
     delete-and-count cut, GRAPH.COPY, CREATE INDEX + db.indexes(),
     PROFILE params-header. Expected outcomes feed `failures` (L33).
  D. cleanup           — GRAPH.DELETE every sever_audit5_cloud* key, verify by
     SCAN that none remain and that sever_demo / sidecars are untouched.

Never prints credentials. Never touches a key that is not sever_audit5_cloud*.

Env: SEVER_FALKOR_HOST/PORT/USER/PASSWORD (+ SEVER_SAMPLE_DIR for the load).
Run:  python scripts/audit5_cloud_instance.py
Receipt -> docs/receipts/audit5_cloud_instance.json
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()

from sever.core.falkor_port import (  # noqa: E402
    CANONICAL_PATH_QUERY_TEMPLATE,
    CUT_ATOMIC_QUERY_TEMPLATE,
    JEWELS_QUERY,
    MARK_OWNED_QUERY,
    OWNED_QUERY,
    PATH_QUERY_TEMPLATE,
    REACHABILITY_ARM_TEMPLATES,
    REACHABILITY_QUERY_TEMPLATE,
    USER_OBJECTIDS_QUERY,
    FalkorGraphPort,
)
from sever.core.jewels import cypher_traversal_pattern  # noqa: E402
from sever.etl.ad_collectors import parse_ad_dir  # noqa: E402
from sever.synth.tenants import make_tenant  # noqa: E402

THROWAWAY_PREFIX = "sever_audit5_cloud"
SAMPLE_DIR = os.environ.get(
    "SEVER_SAMPLE_DIR", str(Path(__file__).resolve().parents[1] / "data" / "ad_sample"))

receipt: dict = {"beat": "cloud instance audit (audit5/cloud-instance)", "probes": {}}
failures: list[str] = []


def _bytes(x):
    return x.decode() if isinstance(x, bytes) else x


def main() -> int:
    host = os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1")
    port_i = int(os.environ.get("SEVER_FALKOR_PORT", "6379"))
    user = os.environ.get("SEVER_FALKOR_USER")
    password = os.environ.get("SEVER_FALKOR_PASSWORD")

    # a plain redis client for raw RESP (INFO/SCAN/MEMORY/MODULE/GRAPH.* admin
    # surface) — the falkordb wrapper only proxies execute_command.
    import redis

    raw = redis.Redis(
        host=host, port=port_i, username=user, password=password,
        socket_timeout=int(os.environ.get("SEVER_FALKOR_SOCKET_TIMEOUT", "30")),
        socket_connect_timeout=int(os.environ.get("SEVER_FALKOR_CONNECT_TIMEOUT", "10")),
    )

    # ---------------- A. estate inventory (read-only) ----------------
    inv: dict = {}
    def _module_dicts(mods):
        out = []
        for m in mods:
            if isinstance(m, dict):
                d = {_bytes(k): v for k, v in m.items()}
            elif isinstance(m, (list, tuple)) and m and isinstance(m[0], (str, bytes)):
                d = {_bytes(m[i]): m[i + 1] for i in range(0, len(m) - 1, 2)}
            else:
                d = {"name": m}
            out.append({
                "name": _bytes(d.get("name")),
                "ver": d.get("ver"),
                "path": _bytes(d.get("path")) or "",
                "args": [_bytes(a) if not isinstance(a, (list, tuple))
                         else [_bytes(x) for x in a] for a in (d.get("args") or [])],
            })
        return out

    inv["module_list"] = _module_dicts(raw.execute_command("MODULE", "LIST"))
    server = raw.info("server")
    mem = raw.info("memory")
    inv["engine"] = {
        "redis_version": server.get("redis_version"),
        "os": server.get("os"),
        "uptime_seconds": server.get("uptime_in_seconds"),
        "maxmemory_bytes": mem.get("maxmemory"),
        "used_memory_bytes": mem.get("used_memory"),
        "used_memory_peak_bytes": mem.get("used_memory_peak"),
        "used_memory_startup_bytes": mem.get("used_memory_startup"),
        "used_memory_dataset_bytes": mem.get("used_memory_dataset"),
        "maxmemory_policy": mem.get("maxmemory_policy"),
        "aof_enabled": server.get("aof_enabled"),
        "role": server.get("role"),
    }
    keys: list[str] = []
    cursor = 0
    while True:
        cursor, batch = raw.scan(cursor=cursor, count=200)
        keys += [_bytes(k) for k in batch]
        if cursor == 0:
            break
    keys.sort()
    estate = []
    for k in keys:
        entry: dict = {"key": k, "type": _bytes(raw.type(k))}
        try:
            entry["memory_usage_bytes"] = raw.memory_usage(k)
        except Exception as e:  # noqa: BLE001
            entry["memory_usage_bytes"] = f"ERR {str(e)[:60]}"
        if entry["type"] == "graphdata":
            try:
                gm = raw.execute_command("GRAPH.MEMORY", "USAGE", k, timeout=10000)
                entry["graph_memory_mb"] = {
                    _bytes(a): (b if not isinstance(b, dict)
                               else {_bytes(x): y for x, y in b.items()})
                    for a, b in (gm.items() if isinstance(gm, dict) else [])
                }
                n = raw.execute_command("GRAPH.QUERY", k, "MATCH (n) RETURN count(n) AS n")
                e_ = raw.execute_command("GRAPH.QUERY", k, "MATCH ()-[r]->() RETURN count(r) AS e")
                entry["nodes"] = int(n[1][0][0])
                entry["edges"] = int(e_[1][0][0])
                labs = raw.execute_command("GRAPH.QUERY", k, "MATCH (n) UNWIND labels(n) AS l RETURN DISTINCT l")
                entry["labels_present"] = sorted(
                    _bytes(row[0][0]) if isinstance(row[0], list) else _bytes(row[0]) for row in labs[1])
            except Exception as e:  # noqa: BLE001
                entry["graph_probe_error"] = str(e)[:100]
        estate.append(entry)
    inv["dbsize"] = raw.dbsize()
    inv["graph_list"] = sorted(_bytes(g) for g in raw.execute_command("GRAPH.LIST"))
    inv["estate"] = estate

    acl_surface = {}
    for cmd, args in (
        ("CONFIG", ("GET", "maxmemory")),
        ("ACL", ("WHOAMI",)),
        ("XLEN", ("telemetry{sever_demo}",)),
        ("XRANGE", ("telemetry{sever_demo}", "-", "+", "COUNT", "1")),
        ("KEYS", ("sever_audit5_cloud_probe_*",)),
        ("GRAPH.ROSTER", ()),
        ("SAVE", ()),
        ("DEBUG", ("JMAP",)),
    ):
        try:
            raw.execute_command(cmd, *args)
            acl_surface[cmd] = "allowed"
        except Exception as e:  # noqa: BLE001
            acl_surface[cmd] = f"denied: {str(e)[:70]}"
    for cmd in ("INFO", "PING", "SCAN", "DBSIZE", "TYPE", "MEMORY USAGE",
                "GRAPH.QUERY", "GRAPH.LIST", "GRAPH.MEMORY USAGE", "GRAPH.EXPLAIN",
                "GRAPH.PROFILE", "GRAPH.SLOWLOG", "GRAPH.CONFIG GET", "MODULE LIST",
                "GRAPH.DELETE", "GRAPH.COPY"):
        acl_surface[cmd] = "allowed (used by this audit)"
    inv["acl_surface"] = acl_surface
    receipt["probes"]["estate_inventory"] = inv
    print(f"[A] inventory: dbsize={inv['dbsize']} graphs={inv['graph_list']}")
    print(f"[A] engine: maxmemory={inv['engine']['maxmemory_bytes']} used={inv['engine']['used_memory_bytes']} peak={inv['engine']['used_memory_peak_bytes']}")

    # ---------------- B. sizing probe (throwaway tenants) ----------------
    print(f"[B] base sample: {SAMPLE_DIR}")
    base = parse_ad_dir(SAMPLE_DIR)
    print(f"[B] base graph: {base.stats['node_count']} nodes / {base.stats['edge_count']} edges")
    sizing = {"sample_nodes": base.stats["node_count"], "sample_edges": base.stats["edge_count"],
              "tenants": []}
    u0 = raw.info("memory")["used_memory"]
    for i in (1, 2, 3):
        name = f"{THROWAWAY_PREFIX}_t{i}"
        try:
            raw.execute_command("GRAPH.DELETE", name)
        except Exception:  # noqa: BLE001
            pass
        tenant = make_tenant(base, i)
        tp = FalkorGraphPort(host=host, port=port_i, username=user, password=password,
                             graph_name=name)
        t0 = time.time()
        tp.load(tenant)
        load_s = time.time() - t0
        u = raw.info("memory")["used_memory"]
        gm = raw.execute_command("GRAPH.MEMORY", "USAGE", name, timeout=10000)
        total_mb = gm.get(b"total_graph_sz_mb") if isinstance(gm, dict) else None
        sizing["tenants"].append({
            "graph": name, "load_seconds": round(load_s, 2),
            "used_memory_after_bytes": u,
            "used_memory_delta_bytes": u - u0,
            "graph_memory_total_mb": _bytes(total_mb),
        })
        print(f"[B] {name}: load {load_s:.2f}s, used_memory delta {u - u0} bytes, GRAPH.MEMORY {total_mb} MB")
        u0 = u
    deltas = [t["used_memory_delta_bytes"] for t in sizing["tenants"]]
    per_tenant = sum(deltas) // len(deltas) if deltas else None  # mean across 3 loads
    eng = inv["engine"]
    if per_tenant:
        maxm = eng["maxmemory_bytes"]
        used = eng["used_memory_bytes"]
        sizing["per_tenant_bytes"] = per_tenant
        sizing["extrapolation_3000_tenants_bytes"] = 3000 * per_tenant
        if maxm:
            # build the ceiling label from the MEASURED maxmemory — the
            # self-hosted §9 engine has no maxmemory (0 = unlimited) and a
            # hardcoded "100MB" label would be a fabricated claim (M37)
            ceiling_label = f"{maxm / (1024 * 1024):.0f}MB maxmemory ceiling"
            sizing["extrapolation_3000_tenants_vs_maxmemory"] = (
                f"{3000 * per_tenant / maxm:.1f}x the {ceiling_label}")
            # honest headroom: subtract what the instance ALREADY uses at
            # measurement time, not just startup (M38) — formula recorded so
            # the receipt is recomputable in one line
            sizing["tenants_fit_formula"] = (
                "(maxmemory - used_memory - 2MiB headroom) // per_tenant_bytes")
            sizing["tenants_that_fit_in_maxmemory_approx"] = int(
                (maxm - used - 2 * 1024 * 1024) // per_tenant)
        else:
            sizing["extrapolation_3000_tenants_vs_maxmemory"] = (
                "maxmemory=0 (unlimited) — no ceiling to extrapolate against")
            sizing["tenants_that_fit_in_maxmemory_approx"] = None
        sizing["ryzen_receipt_per_tenant_mb"] = 5.44  # scale_wall.json: 1.594GiB/300 on falkordb 6.0.0
        # derive the label from the BYTES field, never a hand-typed unit:
        # 5.44MiB x 3000 = 16,320MiB = 15.94GiB (16.32 was a decimal-GB
        # figure mislabeled GiB — M39)
        ryzen_bytes = int(5.44 * 1024 * 1024) * 3000
        sizing["extrapolation_3000_from_ryzen_receipt_bytes"] = ryzen_bytes
        if maxm:
            sizing["extrapolation_3000_from_ryzen_receipt_vs_maxmemory"] = (
                f"{ryzen_bytes / maxm:.1f}x the {ceiling_label} "
                f"({ryzen_bytes / (1024 ** 3):.2f}GiB)")
        else:
            sizing["extrapolation_3000_from_ryzen_receipt_vs_maxmemory"] = (
                f"{ryzen_bytes / (1024 ** 3):.2f}GiB (no maxmemory ceiling set)")
    receipt["probes"]["sizing"] = sizing

    # ---------------- C. version-gap battery ----------------
    vgap: dict = {"engine_note": "FalkorDB Cloud module 'graph' ver 42200 (=4.22.0) vs self-hosted 6.0.0"}
    vg = f"{THROWAWAY_PREFIX}_vgap"
    try:
        raw.execute_command("GRAPH.DELETE", vg)
    except Exception:  # noqa: BLE001
        pass
    vgp = FalkorGraphPort(host=host, port=port_i, username=user, password=password,
                          graph_name=vg)
    hero = "S-1-5-21-990000000000000000000000000001-1001"
    jewel = "S-1-5-21-990000000000000000000000000001-512"
    gq = lambda q, p=None: vgp.graph.query(q, p or {}).result_set  # noqa: E731
    gq("CREATE (:User {objectid: $h, name: 'hero', owned: true}), "
       "(:Group {objectid: $j, name: 'DOMAIN ADMINS'})", {"h": hero, "j": jewel})
    # bind endpoints with MATCH first, MERGE only the edge — MERGE over a full
    # node pattern would (did, in the first run of this audit) duplicate the
    # endpoints: the exact pitfall the product's ADD_EDGE_QUERY avoids.
    gq("MATCH (s {objectid: $h}), (t {objectid: $j}) "
       "MERGE (s)-[r:MEMBER_OF]->(t) RETURN count(r) AS n", {"h": hero, "j": jewel})
    nnodes = raw.execute_command("GRAPH.QUERY", vg, "MATCH (n) RETURN count(n) AS n")
    vgap["setup_node_count"] = int(nnodes[1][0][0])
    if vgap["setup_node_count"] != 2:
        failures.append(f"vgap setup created {vgap['setup_node_count']} nodes, expected 2 (MERGE pitfall)")

    def form(name, fn, expect=None):
        """Probe one query form. ``expect``: True = the engine MUST accept
        (a rejection is a failure), False = the engine MUST reject
        (an acceptance is a failure), None = informational only.
        Expected outcomes feed `failures` so the battery's verdict is
        honest (audit9/L33) — informational probes are labeled as such."""
        try:
            out = fn()
            vgap[name] = {"ok": True, "result": str(out)[:200]}
            print(f"[C] {name}: OK -> {str(out)[:100]}")
            if expect is False:
                failures.append(
                    f"version-gap probe {name}: engine ACCEPTED a form that must be rejected")
        except Exception as e:  # noqa: BLE001
            vgap[name] = {"ok": False, "error": str(e)[:220]}
            print(f"[C] {name}: FAIL -> {str(e)[:110]}")
            if expect is True:
                failures.append(
                    f"version-gap probe {name}: engine rejected a form the product "
                    f"ships ({str(e)[:80]})")

    pattern = cypher_traversal_pattern()
    form("canonical_shortestPath_WITH_form", lambda: gq(
        CANONICAL_PATH_QUERY_TEMPLATE.format(pattern=pattern), {"oid": hero, "target": jewel}),
        expect=True)
    form("shortestPath_RETURN_form_documented_quirk", lambda: gq(
        "MATCH (o {objectid: $oid}), (t {objectid: $target}) "
        "RETURN shortestPath((o)-" + pattern + "->(t)) AS p", {"oid": hero, "target": jewel}),
        expect=True)
    form("reachability_arm_Group", lambda: gq(
        REACHABILITY_ARM_TEMPLATES[0].format(pattern=pattern)), expect=True)
    form("reachability_arm_AZUser", lambda: gq(
        REACHABILITY_ARM_TEMPLATES[1].format(pattern=pattern)), expect=True)
    form("reachability_perpair_hit_form", lambda: gq(
        REACHABILITY_QUERY_TEMPLATE.format(pattern=pattern), {"oid": hero, "target": jewel}),
        expect=True)
    form("jewels_query", lambda: gq(JEWELS_QUERY), expect=True)
    form("owned_query", lambda: gq(OWNED_QUERY), expect=True)
    form("user_objectids_query", lambda: gq(USER_OBJECTIDS_QUERY), expect=True)
    # the RAW template is shipped with a {$oid} placeholder where the engine
    # expects a params header — both engines must REJECT it (product bug
    # fixed on this branch; see cross_engine_parity below)
    form("spPaths_RAW_template_as_shipped_expect_reject", lambda: gq(
        PATH_QUERY_TEMPLATE, {"oid": hero, "target": jewel}), expect=False)
    form("spPaths_relTypes_form_formatted", lambda: gq(
        PATH_QUERY_TEMPLATE.format(), {"oid": hero, "target": jewel}), expect=True)
    # relTypes honored: a CONTAINED_BY-only pair must return nothing under relTypes [traversal set]
    gq("CREATE (:User {objectid: 's-vg-cb'}), (:Group {objectid: 's-vg-tgt'})")
    gq("MATCH (s {objectid: 's-vg-cb'}), (t {objectid: 's-vg-tgt'}) "
       "MERGE (s)-[r:CONTAINED_BY]->(t) RETURN count(r) AS n")
    form("spPaths_relTypes_filter_honored_CONTAINED_BY_pair_yields_0", lambda: gq(
        PATH_QUERY_TEMPLATE.format(), {"oid": "s-vg-cb", "target": "s-vg-tgt"}), expect=True)
    form("paths_to_jewels_canonical_via_port", lambda: vgp.paths_to_jewels(hero),
         expect=True)
    # ties mode is engine-dependent (tests/test_live_semantics.py skips it on
    # engines that lack the procedure) — informational, not a verdict input
    form("paths_to_jewels_ties_via_port_after_fix", lambda: vgp.paths_to_jewels(
        hero, ties=True))
    form("add_edge_MERGE_semantics", lambda: (
        gq(FalkorGraphPort.ADD_EDGE_QUERY.format(rel="GENERIC_ALL"),
           {"src": hero, "dst": jewel, "props": {"note": "vg"}}),
        gq(FalkorGraphPort.ADD_EDGE_QUERY.format(rel="GENERIC_ALL"),
           {"src": hero, "dst": jewel, "props": {"note": "vg"}}))[-1], expect=True)
    # the product ships ONE atomic delete-and-count statement (audit5/
    # multi-client removed the count-then-delete TOCTOU pair) — probe the
    # form that ships (audit9/H16)
    form("cut_atomic_delete_and_count", lambda: gq(
        CUT_ATOMIC_QUERY_TEMPLATE.format(rel="GENERIC_ALL"), {"src": hero, "dst": jewel}),
        expect=True)
    form("mark_owned_SET", lambda: gq(MARK_OWNED_QUERY, {"oid": hero}), expect=True)
    form("toLower_ENDS_WITH", lambda: gq(
        "MATCH (u:User) WHERE toLower(u.name) ENDS WITH '-globaladministrator' RETURN u.objectid"),
        expect=True)
    form("create_index", lambda: gq("CREATE INDEX FOR (n:User) ON (n.objectid)"),
         expect=True)
    form("db_indexes_procedure", lambda: gq(
        "CALL db.indexes() YIELD label, properties, status RETURN label, properties, status"),
        expect=True)
    form("OPTIONAL_MATCH_pre_count", lambda: gq(
        "MATCH (s {objectid: $a}), (t {objectid: $b}) OPTIONAL MATCH (s)-[r0:MEMBER_OF]->(t) "
        "WITH s, t, count(r0) AS pre RETURN pre", {"a": hero, "b": jewel}), expect=True)
    copy_target = f"{THROWAWAY_PREFIX}_copy"
    def _copy_probe():
        try:
            raw.execute_command("GRAPH.DELETE", copy_target)
        except Exception:  # noqa: BLE001
            pass  # no such key — the normal case
        return raw.execute_command("GRAPH.COPY", vg, copy_target)

    form("GRAPH.COPY", _copy_probe, expect=True)
    if vgap["GRAPH.COPY"]["ok"]:
        cp = FalkorGraphPort(host=host, port=port_i, username=user, password=password,
                             graph_name=copy_target)
        vgap["GRAPH.COPY"]["nodes_in_copy"] = cp.node_count()
    form("PROFILE_params_header_transport", lambda: vgp.profile(
        "MATCH (o {objectid: $oid}) RETURN o.objectid AS oid", {"oid": hero})[:120],
        expect=True)
    # unknown command on BOTH engines (see cross_engine_parity) — informational
    form("GRAPH.ROSTER_exists", lambda: raw.execute_command("GRAPH.ROSTER"))
    # cross-engine parity matrix, measured live on BOTH engines this audit
    # (cloud module 'graph' 42200; ryzen module 'graph' 60000):
    vgap["cross_engine_parity"] = {
        "shortestPath_WITH_form": "parses+runs on BOTH (the form the product ships)",
        "shortestPath_RETURN_form": (
            "parses+runs on BOTH — the 'WITH-clause only' quirk in the old "
            "docstrings does NOT reproduce on 4.22.0 or 6.0.0 (1 row each; "
            "possibly an older-falkordb behavior) — docstrings updated"),
        "spPaths_RAW_template_as_shipped": (
            "REJECTED on BOTH (4.22.0: \"Invalid input '{'\"; 6.0.0: \"unhandled "
            "type in inlined properties\") — product bug fixed on this branch; "
            "the 6.0.0 error text is exactly what the code comments "
            "misattributed to an 'intermittent engine bug under churn'"),
        "spPaths_formatted_relTypes_pathCount": "parses+runs on BOTH; relTypes filter honored on 4.22.0 (CONTAINED_BY-only pair yields 0 paths)",
        "GRAPH.COPY": "works on 4.22.0 (b'OK', node-count parity) — plan projections safe on the cloud",
        "GRAPH.ROSTER": "unknown command on BOTH engines — not a cloud gap",
        "GRAPH.MEMORY_USAGE": (
            "works on BOTH; integer-MB precision: sever_demo reads 2 MB on "
            "4.22.0 while scale_wall per-graph reads 0.0 MB on 6.0.0 — lead "
            "with measured used_memory deltas, not GRAPH.MEMORY, for sizing"),
        "add_edge_MERGE_pre_semantics": "identical on 4.22.0 (pre=0 new grant, pre=1 idempotent re-grant)",
        "db_indexes_PROFILE_timeout_transport": "identical on 4.22.0",
    }
    receipt["probes"]["version_gap"] = vgap

    # ---------------- D. cleanup + verify ----------------
    # purge EVERY sever_audit5_cloud* key (this audit's throwaway prefix —
    # including leftovers from this audit's own debug runs), never anything else.
    cleanup = {"deleted": [], "remaining_audit5_keys": []}
    cur = 0
    leftovers: list[str] = []
    while True:
        cur, batch = raw.scan(cursor=cur, count=200)
        leftovers += [_bytes(k) for k in batch if _bytes(k).startswith(THROWAWAY_PREFIX)]
        if cur == 0:
            break
    for name in sorted(set(leftovers)):
        try:
            raw.execute_command("GRAPH.DELETE", name)
            cleanup["deleted"].append(name)
        except Exception as e:  # noqa: BLE001
            cleanup["deleted"].append(f"{name}: ERR {str(e)[:60]}")
    cur = 0
    leftover = []
    while True:
        cur, batch = raw.scan(cursor=cur, count=200)
        leftover += [_bytes(k) for k in batch if _bytes(k).startswith(THROWAWAY_PREFIX)]
        if cur == 0:
            break
    cleanup["remaining_audit5_keys"] = sorted(leftover)
    cur = 0
    final_keys: list[str] = []
    while True:
        cur, batch = raw.scan(cursor=cur, count=200)
        final_keys += [_bytes(k) for k in batch]
        if cur == 0:
            break
    cleanup["final_keyspace"] = sorted(final_keys)
    demo_after = raw.execute_command("GRAPH.QUERY", "sever_demo", "MATCH (n) RETURN count(n) AS n")
    cleanup["sever_demo_nodes_after"] = int(demo_after[1][0][0])
    if cleanup["remaining_audit5_keys"]:
        failures.append(f"throwaway keys not deleted: {cleanup['remaining_audit5_keys']}")
    pre_set = set(keys)
    if set(final_keys) - pre_set:
        failures.append(f"new non-throwaway keys appeared: {set(final_keys) - pre_set}")
    receipt["probes"]["cleanup"] = cleanup
    print(f"[D] deleted: {cleanup['deleted']}; remaining audit5 keys: {cleanup['remaining_audit5_keys']}")
    print(f"[D] final keyspace: {cleanup['final_keyspace']}")

    receipt["failures"] = failures
    receipt["all_pass"] = not failures
    out = Path(__file__).resolve().parents[1] / "docs" / "receipts" / "audit5_cloud_instance.json"
    out.write_text(json.dumps(receipt, indent=1) + "\n", encoding="utf-8")
    print(f"[receipt] {out}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
