"""Smoke-test SEVER's queries against the FalkorDB Cloud instance."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # anchored on the repo root, not CWD

from dotenv import load_dotenv

load_dotenv()  # README §8: every entry point loads a root .env — real environment always wins

HOST = os.environ["SEVER_FALKOR_HOST"]  # cloud instance endpoint: env-only, never hardcoded (audit3/pentest-internal)
PORT = int(os.environ.get("SEVER_FALKOR_PORT", "6379"))
USER = os.environ.get("SEVER_FALKOR_USER", "falkordb")  # audit9/L35: env, with the documented default

from falkordb import FalkorDB

fdb = FalkorDB(host=HOST, port=PORT, username=USER, password=os.environ["SEVER_FALKOR_PASSWORD"])
g = fdb.select_graph("sever_cloud_smoke")

# audit9/L35: every failing probe is recorded and the script exits 1 — a
# smoke test that always exits 0 proves nothing
failures: list[str] = []

print("=== 1. raw PING/connection ===")
print("client OK, graph key:", g.name)

print("=== 2. engine version ===")
try:
    info = fdb.client.execute_command("INFO", "server")
    for line in info.decode().splitlines() if isinstance(info, bytes) else str(info).splitlines():
        if "redis_version" in line or "falkordb" in line.lower():
            print(" ", line)
except Exception as e:
    print("  INFO err:", str(e)[:120])
    failures.append(f"INFO server: {str(e)[:120]}")

# audit9/M41: sections 3-7 are wrapped in try/finally with the GRAPH.DELETE
# in finally — the in-repo audit5 receipt shows a smoke run dying before
# cleanup and leaving sever_cloud_smoke on the production cloud instance
try:
    print("=== 3. basic Cypher ===")
    g.query("CREATE (:N {objectid: 'a'})-[:MEMBER_OF]->(:N {objectid: 'b'})")
    print(g.query("MATCH (n:N) RETURN count(n) AS n").result_set)

    print("=== 4. shortestPath WITH-form (load-bearing quirk) ===")
    try:
        res = g.query(
            "MATCH (o {objectid: 'a'}), (t {objectid: 'b'}) "
            "WITH shortestPath((o)-[:MEMBER_OF*..12]->(t)) AS p RETURN p"
        ).result_set
        print("  shortestPath OK, rows:", len(res))
    except Exception as e:
        print("  shortestPath FAIL:", str(e)[:160])
        failures.append(f"shortestPath WITH-form: {str(e)[:120]}")

    print("=== 5. algo.SPpaths ===")
    try:
        res = g.query(
            "MATCH (o {objectid: 'a'}), (t {objectid: 'b'}) "
            "CALL algo.SPpaths({sourceNode: o, targetNode: t, pathCount: 100}) YIELD path RETURN path"
        ).result_set
        print("  SPpaths OK, rows:", len(res))
    except Exception as e:
        print("  SPpaths FAIL:", str(e)[:160])
        failures.append(f"algo.SPpaths: {str(e)[:120]}")

    print("=== 6. range index ===")
    try:
        g.query("CREATE INDEX FOR (n:N) ON (n.objectid)")
        idx = fdb.client.execute_command("GRAPH.QUERY", "sever_cloud_smoke", "CALL db.indexes() YIELD label, properties, status RETURN label, properties, status")
        # audit9/L35: the returned rows are ASSERTED, not just fetched and
        # discarded — the smoke must prove the N-label index is really there
        rows = idx[1] if isinstance(idx, list) and len(idx) > 1 and isinstance(idx[1], list) else []
        label_n_present = any("N" in str(row) for row in rows)
        print("  index rows:", rows, "| N-label present:", label_n_present)
        if not label_n_present:
            failures.append("db.indexes(): no N-label index row returned")
    except Exception as e:
        print("  index FAIL:", str(e)[:160])
        failures.append(f"range index: {str(e)[:120]}")

    print("=== 7. GRAPH.PROFILE (params-header transport) ===")
    try:
        from sever.core.falkor_port import FalkorGraphPort
        p = FalkorGraphPort(host=HOST, port=PORT, username=USER,
                             password=os.environ["SEVER_FALKOR_PASSWORD"], graph_name="sever_cloud_smoke")
        out = p.profile("MATCH (o {objectid: $oid}) RETURN o.objectid AS oid", {"oid": "a"})
        print("  PROFILE OK:", out.split("\\n")[0][:120] if "\\n" in out else out[:120])
    except Exception as e:
        print("  PROFILE FAIL:", str(e)[:200])
        failures.append(f"GRAPH.PROFILE: {str(e)[:120]}")
finally:
    print("=== 8. cleanup ===")
    fdb.client.execute_command("GRAPH.DELETE", "sever_cloud_smoke")
    print("  deleted smoke graph")

print("DONE")
if failures:
    print(f"\nSMOKE FAILURES ({len(failures)}):")
    for f in failures:
        print(" -", f)
    sys.exit(1)
