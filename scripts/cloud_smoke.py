"""Smoke-test SEVER's queries against the FalkorDB Cloud instance."""
import os
import sys
import time

sys.path.insert(0, ".")

HOST = "r-6jissuruar.instance-mgs1tqgkg.hc-7up0crkyn.ap-south-1.aws.f2e0a955bb84.cloud"
PORT = 59719
USER = "falkordb"

from falkordb import FalkorDB

fdb = FalkorDB(host=HOST, port=PORT, username=USER, password=os.environ["SEVER_FALKOR_PASSWORD"])
g = fdb.select_graph("sever_cloud_smoke")

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

print("=== 5. algo.SPpaths ===")
try:
    res = g.query(
        "MATCH (o {objectid: 'a'}), (t {objectid: 'b'}) "
        "CALL algo.SPpaths({sourceNode: o, targetNode: t, pathCount: 100}) YIELD path RETURN path"
    ).result_set
    print("  SPpaths OK, rows:", len(res))
except Exception as e:
    print("  SPpaths FAIL:", str(e)[:160])

print("=== 6. range index ===")
try:
    g.query("CREATE INDEX FOR (n:N) ON (n.objectid)")
    idx = fdb.client.execute_command("GRAPH.QUERY", "sever_cloud_smoke", "CALL db.indexes() YIELD label, properties, status RETURN label, properties, status")
    print("  index call OK")
except Exception as e:
    print("  index FAIL:", str(e)[:160])

print("=== 7. GRAPH.PROFILE (params-header transport) ===")
try:
    from sever.core.falkor_port import FalkorGraphPort
    p = FalkorGraphPort(host=HOST, port=PORT, username=USER,
                         password=os.environ["SEVER_FALKOR_PASSWORD"], graph_name="sever_cloud_smoke")
    out = p.profile("MATCH (o {objectid: $oid}) RETURN o.objectid AS oid", {"oid": "a"})
    print("  PROFILE OK:", out.split("\\n")[0][:120] if "\\n" in out else out[:120])
except Exception as e:
    print("  PROFILE FAIL:", str(e)[:200])

print("=== 8. cleanup ===")
fdb.client.execute_command("GRAPH.DELETE", "sever_cloud_smoke")
print("  deleted smoke graph")
print("DONE")
