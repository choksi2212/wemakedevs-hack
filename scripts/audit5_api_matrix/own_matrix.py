#!/usr/bin/env python
"""audit5/api-matrix OWN-INSTANCE destructive conformance (ryzen local).

Runs against http://127.0.0.1:8305 (+ :8306 for the cross-process ledger
phase) — consoles booted from the audit5/api-matrix worktree, graph key
sever_audit5_apimatrix (disposable, owner-authorized).

Phases:
  0 readiness  1 baseline  2 rejection matrix (422/403/400/413 spot sweep)
  3 real-estate mutations (finding applies edge, approved cut removes it)
  4 full remediation plan + approved execution (completed, no drift)
  5 drift-stop with tampered projections on REAL steps
  6 cross-process concurrent ledger storm (two consoles, one ledger)
  7 engine-stall -> 503 everywhere + honest cut_failed ledger record
  8 final ledger integrity (append-only, parseable, ordered)
"""
from __future__ import annotations

import concurrent.futures
import ctypes
import json
import subprocess
import sys
import time

import requests

A = "http://127.0.0.1:8305"
B = "http://127.0.0.1:8306"
HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"
GMSA = "S-1-5-21-2697957641-2271029196-387917394-2102"
GHOST = "S-1-5-21-2697957641-2271029196-387917394-9999"
OUT = r"C:\Users\niklaus\audit5_own_results.jsonl"
results: list[dict] = []


def call(method, url, timeout=45, **kw):
    return requests.request(method, url, timeout=timeout, **kw)


def record(rec):
    results.append(rec)
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, default=str) + "\n")
    return rec


def check(cid, expected, desc, method, url, expect_pred=None, timeout=45, **kw):
    exp = expected if isinstance(expected, list) else [expected]
    rec = {"id": cid, "desc": desc, "expected": exp}
    t0 = time.time()
    try:
        r = call(method, url, timeout=timeout, **kw)
        rec["actual"] = r.status_code
        rec["pass"] = r.status_code in exp
        rec["elapsed_s"] = round(time.time() - t0, 2)
        if expect_pred:
            rec["semantics"] = expect_pred(r)
            rec["pass"] = rec["pass"] and all(v is not False for v in rec["semantics"].values())
            if not rec["pass"]:
                rec["body"] = r.text[:250]
        elif not rec["pass"]:
            rec["body"] = r.text[:250]
    except Exception as e:
        rec["actual"] = "ERR"
        rec["pass"] = False
        rec["body"] = f"{type(e).__name__}: {e}"[:250]
    print(f"{cid:36} {rec.get('actual')} exp {exp} {'ok ' if rec['pass'] else 'FAIL'} {desc}", flush=True)
    return record(rec)


def jpost(cid, url, obj, expected, desc, expect_pred=None, timeout=45):
    return check(cid, expected, desc, "POST", url, json=obj, expect_pred=expect_pred, timeout=timeout)


def raw(cid, url, body, expected, desc, ct="application/json", timeout=45):
    return check(cid, expected, desc, "POST", url, data=body, headers={"Content-Type": ct}, timeout=timeout)


def get(cid, url, expected, desc, expect_pred=None, timeout=45):
    return check(cid, expected, desc, "GET", url, expect_pred=expect_pred, timeout=timeout)


def receipts(base=A):
    r = call("GET", base + "/api/receipts", timeout=60)
    return r.json() if r.status_code == 200 else None


def ledger_integrity(base_list):
    ok = True
    notes = {}
    for base in base_list:
        b = receipts(base)
        parseable = isinstance(b, list) and all(isinstance(e, dict) for e in b)
        ts = [e.get("ts") or "" for e in b]
        ordered = all(ts[i] <= ts[i + 1] for i in range(len(ts) - 1))
        notes[base] = {"parseable": parseable, "ordered": ordered, "count": len(b)}
        ok = ok and parseable and ordered
    return ok, notes


# ---------------------------------------------------------------- phase 0
print("=== PHASE 0: readiness ===", flush=True)
for name, base in (("A", A), ("B", B)):
    ready = False
    for _ in range(60):
        try:
            r = requests.get(base + "/api/state", timeout=5)
            if r.status_code == 200 and r.json().get("nodes") == 1480:
                ready = True
                break
        except Exception:
            pass
        time.sleep(2)
    print(f"console {name} ({base}) ready={ready}", flush=True)
    if not ready:
        print("FATAL: console not ready", flush=True)
        sys.exit(2)

# ---------------------------------------------------------------- phase 1
print("=== PHASE 1: baseline ===", flush=True)
base_state = call("GET", A + "/api/state").json()
base_receipts = receipts(A)
base_count = len(base_receipts)
print("baseline state:", {k: base_state[k] for k in ("nodes", "edges", "reachability", "owned")}, "| receipts:", base_count, flush=True)
with open(OUT + ".baseline", "w", encoding="utf-8") as f:
    json.dump({"state": base_state, "receipts": base_receipts}, f)
assert base_state["reachability"] == 0, "fresh graph must start collapsed"

# ---------------------------------------------------------------- phase 2
print("=== PHASE 2: rejection matrix ===", flush=True)
C, F, P = A + "/api/cut", A + "/api/finding", A + "/api/plan/execute"
cut_body = {"src": HERO, "dst": GHOST, "rel": "GENERIC_ALL", "approved": False}

raw("o_f_malformed", F, b'{"kind":"credential_breach","subj', 422, "malformed JSON -> 422")
raw("o_f_ct_textplain", F, json.dumps({"kind": "credential_breach", "subject": HERO}).encode(), 422, "text/plain content-type -> 422", ct="text/plain")
raw("o_f_body_array", F, b"[1,2]", 422, "JSON array body -> 422")
jpost("o_f_missing_subject", F, {}, 422, "missing subject -> 422")
jpost("o_f_empty_subject", F, {"kind": "credential_breach", "subject": ""}, 422, "empty subject -> 422")
jpost("o_f_100kb_subject", F, {"kind": "credential_breach", "subject": "A" * 100_000}, 422, "100KB subject -> 422")
raw("o_f_surrogate", F, json.dumps({"kind": "credential_breach", "subject": "\ud800"}).encode(), 422, "lone surrogate -> 422")
jpost("o_f_unknown_kind", F, {"kind": "bogus_kind", "subject": HERO}, 422, "unknown kind -> 422")
jpost("o_f_ace_nogrants", F, {"kind": "ace_granted", "subject": HERO}, 422, "ace_granted w/o grant -> 422")
jpost("o_f_self_grant", F, {"kind": "ace_granted", "subject": HERO, "target": HERO, "rel": "GENERIC_ALL"}, 422, "self-grant -> 422")
jpost("o_f_rel_newline", F, {"kind": "ace_granted", "subject": HERO, "target": GMSA, "rel": "MEMBER_OF\n"}, 422, "rel trailing newline -> 422")
jpost("o_f_inject_rel", F, {"kind": "ace_granted", "subject": HERO, "target": GMSA, "rel": "X)-[r:M]->(d RETURN 1"}, 422, "Cypher injection rel -> 422")
jpost("o_f_ghost_subject", F, {"kind": "credential_breach", "subject": GHOST}, 400, "ghost subject -> 400 estate")
jpost("o_f_ghost_target", F, {"kind": "ace_granted", "subject": HERO, "target": GHOST, "rel": "GENERIC_ALL"}, 400, "ghost target -> 400 estate")
jpost("o_f_ssrf_url", F, {"kind": "credential_breach", "subject": "http://169.254.169.254/latest/meta-data/"}, 400, "SSRF-shaped subject -> 400")
raw("o_f_dupkeys_lastwins", F, b'{"kind":"credential_breach","subject":"' + HERO.encode() + b'","subject":"S-GHOST"}', 400, "dup keys real->ghost last-wins -> 400 estate")

jpost("o_c_missing_approved", C, {"src": HERO, "dst": GHOST, "rel": "GENERIC_ALL"}, 422, "missing approved -> 422")
jpost("o_c_approved_1", C, {**cut_body, "approved": 1}, 422, "approved 1 -> 422")
jpost("o_c_approved_strtrue", C, {**cut_body, "approved": "true"}, 422, "approved 'true' -> 422")
jpost("o_c_approved_nested", C, {**cut_body, "approved": {"v": True}}, 422, "approved nested object -> 422")
jpost("o_c_gate_false", C, cut_body, 403, "gate false -> 403")
jpost("o_c_gate_first_vocab", C, {**cut_body, "rel": "generic_all"}, 403, "gate before vocabulary -> 403")
jpost("o_c_gate_first_ghost", C, {"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL", "approved": False}, 403, "gate before estate -> 403")
jpost("o_c_true_generic_all", C, {"src": HERO, "dst": GMSA, "rel": "generic_all", "approved": True}, 400, "approved unknown rel -> 400 vocabulary")
raw("o_c_surrogate_src", C, json.dumps({"src": "\ud800", "dst": GHOST, "rel": "GENERIC_ALL", "approved": False}).encode(), 422, "cut lone surrogate src -> 422")

steps1 = [{"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": 1}]
jpost("o_p_missing_approved", P, {"steps": steps1}, 422, "plan missing approved -> 422")
jpost("o_p_approved_1", P, {"steps": steps1, "approved": 1}, 422, "plan approved 1 -> 422")
jpost("o_p_gate_false", P, {"steps": steps1, "approved": False}, 403, "plan gate false -> 403")
jpost("o_p_gate_first_vocab", P, {"steps": [{"src": HERO, "dst": GHOST, "rel": "generic_all", "projected_reachability": 1}], "approved": False}, 403, "plan gate before vocabulary -> 403")
jpost("o_p_steps_empty", P, {"steps": [], "approved": True}, 422, "plan empty steps -> 422")
jpost("o_p_steps_11", P, {"steps": steps1 * 11, "approved": True}, 422, "plan 11 steps -> 422")
jpost("o_p_neg_projection", P, {"steps": [{"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": -1}], "approved": True}, 422, "negative projection -> 422")
jpost("o_p_true_generic_all", P, {"steps": [{"src": HERO, "dst": GHOST, "rel": "generic_all", "projected_reachability": 1}], "approved": True}, 400, "plan approved unknown rel -> 400 vocabulary")


def sized(n):
    obj = {"src": HERO, "dst": GHOST, "rel": "GENERIC_ALL", "approved": False, "pad": ""}
    obj["pad"] = "x" * (n - len(json.dumps(obj).encode()))
    b = json.dumps(obj).encode()
    assert len(b) == n, (len(b), n)
    return b


raw("o_c_body_999999", C, sized(999_999), 422, "999999B body under cap reaches schema")
raw("o_c_body_1000000", C, sized(1_000_000), 422, "1000000B body at cap reaches schema")
raw("o_c_body_1000001", C, sized(1_000_001), 413, "1000001B body over cap -> 413")
raw("o_c_body_2mb", C, b'{"pad":"' + b"x" * 2_100_000 + b'"}', 413, "2MB junk body -> 413")


def chunked_413(url, total=1_600_000, chunk=100_000):
    import socket as _s
    host, port = "127.0.0.1", int(url.rsplit(":", 1)[1])
    s = _s.create_connection((host, port), timeout=30)
    req = (f"POST /api/cut HTTP/1.1\r\nHost: {host}:{port}\r\n"
           "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
    s.sendall(req.encode())
    sent = 0
    body = b'{"pad":"' + b"z" * (total - 11) + b'"}'
    while sent < len(body):
        part = body[sent:sent + chunk]
        try:
            s.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
        except OSError:
            break  # server already reset the stream after aborting — expected
        sent += len(part)
        if sent > 1_100_000:
            break
    s.settimeout(10)
    try:
        data = s.recv(65536)
    except _s.timeout:
        data = b"<no response within 10s>"
    except OSError as e:
        data = f"<conn reset: {e}>".encode()
    s.close()
    code = data.split(b" ", 2)[1].decode() if b" " in data else "??"
    return code, data[:200]


code, sample = chunked_413(A)
rec = {"id": "o_c_chunked_413", "desc": "chunked 1.6MB -> 413 (streaming path)", "expected": ["413"], "actual": code, "pass": code == "413"}
if code != "413":
    rec["body"] = sample.decode("utf-8", "replace")
print(f"{'o_c_chunked_413':36} {code} exp ['413'] {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

# hostile storm must not poison the ledger
before_hostile = len(receipts(A))
for i in range(20):
    if i % 2:
        raw(f"o_hostile_{i}", F, json.dumps({"kind": "bogus", "subject": "\ud800"}).encode(), 422, "hostile surrogate storm")
    else:
        jpost(f"o_hostile_{i}", F, {"kind": "credential_breach", "subject": "A" * 100_000}, 422, "hostile oversized storm")
after_hostile = len(receipts(A))
rec = {"id": "o_hostile_no_ledger_writes", "desc": "hostile 422s wrote zero ledger entries", "expected": "equal", "actual": (before_hostile, after_hostile), "pass": before_hostile == after_hostile}
print(f"{'o_hostile_no_ledger_writes':36} {before_hostile}->{after_hostile} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

# ---------------------------------------------------------------- phase 3
print("=== PHASE 3: real mutations ===", flush=True)
edges0 = call("GET", A + "/api/state").json()["edges"]
jpost("o_f_breach_hero", F, {"kind": "credential_breach", "subject": HERO}, 200,
      "breach finding on hero -> 200 applied",
      expect_pred=lambda r: {"applied": r.json().get("applied"), "applied_is_true": r.json().get("applied") is True})
s1 = call("GET", A + "/api/state").json()
rec = {"id": "o_state_after_breach", "expected": "reachability>=1", "actual": s1["reachability"], "pass": s1["reachability"] >= 1}
print(f"{'o_state_after_breach':36} reach={s1['reachability']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

r = call("GET", A + "/api/paths")
REALDST = r.json()["paths"][0]["hops"][0]["dst"]
print("REALDST:", REALDST, flush=True)

jpost("o_f_ace_adds_edge", F, {"kind": "ace_granted", "subject": HERO, "target": GMSA, "rel": "GENERIC_ALL"}, 200,
      "ace_granted MERGEs a real abusable edge",
      expect_pred=lambda r: {"applied": r.json().get("applied")})
s2 = call("GET", A + "/api/state").json()
rec = {"id": "o_edge_added", "expected": "edges+1", "actual": (edges0, s2["edges"]), "pass": s2["edges"] == edges0 + 1}
print(f"{'o_edge_added':36} {edges0}->{s2['edges']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

jpost("o_cut_gate_recheck", C, {"src": HERO, "dst": GMSA, "rel": "GENERIC_ALL", "approved": False}, 403, "unapproved cut of real edge -> 403")
s3 = call("GET", A + "/api/state").json()
rec = {"id": "o_gate_no_mutation", "expected": "edges unchanged", "actual": s3["edges"], "pass": s3["edges"] == edges0 + 1}
print(f"{'o_gate_no_mutation':36} edges={s3['edges']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

jpost("o_cut_approved_real", C, {"src": HERO, "dst": GMSA, "rel": "GENERIC_ALL", "approved": True}, 200,
      "approved cut removes the edge (THE gated mutation path)",
      expect_pred=lambda r: {"removed": r.json()["cut"]["relationships_removed"],
                             "removed_ge_1": r.json()["cut"]["relationships_removed"] >= 1,
                             "approved_by_recorded": bool(r.json().get("approved_by"))})
s4 = call("GET", A + "/api/state").json()
rec = {"id": "o_edge_removed", "expected": "edges back to base", "actual": (edges0, s4["edges"]), "pass": s4["edges"] == edges0}
print(f"{'o_edge_removed':36} {edges0}->{s4['edges']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

# ---------------------------------------------------------------- phase 4
print("=== PHASE 4: full plan + approved execution ===", flush=True)
reach_before_plan = call("GET", A + "/api/state").json()["reachability"]
get("o_plan_propose", A + "/api/plan", 200, "GET /api/plan proposes measured sequence",
    expect_pred=lambda r: (lambda b: {
        "method_ok": b.get("method") == "graph_copy_remeasure",
        "steps_nonempty": len(b.get("steps", [])) > 0,
        "numbered": [s.get("step") for s in b.get("steps", [])] == list(range(1, len(b.get("steps", [])) + 1)),
        "honesty": bool(b.get("honesty")),
    })(r.json()))
plan = call("GET", A + "/api/plan").json()
plan_steps = [{"src": s["cut"]["src"], "rel": s["cut"]["rel"], "dst": s["cut"]["dst"],
               "projected_reachability": s["projected_reachability"]} for s in plan["steps"]]
state_mid = call("GET", A + "/api/state").json()
rec = {"id": "o_plan_projection_no_touch", "expected": "estate untouched by plan", "actual": (reach_before_plan, state_mid["reachability"], state_mid["edges"]),
       "pass": state_mid["reachability"] == reach_before_plan and state_mid["edges"] == edges0}
print(f"{'o_plan_projection_no_touch':36} reach={state_mid['reachability']} edges={state_mid['edges']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

jpost("o_plan_exec_gate403", P, {"approved": False, "steps": plan_steps}, 403, "plan execute unapproved -> 403, nothing runs")
s_gate = call("GET", A + "/api/state").json()
rec = {"id": "o_plan_gate_no_mutation", "expected": "reachability unchanged", "actual": s_gate["reachability"], "pass": s_gate["reachability"] == reach_before_plan}
print(f"{'o_plan_gate_no_mutation':36} reach={s_gate['reachability']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

# single approved execution — capture its receipts once
r_exec = call("POST", P, json={"approved": True, "steps": plan_steps})
exec_result = r_exec.json() if r_exec.status_code == 200 else {}
sem4 = {
    "http_200": r_exec.status_code == 200,
    "status_completed": exec_result.get("status") == "completed",
    "executed_all": exec_result.get("executed_steps") == len(plan_steps),
    "no_drift": bool(exec_result.get("steps")) and all(s.get("plan_drift") is False for s in exec_result["steps"]),
    "per_step_remeasure": bool(exec_result.get("steps")) and all("after" in s and "before" in s for s in exec_result["steps"]),
    "approved_by_on_every_step": bool(exec_result.get("steps")) and all(s.get("approved_by") for s in exec_result["steps"]),
    "plan_step_numbered": bool(exec_result.get("steps")) and [s.get("plan_step") for s in exec_result["steps"]] == list(range(1, len(plan_steps) + 1)),
}
rec = {"id": "o_plan_exec_approved", "desc": "approved plan executes every step, re-measured, no drift", "expected": 200,
       "actual": r_exec.status_code, "semantics": sem4, "pass": all(sem4.values())}
if not rec["pass"]:
    rec["body"] = r_exec.text[:250]
print(f"{'o_plan_exec_approved':36} {r_exec.status_code} {sem4} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)
executed_cuts = [s["cut"] for s in exec_result.get("steps", [])]

s5 = call("GET", A + "/api/state").json()
rec = {"id": "o_plan_final_state", "expected": "reachability == last projection", "actual": (s5["reachability"], plan["steps"][-1]["projected_reachability"]),
       "pass": s5["reachability"] == plan["steps"][-1]["projected_reachability"]}
print(f"{'o_plan_final_state':36} reach={s5['reachability']} proj={plan['steps'][-1]['projected_reachability']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

# ---------------------------------------------------------------- phase 5
print("=== PHASE 5: drift-stop on real steps ===", flush=True)
for i, cut in enumerate(executed_cuts):
    jpost(f"o_relight_ace_{i}", F, {"kind": "ace_granted", "subject": cut["src"], "target": cut["dst"], "rel": cut["rel"]}, 200,
          "re-light estate: re-add removed edge (authorized mutation)")
s6 = call("GET", A + "/api/state").json()
rec = {"id": "o_relight_state", "expected": "reachability back >=1", "actual": s6["reachability"], "pass": s6["reachability"] >= 1}
print(f"{'o_relight_state':36} reach={s6['reachability']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

plan2 = call("GET", A + "/api/plan").json()
plan2_steps = [{"src": s["cut"]["src"], "rel": s["cut"]["rel"], "dst": s["cut"]["dst"],
                "projected_reachability": s["projected_reachability"]} for s in plan2["steps"]]
if plan2_steps:
    tampered = [dict(plan2_steps[0], projected_reachability=plan2_steps[0]["projected_reachability"] + 5)] + plan2_steps[1:]
    jpost("o_plan_drift_stop", P, {"approved": True, "steps": tampered}, 200,
          "tampered projection -> drift detected at step 1, stale steps never run",
          expect_pred=lambda r: (lambda b: {
              "status": b.get("status"),
              "status_drift_stopped": b.get("status") == "drift_stopped_at_step",
              "executed_is_1": b.get("executed_steps") == 1,
              "drift_flag_true": bool(b.get("steps")) and b["steps"][0].get("plan_drift") is True,
              "stale_steps_not_run": len(b.get("steps", [])) == 1,
          })(r.json()))
    s7 = call("GET", A + "/api/state").json()
    print("state after drift-stop:", s7["reachability"], flush=True)
else:
    rec = {"id": "o_plan_drift_stop", "desc": "re-lit estate returned an empty plan", "expected": "non-empty steps", "actual": "empty steps", "pass": False}
    print(f"{'o_plan_drift_stop':36} FAIL re-lit estate has empty plan", flush=True)
    record(rec)

plan3 = call("GET", A + "/api/plan").json()
if plan3["steps"]:
    plan3_steps = [{"src": s["cut"]["src"], "rel": s["cut"]["rel"], "dst": s["cut"]["dst"],
                    "projected_reachability": s["projected_reachability"]} for s in plan3["steps"]]
    jpost("o_plan_honest_complete", P, {"approved": True, "steps": plan3_steps}, 200,
          "honest re-plan completes after drift-stop (re-plan beat)",
          expect_pred=lambda r: {"status": r.json().get("status"),
                                "no_drift": all(s.get("plan_drift") is False for s in r.json().get("steps", []))})
else:
    rec = {"id": "o_plan_honest_complete", "desc": "re-plan: nothing left to plan", "expected": "empty steps", "actual": "empty steps", "pass": True}
    print(f"{'o_plan_honest_complete':36} nothing left to plan ok", flush=True)
    record(rec)
s8 = call("GET", A + "/api/state").json()
rec = {"id": "o_estate_collapsed_final", "expected": "reachability 0 (fully interdicted)", "actual": s8["reachability"], "pass": s8["reachability"] == 0}
print(f"{'o_estate_collapsed_final':36} reach={s8['reachability']} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

# ---------------------------------------------------------------- phase 6
print("=== PHASE 6: cross-process concurrent ledger storm ===", flush=True)
pre_storm = len(receipts(A))
errors: list = []


def storm_worker(base, n_state, n_finding, n_hostile):
    s = requests.Session()
    for i in range(max(n_state, n_finding, n_hostile)):
        if i < n_state:
            r = s.get(base + "/api/state", timeout=30)
            if r.status_code != 200:
                errors.append(("state", base, r.status_code))
        if i < n_finding:
            r = s.post(base + "/api/finding", json={"kind": "credential_breach", "subject": HERO}, timeout=30)
            if r.status_code != 200:
                errors.append(("finding", base, r.status_code))
        if i < n_hostile:
            r = s.post(base + "/api/finding", data=json.dumps({"kind": "bogus", "subject": "\ud800"}).encode(),
                       headers={"Content-Type": "application/json"}, timeout=30)
            if r.status_code != 422:
                errors.append(("hostile", base, r.status_code))


with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
    f1 = ex.submit(storm_worker, A, 25, 15, 10)
    f2 = ex.submit(storm_worker, B, 25, 15, 10)
    f1.result()
    f2.result()

post_storm = len(receipts(A))
expected_new = 2 * (25 + 15)  # hostile 422s write nothing
ok6, notes6 = ledger_integrity([A, B])
rec = {"id": "o_concurrent_ledger", "desc": "two consoles, concurrent writers, one append-only ledger",
       "expected": f"+{expected_new} entries, parseable, ordered, both views equal",
       "actual": {"pre": pre_storm, "post": post_storm, "delta": post_storm - pre_storm, "errors": errors[:5], "notes": notes6},
       "pass": (post_storm - pre_storm) == expected_new and not errors and ok6
               and receipts(A) == receipts(B)}
print(f"{'o_concurrent_ledger':36} {pre_storm}->{post_storm} (exp +{expected_new}) errs={len(errors)} int={ok6} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
record(rec)

# ---------------------------------------------------------------- phase 7
print("=== PHASE 7: engine stall -> 503 ===", flush=True)
pid_out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
pid = None
for line in pid_out.splitlines():
    if ":6379" in line and "LISTENING" in line and ("0.0.0.0" in line or "127.0.0.1" in line):
        pid = int(line.split()[-1])
        break
name_out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True).stdout
print("falkordb pid:", pid, "|", " ".join(name_out.split()[-2:]), flush=True)

k32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
PROCESS_SUSPEND_RESUME = 0x0800
handle = k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
suspended = False
try:
    if not handle:
        raise OSError(f"OpenProcess({pid}) failed")
    ntdll.NtSuspendProcess(handle)
    suspended = True
    time.sleep(0.5)
    print("engine SUSPENDED", flush=True)

    def stall_pred(r):
        return {"elapsed_s": round(r.elapsed.total_seconds(), 1),
                "json_body": r.text.strip().startswith("{"),
                "engine_detail": "engine unreachable" in r.text}

    get("o503_state", A + "/api/state", 503, "stalled engine: GET /api/state -> 503 JSON", expect_pred=stall_pred)
    jpost("o503_cut_midflight", C, {"src": HERO, "dst": GHOST, "rel": "GENERIC_ALL", "approved": True}, 503,
          "stalled engine: approved cut mid-flight -> 503 (honest unknown)", expect_pred=stall_pred)
    jpost("o503_finding", F, {"kind": "credential_breach", "subject": HERO}, 503,
          "stalled engine: finding -> 503 (pre-mutation probe)", expect_pred=stall_pred)
    get("o503_receipts_200", A + "/api/receipts", 200,
        "stalled engine: ledger file stays readable (200), trail survives outage",
        expect_pred=lambda r: {"parseable": isinstance(r.json(), list)})
finally:
    if suspended and handle:
        ntdll.NtResumeProcess(handle)
        print("engine RESUMED", flush=True)
    if handle:
        k32.CloseHandle(handle)

time.sleep(1.0)
get("o503_recovery_state", A + "/api/state", 200, "engine resumed: console recovers -> 200",
    expect_pred=lambda r: {"backend_ok": r.json().get("backend") == "falkordb"})

recs_after_stall = receipts(A)
cut_failed = [e for e in recs_after_stall if e.get("step") == "cut_failed"]
rec = {"id": "o503_cut_failed_ledger", "desc": "mid-flight cut recorded as cut_failed outcome=unknown",
       "expected": ">=1 cut_failed entry with outcome unknown + approved_by",
       "actual": cut_failed[-1] if cut_failed else None,
       "pass": bool(cut_failed) and cut_failed[-1].get("outcome") == "unknown" and bool(cut_failed[-1].get("approved_by"))}
print(f"{'o503_cut_failed_ledger':36} {'ok ' if rec['pass'] else 'FAIL'} {json.dumps(cut_failed[-1], default=str)[:160] if cut_failed else 'NONE'}", flush=True)
record(rec)

# ---------------------------------------------------------------- phase 8
print("=== PHASE 8: final ledger integrity ===", flush=True)
final = receipts(A)
ok8, notes8 = ledger_integrity([A, B])
prefix_ok = final[:len(base_receipts)] == base_receipts
ts = [e.get("ts") or "" for e in final]
ordered = all(ts[i] <= ts[i + 1] for i in range(len(ts) - 1))
parseable = all(isinstance(e, dict) for e in final)
steps_seen = sorted({str(e.get("step")) for e in final}, key=str)
rec = {"id": "o_final_ledger", "desc": "append-only prefix, parseable, ordered after full storm",
       "expected": "prefix preserved, ordered, parseable",
       "actual": {"baseline": len(base_receipts), "final": len(final), "prefix_ok": prefix_ok,
                  "ordered": ordered, "parseable": parseable, "steps_seen": steps_seen},
       "pass": prefix_ok and ordered and parseable and len(final) > len(base_receipts)}
print(f"{'o_final_ledger':36} {len(base_receipts)}->{len(final)} prefix={prefix_ok} ordered={ordered} {'ok ' if rec['pass'] else 'FAIL'}", flush=True)
print("steps seen:", steps_seen, flush=True)
record(rec)

# ---------------------------------------------------------------- summary
fails = [x for x in results if not x.get("pass")]
any_500 = [x for x in results if x.get("actual") == 500]
any_503_unexpected = [x for x in results if x.get("actual") == 503 and not str(x.get("id")).startswith("o503")]
print(f"\nOWN-INSTANCE TOTAL {len(results)} | FAIL {len(fails)} | 500s {len(any_500)} | unexpected 503s {len(any_503_unexpected)}", flush=True)
for x in fails:
    print("FAIL:", x.get("id"), "exp", x.get("expected"), "actual", x.get("actual"), str(x.get("semantics", x.get("body", "")))[:200], flush=True)
with open(OUT + ".summary.json", "w", encoding="utf-8") as f:
    json.dump({"total": len(results), "fails": fails, "any_500": any_500, "unexpected_503": any_503_unexpected}, f, indent=2, default=str)
