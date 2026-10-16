#!/usr/bin/env python
"""audit5/api-matrix — LIVE input-matrix conformance sweep.

Target: https://sever-console.onrender.com (public Render deploy, FalkorDB Cloud).
Mutations AUTHORIZED by task; every case below is either a rejection (no
mutation) or an authorized no-op/idempotent mutation on ghost principals.

Documented contract asserted (sever/console/app.py + schemas.py):
  422 schema / 400 vocabulary+estate / 403 gate / 413 body cap (>1MB) /
  503 ONLY for engine stalls / 405 wrong method / 404 unknown path /
  docs (openapi.json, /docs, /redoc) opt-in OFF on the public deploy.
"""
from __future__ import annotations

import json
import os
import sys
import time

import requests

BASE = os.environ.get("SEVER_AUDIT_BASE", "https://sever-console.onrender.com")
OUT = sys.argv[1] if len(sys.argv) > 1 else "audit5_live_results.jsonl"
HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"  # live owned hero (/api/state)
GHOST = "S-1-5-21-2697957641-2271029196-387917394-9999"

results: list[dict] = []
transport_flaps = {"conn": 0, "proxy_502": 0}


def call(method: str, path: str, **kw):
    """Transport-robust request: Render free-tier proxy flaps (502) and cold
    starts are NOT the app's contract — retry those, never retry app codes."""
    last = None
    for attempt in range(8):
        try:
            r = requests.request(method, BASE + path, timeout=120, **kw)
            if r.status_code == 502:
                transport_flaps["proxy_502"] += 1
                last = r
                time.sleep(2 + attempt)
                continue
            return r
        except requests.RequestException as e:
            transport_flaps["conn"] += 1
            last = e
            time.sleep(2 + attempt)
    raise RuntimeError(f"transport failed after retries: {last}")


def check(cid, method, path, expected, desc, **kw):
    exp = expected if isinstance(expected, list) else [expected]
    rec = {"id": cid, "desc": desc, "expected": exp}
    try:
        r = call(method, path, **kw)
        rec["actual"] = r.status_code
        rec["pass"] = r.status_code in exp
        if not rec["pass"]:
            rec["body"] = r.text[:300]
        if r.status_code >= 500 and r.status_code != 503:
            rec["body"] = r.text[:300]
        if r.status_code == 503:
            rec["body"] = r.text[:300]  # 503 must be engine-stall only
        ct = kw.get("headers", {}).get("Content-Type") or kw.get("headers", {}).get("content-type")
        print(f"{cid:34} {r.status_code:>4} exp {exp} {'ok ' if rec['pass'] else 'FAIL'} {desc}", flush=True)
        return r
    except Exception as e:
        rec["actual"] = "ERR"
        rec["pass"] = False
        rec["body"] = str(e)[:300]
        print(f"{cid:34} ERR  exp {exp} FAIL {desc} :: {e}", flush=True)
        return None
    finally:
        results.append(rec)
        with open(OUT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")


def j(**kw):  # requests json shortcut
    return {"json": kw}


J = "application/json"


def raw(body: bytes, ct=J):
    return {"data": body, "headers": {"Content-Type": ct} if ct else {}}


# ---------------------------------------------------------------- baseline
print("=== BASELINE ===", flush=True)
r = check("get_state_baseline", "GET", "/api/state", 200, "state 200 + capture estate baseline")
base_state = r.json() if r is not None else {}
r = check("get_receipts_baseline", "GET", "/api/receipts", 200, "receipts 200 + baseline prefix capture")
baseline_receipts = r.json() if r is not None else []
with open(OUT + ".baseline_receipts.json", "w", encoding="utf-8") as f:
    json.dump(baseline_receipts, f)
with open(OUT + ".baseline_state.json", "w", encoding="utf-8") as f:
    json.dump(base_state, f)
r = check("get_paths_baseline", "GET", "/api/paths", 200, "paths 200 + real hop ids")
REAL_TARGET = None
if r is not None:
    paths = r.json().get("paths", [])
    if paths and paths[0].get("hops"):
        REAL_TARGET = paths[0]["hops"][0].get("dst_id")
results[-1]["real_target"] = REAL_TARGET
print("REAL_TARGET:", REAL_TARGET, flush=True)

check("get_root_html", "GET", "/", 200, "GET / serves the console HTML")
r = check("get_proposal", "GET", "/api/proposal", 200, "GET /api/proposal ranked list")

# security headers on every response (audit3/pentest-external contract)
r = requests.get(BASE + "/api/state", timeout=120)
hdr = lambda k: r.headers.get(k)
hdr_ok = {
    "X-Content-Type-Options": hdr("X-Content-Type-Options") == "nosniff",
    "X-Frame-Options": hdr("X-Frame-Options") == "DENY",
    "Referrer-Policy": hdr("Referrer-Policy") == "no-referrer",
    "CSP": bool(hdr("Content-Security-Policy")),
    "HSTS": bool(hdr("Strict-Transport-Security")),
}
results.append({"id": "security_headers", "desc": "hardening headers on /api/state", "expected": "all", "actual": hdr_ok, "pass": all(hdr_ok.values())})
print("security_headers", hdr_ok, flush=True)

# docs opt-in OFF on the public deploy
check("docs_off_openapi", "GET", "/openapi.json", 404, "openapi.json not exposed (recon surface)")
check("docs_off_swagger", "GET", "/docs", 404, "/docs not exposed")
check("docs_off_redoc", "GET", "/redoc", 404, "/redoc not exposed")

r = check("cors_preflight_405", "OPTIONS", "/api/cut", 405, "CORS preflight unanswered (no CORSMiddleware)")
if r is not None:
    results[-1]["acao_absent"] = "Access-Control-Allow-Origin" not in r.headers

# wrong method / unknown path
check("post_on_get_endpoint", "POST", "/api/state", 405, "POST on GET-only endpoint -> 405")
check("unknown_path_404", "GET", "/api/definitely-not-here", 404, "unknown path -> 404")
check("get_state_junk_query", "GET", "/api/state?foo=bar&limit=99999", 200, "GET query params ignored")

# ------------------------------------------------------------ POST /api/finding
print("=== POST /api/finding ===", flush=True)
F = "/api/finding"
check("f_malformed_json", "POST", F, 422, "malformed JSON body", **raw(b'{"kind":"credential_breach","subject":"'))
check("f_ct_textplain", "POST", F, 422, "wrong content-type text/plain + JSON body", **raw(json.dumps({"kind": "credential_breach", "subject": HERO}).encode(), "text/plain"))
check("f_ct_xml", "POST", F, 422, "wrong content-type application/xml", **raw(b"<kind>credential_breach</kind>", "application/xml"))
check("f_ct_urlencoded", "POST", F, 422, "wrong content-type x-www-form-urlencoded", **raw(b"kind=credential_breach&subject=" + HERO.encode(), "application/x-www-form-urlencoded"))
check("f_ct_multipart", "POST", F, 422, "wrong content-type multipart/form-data", **raw(b"--X\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\ncredential_breach\r\n--X--\r\n", "multipart/form-data; boundary=X"))
check("f_empty_body", "POST", F, 422, "empty body (content-length 0)", **raw(b""))
check("f_body_array", "POST", F, 422, "JSON array body", **raw(b"[1,2,3]"))
check("f_body_string", "POST", F, 422, "JSON string body", **raw(b'"hello"'))
check("f_body_null", "POST", F, 422, "JSON null body", **raw(b"null"))
check("f_missing_subject", "POST", F, 422, "missing required subject", **raw(b"{}"))
check("f_empty_subject", "POST", F, 422, "empty subject string", **j(kind="credential_breach", subject=""))
check("f_100kb_subject", "POST", F, 422, "100KB subject field", **j(kind="credential_breach", subject="A" * 100_000))
check("f_100kb_rel", "POST", F, 422, "100KB rel field", **j(kind="ace_granted", subject=HERO, target=HERO, rel="A" * 100_000))
check("f_surrogate_subject", "POST", F, 422, "lone surrogate in subject", **raw(json.dumps({"kind": "credential_breach", "subject": "\ud800"}).encode()))
check("f_surrogate_rel", "POST", F, 422, "lone surrogate in rel", **raw(json.dumps({"kind": "ace_granted", "subject": HERO, "target": HERO, "rel": "\ud800"}).encode()))
check("f_unknown_kind", "POST", F, 422, "unknown finding kind (closed vocab)", **j(kind="totally_unknown_kind", subject=HERO))
check("f_ace_no_grant", "POST", F, 422, "ace_granted without target/rel", **j(kind="ace_granted", subject=HERO))
check("f_self_grant", "POST", F, 422, "self-grant target==subject", **j(kind="ace_granted", subject=HERO, target=HERO, rel="GENERIC_ALL"))
check("f_rel_newline", "POST", F, 422, "rel with trailing newline (anchor)", **j(kind="ace_granted", subject=HERO, target=HERO, rel="MEMBER_OF\n"))
check("f_rel_injection", "POST", F, 422, "Cypher injection rel", **j(kind="ace_granted", subject=HERO, target=HERO, rel="MATCH (n) RETURN n"))
check("f_rel_space", "POST", F, 422, "rel with space", **j(kind="ace_granted", subject=HERO, target=HERO, rel="MEMBER OF"))
check("f_rel_leading_digit", "POST", F, 422, "rel starting with digit", **j(kind="ace_granted", subject=HERO, target=HERO, rel="1MEMBER"))
check("f_rel_65chars", "POST", F, 422, "rel 65 chars", **j(kind="ace_granted", subject=HERO, target=HERO, rel="A" * 65))
check("f_ghost_subject", "POST", F, 400, "ghost principal subject", **j(kind="credential_breach", subject=GHOST))
check("f_ghost_target", "POST", F, 400, "ghost principal target", **j(kind="ace_granted", subject=HERO, target=GHOST, rel="GENERIC_ALL"))
check("f_ssrf_subject", "POST", F, 400, "SSRF-shaped subject (metadata URL)", **j(kind="credential_breach", subject="http://169.254.169.254/latest/meta-data/"))
check("f_ssrf_file_subject", "POST", F, 400, "SSRF-shaped subject (file://)", **j(kind="credential_breach", subject="file:///etc/passwd"))
r = check("f_unknown_rel_generic", "POST", F, 400, "schema-valid unknown rel generic_all (vocabulary)", **j(kind="ace_granted", subject=HERO, target=REAL_TARGET, rel="generic_all"))
if REAL_TARGET:
    check("f_ssrf_cased_rel", "POST", F, 400, "SSRF-looking charset-valid rel HTTPSHOP", **j(kind="ace_granted", subject=HERO, target=REAL_TARGET, rel="HTTPSHOP"))
check("f_astral_subject", "POST", F, 400, "valid astral unicode subject -> ghost 400", **j(kind="credential_breach", subject="\U0001F5A5"))
check("f_surrogate_pair_target", "POST", F, 400, "valid surrogate pair reassembles -> ghost 400", **raw(b'{"kind":"credential_breach","subject":"' + HERO.encode() + b'","target":"\\ud83d\\udcbb","rel":"GENERIC_ALL"}'))
# duplicate JSON keys — python json is last-wins; both directions fail closed
check("f_dupkeys_ghost_last", "POST", F, 400, "dup keys: real subject then ghost -> last wins -> 400 estate", **raw(b'{"kind":"credential_breach","subject":"' + HERO.encode() + b'","subject":"S-GHOST"}'))
r = check("f_dupkeys_valid_last", "POST", F, 200, "dup keys: bogus kind then valid -> last-wins applies finding", **raw(b'{"kind":"bogus_kind","kind":"credential_breach","subject":"' + HERO.encode() + b'"}'))
if r is not None and r.status_code == 200:
    results[-1]["applied"] = r.json().get("applied")

# ------------------------------------------------------------ POST /api/cut
print("=== POST /api/cut ===", flush=True)
C = "/api/cut"
cut_ok = dict(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved=False)
check("c_missing_approved", "POST", C, 422, "missing approved", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL"))
check("c_approved_null", "POST", C, 422, "approved null", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved=None))
check("c_approved_1", "POST", C, 422, "approved 1", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved=1))
check("c_approved_1_0", "POST", C, 422, "approved 1.0", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved=1.0))
check("c_approved_str_true", "POST", C, 422, "approved 'true'", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved="true"))
check("c_approved_str_yes", "POST", C, 422, "approved 'yes'", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved="yes"))
check("c_approved_str_on", "POST", C, 422, "approved 'on'", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved="on"))
check("c_approved_str_1", "POST", C, 422, "approved '1'", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved="1"))
check("c_approved_nested_obj", "POST", C, 422, "approved nested object", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved={"v": True}))
check("c_approved_array", "POST", C, 422, "approved [true]", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved=[True]))
check("c_gate_false", "POST", C, 403, "gate: approved=false -> 403", **j(**cut_ok))
check("c_gate_false_invalid_rel", "POST", C, 403, "gate before vocabulary: false + generic_all -> 403 not 400", **j(src=HERO, dst=GHOST, rel="generic_all", approved=False))
check("c_gate_false_ghost", "POST", C, 403, "gate before estate: false + ghosts -> 403 not 400", **j(src=GHOST, dst=GHOST, rel="GENERIC_ALL", approved=False))
check("c_missing_src", "POST", C, 422, "missing src", **j(dst=GHOST, rel="GENERIC_ALL", approved=False))
check("c_empty_src", "POST", C, 422, "empty src", **j(src="", dst=GHOST, rel="GENERIC_ALL", approved=False))
check("c_empty_dst", "POST", C, 422, "empty dst", **j(src=HERO, dst="", rel="GENERIC_ALL", approved=False))
check("c_100kb_src", "POST", C, 422, "100KB src field", **j(src="A" * 100_000, dst=GHOST, rel="GENERIC_ALL", approved=False))
check("c_surrogate_src", "POST", C, 422, "lone surrogate in src", **raw(json.dumps({"src": "\ud800", "dst": GHOST, "rel": "GENERIC_ALL", "approved": False}).encode()))
check("c_rel_newline", "POST", C, 422, "rel trailing newline", **j(src=HERO, dst=GHOST, rel="MEMBER_OF\n", approved=False))
check("c_rel_injection", "POST", C, 422, "Cypher injection rel", **j(src=HERO, dst=GHOST, rel="X)-[r:M]->(d RETURN 1", approved=False))
check("c_empty_approved_by", "POST", C, 422, "empty approved_by", **j(src=HERO, dst=GHOST, rel="GENERIC_ALL", approved=False, approved_by=""))
check("c_dupkeys_approved_false_last", "POST", C, 403, "dup keys approved true then false -> 403 fail closed", **raw(b'{"approved": true, "approved": false, "src": "' + HERO.encode() + b'", "dst": "' + GHOST.encode() + b'", "rel": "GENERIC_ALL"}'))
check("c_approved_true_generic_all", "POST", C, 400, "approved + unknown rel -> 400 vocabulary, no mutation", **j(src=HERO, dst=REAL_TARGET or GHOST, rel="generic_all", approved=True))
r = check("c_approved_true_ghost_noop", "POST", C, 200, "approved + ghost edge -> honest zero-removal receipt (no-op)", **j(src=GHOST, dst=GHOST, rel="GENERIC_ALL", approved=True))
if r is not None and r.status_code == 200:
    body = r.json()
    results[-1]["removed"] = body.get("relationships_removed", body.get("removed"))

# body cap: >1MB -> 413 (content-length fast path)
big = json.dumps({"src": HERO, "dst": GHOST, "rel": "GENERIC_ALL", "approved": False, "pad": "x" * 1_500_000}).encode()
check("c_body_1_5mb_413", "POST", C, 413, "1.5MB body -> 413 (content-length path)", **raw(big))
# body cap: chunked/unknown-length -> 413 (streaming path)
def chunks(n=24, size=70_000):
    for _ in range(n):
        yield b"x" * size
check("c_body_chunked_413", "POST", C, 413, "1.6MB chunked body -> 413 (streaming path)", data=chunks(), headers={"Content-Type": J})
# just under cap passes to the schema (unknown extra field ignored, gate still applies)
just_under = json.dumps({"src": HERO, "dst": GHOST, "rel": "GENERIC_ALL", "approved": False, "pad": "y" * (1_000_000 - 160)}).encode()
check("c_body_just_under_1mb", "POST", C, 403, "~1MB body under cap reaches schema/gate (extras ignored)", **raw(just_under))
# exactly 1MB+1
over_1 = json.dumps({"pad": "z" * (1_000_000 - 12)}).encode()
check("c_body_1mb_plus_1_413", "POST", C, 413, "1MB+ body over cap -> 413", **raw(over_1))

# ------------------------------------------------- POST /api/plan/execute
print("=== POST /api/plan/execute ===", flush=True)
P = "/api/plan/execute"
ghost_steps = [{"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": 1} for _ in range(3)]
check("p_missing_approved", "POST", P, 422, "missing approved", **j(steps=ghost_steps))
check("p_approved_null", "POST", P, 422, "approved null", **j(steps=ghost_steps, approved=None))
check("p_approved_1", "POST", P, 422, "approved 1", **j(steps=ghost_steps, approved=1))
check("p_approved_str_true", "POST", P, 422, "approved 'true'", **j(steps=ghost_steps, approved="true"))
check("p_approved_nested", "POST", P, 422, "approved nested object", **j(steps=ghost_steps, approved={"ok": True}))
check("p_approved_false_valid", "POST", P, 403, "gate: approved=false -> 403", **j(steps=ghost_steps, approved=False))
check("p_gate_first_invalid_rel", "POST", P, 403, "gate before vocabulary: false + generic_all steps -> 403", **j(steps=[{"src": HERO, "dst": GHOST, "rel": "generic_all", "projected_reachability": 1}], approved=False))
check("p_steps_empty", "POST", P, 422, "approved + empty steps -> 422", **j(steps=[], approved=True))
check("p_steps_missing", "POST", P, 422, "steps missing entirely", **j(approved=True))
check("p_steps_11", "POST", P, 422, "11 steps (max 10)", **j(steps=[{"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": 1}] * 11, approved=True))
check("p_step_missing_projection", "POST", P, 422, "step missing projected_reachability", **j(steps=[{"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL"}], approved=True))
check("p_step_negative_projection", "POST", P, 422, "step negative projected_reachability", **j(steps=[{"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": -1}], approved=True))
check("p_step_100kb_src", "POST", P, 422, "step 100KB src", **j(steps=[{"src": "A" * 100_000, "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": 1}], approved=True))
check("p_step_surrogate", "POST", P, 422, "step lone surrogate", **raw(json.dumps({"approved": True, "steps": [{"src": "\ud800", "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": 1}]}).encode()))
check("p_dupkeys_fail_closed", "POST", P, 403, "dup keys approved true then false -> 403", **raw(b'{"approved": true, "approved": false, "steps": ' + json.dumps(ghost_steps).encode() + b'}'))
check("p_approved_generic_all_400", "POST", P, 400, "approved + unknown rel step -> 400 vocabulary, no mutation", **j(steps=[{"src": HERO, "dst": GHOST, "rel": "generic_all", "projected_reachability": 1}], approved=True))
r = check("p_approved_ghost_completed", "POST", P, 200, "approved + 3 no-op ghost steps, projections match -> completed", **j(steps=ghost_steps, approved=True))
if r is not None and r.status_code == 200:
    body = r.json()
    results[-1]["status"] = body.get("status")
    results[-1]["executed_steps"] = body.get("executed_steps")
    results[-1]["drifts"] = [s.get("plan_drift") for s in body.get("steps", [])]
r = check("p_drift_stop_ghost", "POST", P, 200, "approved + wrong projection -> drift_stopped_at_step, later steps never run", **j(steps=[
    {"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": 0},
    {"src": GHOST, "dst": GHOST, "rel": "GENERIC_ALL", "projected_reachability": 0},
], approved=True))
if r is not None and r.status_code == 200:
    body = r.json()
    results[-1]["status"] = body.get("status")
    results[-1]["executed_steps"] = body.get("executed_steps")
    results[-1]["drifts"] = [s.get("plan_drift") for s in body.get("steps", [])]

# ------------------------------------------------------------ GET /api/plan
print("=== GET /api/plan ===", flush=True)
r = check("get_plan_200", "GET", "/api/plan", 200, "plan 200 graph_copy_remeasure")
plan_shape_ok = False
if r is not None and r.status_code == 200:
    plan = r.json()
    steps = plan.get("steps", [])
    plan_shape_ok = (
        plan.get("method") == "graph_copy_remeasure"
        and isinstance(steps, list) and len(steps) > 0
        and steps[0].get("step") == 1
        and all(s.get("cut", {}).get("src") and s["cut"].get("rel") and s["cut"].get("dst") for s in steps)
        and all(isinstance(s.get("projected_reachability"), int) for s in steps)
        and all(s["step"] == i + 1 for i, s in enumerate(steps))
    )
    results[-1]["plan_shape_ok"] = plan_shape_ok
    if not plan_shape_ok:
        results[-1]["pass"] = False
    results[-1]["n_steps"] = len(steps)
r = check("get_state_after_plan", "GET", "/api/state", 200, "estate untouched by plan projection (state re-read)")
if r is not None:
    s2 = r.json()
    untouched = (s2.get("nodes") == base_state.get("nodes") and s2.get("edges") == base_state.get("edges")
                 and s2.get("reachability") == base_state.get("reachability"))
    results[-1]["estate_untouched"] = untouched
    if not untouched:
        results[-1]["pass"] = False
        results[-1]["state_after"] = {k: s2.get(k) for k in ("nodes", "edges", "reachability", "owned")}

# GET with junk body / wrong CT should not disturb GETs (bodies ignored)
check("get_state_junk_body", "GET", "/api/state", 200, "GET with garbage body unaffected", **raw(b"garbage-not-json", "text/plain"))

# ------------------------------------------------------------ ledger integrity
print("=== LEDGER INTEGRITY ===", flush=True)
r = check("receipts_after_storm", "GET", "/api/receipts", 200, "receipts parseable after storm")
if r is not None and r.status_code == 200:
    after = r.json()
    parseable = isinstance(after, list) and all(isinstance(e, dict) for e in after)
    prefix_ok = len(after) >= len(baseline_receipts) and after[: len(baseline_receipts)] == baseline_receipts
    ts_list = [e.get("ts") for e in after if e.get("ts")]
    ordered = all(ts_list[i] <= ts_list[i + 1] for i in range(len(ts_list) - 1))
    results[-1].update({
        "parseable": parseable,
        "append_only_prefix_preserved": prefix_ok,
        "ts_ordering_sane": ordered,
        "baseline_count": len(baseline_receipts),
        "after_count": len(after),
    })
    results[-1]["pass"] = parseable and prefix_ok and ordered
    print(f"ledger: parseable={parseable} prefix_ok={prefix_ok} ordered={ordered} {len(baseline_receipts)}->{len(after)}", flush=True)

r = check("final_state_integrity", "GET", "/api/state", 200, "estate integrity after authorized storm")
if r is not None:
    s3 = r.json()
    same = (s3.get("nodes") == base_state.get("nodes") and s3.get("edges") == base_state.get("edges")
           and s3.get("reachability") == base_state.get("reachability") and s3.get("owned") == base_state.get("owned"))
    results[-1]["estate_same_as_baseline"] = same
    if not same:
        results[-1]["pass"] = False
        results[-1]["state_after"] = {k: s3.get(k) for k in ("nodes", "edges", "reachability", "owned")}

# ------------------------------------------------------------ summary
fails = [x for x in results if not x.get("pass")]
any_500 = [x for x in results if x.get("actual") == 500]
any_503 = [x for x in results if x.get("actual") == 503]
print(f"\nTOTAL {len(results)} cases | FAIL {len(fails)} | 500s {len(any_500)} | 503s {len(any_503)} | transport flaps {transport_flaps}", flush=True)
with open(OUT + ".summary.json", "w", encoding="utf-8") as f:
    json.dump({"total": len(results), "fails": fails, "any_500": any_500, "any_503": any_503, "transport_flaps": transport_flaps}, f, indent=2, default=str)
for x in fails:
    print("FAIL:", x.get("id"), "expected", x.get("expected"), "actual", x.get("actual"), str(x.get("body", ""))[:120], flush=True)
