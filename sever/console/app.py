"""SEVER console — the agent's cockpit. FastAPI over the live FalkorDB engine.

The human gate is a real HTTP round-trip: the UI renders the ranked proposal
and the operator clicks APPROVE — the cut executes only on that explicit call.

Run:
    uvicorn sever.console.app:app --host 0.0.0.0 --port 8000
Env: SEVER_FALKOR_HOST/PORT/USER/PASSWORD, SEVER_FALKOR_GRAPH,
     SEVER_SAMPLE_DIR — a .env at the repo root is loaded automatically
     (real environment always wins).

API contract (audit2/api-contract), enforced by sever.console.schemas BEFORE
any handler runs:
- 422 schema: malformed JSON, wrong types, missing fields, empty required
  strings, oversized fields (100KB subject dies here), rel syntax violations
  (injection payloads, trailing newlines, >64 chars), truthy non-bool
  ``approved`` (1, 1.0, "true", "yes", "on", "1"), lone surrogates.
- 400 vocabulary: a syntactically valid but unknown rel (e.g. "generic_all")
  reaches FalkorGraphPort's closed-vocabulary guard and is a client error,
  never a 500.
- 403 gate: the cut handler accepts only ``approved is True`` — the schema's
  StrictBool guarantees nothing else can ever be True here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from starlette.responses import Response
from dotenv import load_dotenv

from sever.agent.investigator import Investigator
from sever.console.security import BodySizeLimitMiddleware
from sever.console.schemas import CutRequest, FindingRequest
from sever.console.security import BodySizeLimitMiddleware
from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import parse_ad_dir
from sever.findings.attack_map import narrate
from sever.findings.stream import Finding
from sever.memory.flow import CaseLog


def build_app() -> FastAPI:
    load_dotenv()  # .env at the repo root, if present — real environment always wins

    # OpenAPI/Swagger is opt-in (SEVER_DOCS=1). The console is deployed on a
    # public URL, and the rendered schema (/openapi.json, /docs, /redoc) is
    # free attacker recon — full route + CutRequest shape disclosure — with no
    # product value for a demo UI that already renders the same information.
    docs_enabled = os.environ.get("SEVER_DOCS", "").lower() in ("1", "true", "yes")
    app = FastAPI(
        title="SEVER console", version="0.2.0",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    @app.middleware("http")
    async def _security_headers(request, call_next):
        # Deliberately NO CORSMiddleware: with no CORS policy, no origin other
        # than the console itself can READ any API response from a browser
        # (no Access-Control-Allow-Origin is ever emitted), and non-JSON
        # content types already die as 422 at the body parser, so cross-site
        # requests cannot mutate either. This middleware adds the remaining
        # client-side hardening observed missing on the public deployment
        # (audit3/pentest-external): MIME-sniffing, clickjacking, referrer
        # leakage, and transport security for proxied HTTPS deployments
        # (Render/Cloudflare terminate TLS in front of plain-HTTP uvicorn).
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # The console ships inline <style>/<script> in its single page, so
        # script/style need 'unsafe-inline'; the protective value here is
        # object-src/base-uri/frame-ancestors and a default-src fence.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response
    # body-size cap BEFORE any buffering (audit3/pentest-internal): hostile
    # multi-MB bodies die as 413 without being fully buffered (~4000x the
    # largest schema-capped field; no legitimate request affected).
    app.add_middleware(BodySizeLimitMiddleware)


    @app.exception_handler(RequestValidationError)
    async def _safe_validation_422(request, exc: RequestValidationError):
        # FastAPI echoes the RAW input inside every 422 detail. A lone
        # surrogate in that echo crashes JSONResponse.render (ensure_ascii=
        # False + .encode("utf-8") raises) and turns the schema's own
        # rejection into a 500. Strip the echo and render with
        # ensure_ascii=True so the error path can never be crashed by input.
        errors = [{k: v for k, v in err.items() if k != "input"} for err in exc.errors()]
        body = json.dumps({"detail": errors}, ensure_ascii=True, default=str)
        return Response(content=body, status_code=422, media_type="application/json")

    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=os.environ.get("SEVER_FALKOR_GRAPH", "sever_demo"),
        username=os.environ.get("SEVER_FALKOR_USER"),
        password=os.environ.get("SEVER_FALKOR_PASSWORD"),
    )
    if port.node_count() == 0:
        port.load(parse_ad_dir(os.environ.get(
            "SEVER_SAMPLE_DIR",
            str(Path(__file__).resolve().parents[2] / "data" / "ad_sample"))))

    inv = Investigator(port)
    log = CaseLog(os.environ.get("SEVER_FALKOR_GRAPH", "sever_demo"))
    app.state.port = port

    def _names(hops: list[tuple[str, str, str]]) -> list[dict[str, str]]:
        out = []
        for s, r, d in hops:
            out.append({
                "src": _name(s), "src_id": s,
                "rel": r,
                "dst": _name(d), "dst_id": d,
            })
        return out

    def _name(oid: str) -> str:
        res = port.graph.query(
            "MATCH (n {objectid: $o}) RETURN n.name AS name LIMIT 1", {"o": oid})
        if res.result_set and res.result_set[0][0]:
            return str(res.result_set[0][0])
        return oid

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        data = {
            "backend": "falkordb",
            "graph": port.graph_name,
            "nodes": port.node_count(),
            "edges": port.edge_count(),
            "jewels": port.crown_jewels(),
            "owned": port.owned_ids(),
            "reachability": port.reachability(),
        }
        log.append({"step": "state", **{k: data[k] for k in ("reachability", "nodes", "edges")}})
        return data

    @app.get("/api/paths")
    async def paths() -> dict[str, Any]:
        out: dict[str, Any] = {"paths": []}
        for owned in port.owned_ids():
            for path in port.paths_to_jewels(owned):
                out["paths"].append({"principal": _name(owned), "hops": names(path)})
        return out

    @app.get("/api/proposal")
    async def proposal() -> list[dict[str, Any]]:
        return inv.propose(limit=5)

    @app.post("/api/finding")
    async def finding(req: FindingRequest) -> dict[str, Any]:
        f = Finding(
            # 4 random bytes (8 hex chars): the old 2-byte id space (65,536)
            # collides visibly in the ledger after a few hundred findings.
            id=f"F-{os.urandom(4).hex()}",
            kind=req.kind, subject=req.subject,
            target=req.target, rel=req.rel, grants_edge=bool(req.target and req.rel),
        )
        try:
            report = inv.triage(f)
        except ValueError as e:
            # An invalid rel (e.g. lowercase, spaces, injection attempt) is a
            # CLIENT error — the injection guard in FalkorGraphPort.add_edge
            # rejects it before any Cypher runs. It must surface as a 400,
            # not an unhandled 500 with a stack trace.
            raise HTTPException(status_code=400, detail=str(e))
        log.append({"step": "finding", "finding": f.id, "kind": f.kind, "triage": report.as_dict()})
        story = narrate(f)
        return {
            "finding": f.id,
            "kind": f.kind,
            "technique": f"{story.technique_id} {story.technique}",
            "narration": story.narration,
            "simulated": True,  # findings stream is a labeled breach-timeline replay, not live telemetry
            "applied": report.applied,
            "reachability": report.after["reachability"],
        }

    @app.post("/api/cut")
    async def cut(req: CutRequest) -> dict[str, Any]:
        # The gate check comes FIRST: an unapproved caller learns nothing
        # about rel validity (no oracle without approval).
        if req.approved is not True:
            raise HTTPException(status_code=403, detail="interdiction requires explicit human approval")
        try:
            receipt = inv.approve_and_cut(req.src, req.dst, req.rel, approved_by=req.approved_by)
        except ValueError as e:
            # Only reachable with an invalid rel: the gate above already
            # handled the not-approved case, and FalkorGraphPort.cut rejects
            # bad rels before any Cypher runs. Client error -> 400, not 500.
            raise HTTPException(status_code=400, detail=str(e))
        log.append({"step": "cut", "receipt": receipt})
        return receipt

    @app.get("/api/receipts")
    async def receipts() -> list[dict[str, Any]]:
        return log.read()

    # expose for tests/teardown
    build_app.port_obj = port
    return app


def names(hops):
    return [{"src": s, "rel": r, "dst": d} for s, r, d in hops]


app = build_app()
