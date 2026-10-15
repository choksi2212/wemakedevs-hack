"""SEVER console — the agent's cockpit. FastAPI over the live FalkorDB engine.

The human gate is a real HTTP round-trip: the UI renders the ranked proposal
and the operator clicks APPROVE — the cut executes only on that explicit call.

Run:
    uvicorn sever.console.app:app --host 0.0.0.0 --port 8000
Env: SEVER_FALKOR_HOST/PORT/USER/PASSWORD, SEVER_FALKOR_GRAPH,
     SEVER_SAMPLE_DIR — a .env at the repo root is loaded automatically
     (real environment always wins).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
from pydantic import BaseModel

from sever.agent.investigator import Investigator
from sever.core.falkor_port import FalkorGraphPort
from sever.etl.ad_collectors import parse_ad_dir
from sever.findings.attack_map import narrate
from sever.findings.stream import Finding
from sever.memory.flow import CaseLog


class CutRequest(BaseModel):
    src: str
    dst: str
    rel: str
    approved: bool
    approved_by: str = "console-operator"


class FindingRequest(BaseModel):
    kind: str = "credential_breach"
    subject: str
    target: str | None = None
    rel: str | None = None


def build_app() -> FastAPI:
    load_dotenv()  # .env at the repo root, if present — real environment always wins
    app = FastAPI(title="SEVER console", version="0.2.0")

    port = FalkorGraphPort(
        host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
        port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
        graph_name=os.environ.get("SEVER_FALKOR_GRAPH", "sever_demo"),
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
            id=f"F-{os.urandom(2).hex()}",
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
