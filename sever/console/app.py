"""SEVER console — the agent's cockpit. FastAPI over a GraphPort.

The human gate is a real HTTP round-trip: the UI renders the ranked proposal
and the operator clicks APPROVE — the cut executes only on that explicit call.

Run against the live engine:
    uvicorn sever.console.app:app --host 0.0.0.0 --port 8000
Env: SEVER_FALKOR_HOST/PORT, SEVER_FALKOR_GRAPH, SEVER_SAMPLE_DIR
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from sever.agent.investigator import Investigator
from sever.core.falkor_port import FalkorGraphPort
from sever.core.mock_port import MockGraphPort
from sever.etl.ad_collectors import parse_ad_dir
from sever.findings.attack_map import narrate
from sever.findings.stream import Finding, apply_finding
from sever.memory.flow import CaseLog

HERO = "S-1-5-21-2697957641-2271029196-387917394-2110"  # T1_TONYMONTANA@PHANTOM.CORP


class CutRequest(BaseModel):
    src: str
    dst: str
    rel: str
    approved: bool
    approved_by: str = "console-operator"


class FindingRequest(BaseModel):
    kind: str = "credential_breach"
    subject: str = HERO
    target: str | None = None
    rel: str | None = None


def build_app() -> FastAPI:
    app = FastAPI(title="SEVER console", version="0.1.0")
    backend = os.environ.get("SEVER_BACKEND", "falkordb")

    if backend == "falkordb":
        port = FalkorGraphPort(
            host=os.environ.get("SEVER_FALKOR_HOST", "127.0.0.1"),
            port=int(os.environ.get("SEVER_FALKOR_PORT", "6379")),
            graph_name=os.environ.get("SEVER_FALKOR_GRAPH", "sever_demo"),
        )
        if port.node_count() == 0:
            normalized = parse_ad_dir(os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample"))
            port.load(normalized)
    else:
        normalized = parse_ad_dir(os.environ.get("SEVER_SAMPLE_DIR", "N:/HERMESSSS/graphhacks/data/ad_sample"))
        port = MockGraphPort()
        port.load(normalized)

    inv = Investigator(port)
    log = CaseLog(os.environ.get("SEVER_FALKOR_GRAPH", "sever_demo"))

    def names(hops: list[tuple[str, str, str]]) -> list[dict[str, str]]:
        out = []
        for s, r, d in hops:
            out.append({
                "src": _name(s), "src_id": s,
                "rel": r,
                "dst": _name(d), "dst_id": d,
            })
        return out

    def _name(oid: str) -> str:
        if hasattr(port, "g"):  # mock
            return port.g.nodes[oid]["props"].get("name", oid)
        return oid  # live: keep ids (names fetched via query when needed)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        reach = port.reachability()
        data = {
            "backend": backend,
            "nodes": port.node_count(),
            "edges": port.edge_count(),
            "jewels": port.crown_jewels(),
            "owned": port.owned_ids(),
            "reachability": reach,
        }
        log.append({"step": "state", **{k: data[k] for k in ("reachability", "nodes", "edges")}})
        return data

    @app.get("/api/paths")
    async def paths() -> dict[str, Any]:
        out: dict[str, Any] = {"owned": [], "paths": []}
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
        report = inv.triage(f)
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
        if req.approved is not True:
            raise HTTPException(status_code=403, detail="interdiction requires explicit human approval")
        receipt = inv.approve_and_cut(req.src, req.dst, req.rel, approved_by=req.approved_by)
        log.append({"step": "cut", "receipt": receipt})
        return receipt

    @app.get("/api/receipts")
    async def receipts() -> list[dict[str, Any]]:
        return log.read()

    return app


app = build_app()
