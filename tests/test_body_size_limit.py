"""Body-size cap middleware (audit3/pentest-internal) — engine-free.

starlette/uvicorn impose no request-body limit: bodies are fully buffered
for JSON parsing, so hostile multi-MB bodies hit RAM (unknown-field variants
even parsed fine and returned 200). The middleware refuses oversize bodies
BEFORE buffering. Status contract (pinned below, audit M72): the
Content-Length fast path answers 413; the chunked/unknown-length path
aborts at the cap and FastAPI answers its own 400 "error parsing the body"
(the middleware's 413 chunked lane is unreachable through FastAPI). The 413
carries the five security headers (audit M47).
"""
from __future__ import annotations

import asyncio
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sever.console.schemas import FindingRequest
from sever.console.security import BodySizeLimitMiddleware

CAP = 1_000  # small cap keeps the test bodies tiny


def build_test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=CAP)

    @app.post("/api/finding")
    async def finding(req: FindingRequest):
        return {"ok": True}

    return app


def test_content_length_over_cap_is_413_without_buffering():
    client = TestClient(build_test_app())
    r = client.post("/api/finding", content=b"9" * (CAP + 1),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert "too large" in r.json()["detail"]


def test_413_carries_the_five_security_headers():
    """audit M47: the 413 answers from the OUTERMOST middleware, bypassing
    the app's header middleware entirely — pre-fix it shipped none of the
    five security headers, falsifying "security headers on every response"
    (README §11) with one curl. The reject lane now ships them itself."""
    from sever.console.security import SECURITY_HEADERS

    client = TestClient(build_test_app())
    r = client.post("/api/finding", content=b"9" * (CAP + 1),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413
    for key, value in SECURITY_HEADERS:
        assert r.headers[key.decode("latin-1")] == value.decode("latin-1"), key


def test_body_at_or_under_cap_reaches_the_schema():
    client = TestClient(build_test_app())
    # under cap, valid JSON -> 200
    r = client.post("/api/finding", content=json.dumps({"subject": "S-1-5-21-x"}),
                    headers={"content-type": "application/json"})
    assert r.status_code == 200
    # exactly at cap: passes the size gate, dies at the schema (garbage payload)
    r = client.post("/api/finding", content=b"9" * CAP,
                    headers={"content-type": "application/json"})
    assert r.status_code == 422


async def _call_asgi(app, chunks, content_type=False):
    messages = []
    idx = {"i": 0}

    async def receive():
        if idx["i"] < len(chunks):
            idx["i"] += 1
            return chunks[idx["i"] - 1]
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    headers = [(b"content-type", b"application/json")] if content_type else []
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/api/finding",
        "raw_path": b"/api/finding", "query_string": b"", "headers": headers,
        "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 80),
    }
    await app(scope, receive, send)
    return messages


def test_chunked_stream_over_cap_is_aborted_without_buffering():
    """No content-length header (chunked-style): the counting receive aborts
    at the cap. Through FastAPI the rejection surfaces as FastAPI's own 400
    "error parsing the body" — the body reader catches the aborted read
    before the middleware's 413 lane is ever observed (pinned reality, audit
    M72/X62: the README's old "413 on both the Content-Length and
    chunked-stream paths" claim was true only for the Content-Length path).
    Either way the body is REJECTED and the bytes beyond the cap are never
    buffered."""
    app = build_test_app()
    chunks = [
        {"type": "http.request", "body": b"9" * (CAP // 2 + 1), "more_body": True},
        {"type": "http.request", "body": b"9" * (CAP // 2), "more_body": False},
    ]
    messages = asyncio.run(_call_asgi(app, chunks))
    start = messages[0]
    assert start["type"] == "http.response.start"
    assert start["status"] == 400, (
        "chunked over-cap must surface as FastAPI's body-parse 400 — "
        f"got {start['status']}"
    )
    body = b"".join(m.get("body", b"") for m in messages[1:])
    assert b"error parsing the body" in body


def test_chunked_stream_under_cap_passes_through():
    app = build_test_app()
    body = json.dumps({"subject": "S-1-5-21-x"}).encode()
    half = len(body) // 2
    chunks = [
        {"type": "http.request", "body": body[:half], "more_body": True},
        {"type": "http.request", "body": body[half:], "more_body": False},
    ]
    messages = asyncio.run(_call_asgi(app, chunks, content_type=True))
    assert messages[0]["status"] == 200
    assert b"true" in messages[-1]["body"]


def test_default_cap_is_one_megabyte():
    app = FastAPI()
    mw = BodySizeLimitMiddleware(app)
    assert mw.max_bytes == 1_000_000
