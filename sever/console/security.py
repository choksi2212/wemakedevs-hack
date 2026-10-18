"""Console request-hardening middleware (audit3/pentest-internal).

Deliberately engine-free and import-cost-free so tests exercise it without a
FalkorDB connection.
"""
from __future__ import annotations

MAX_BODY_BYTES = 1_000_000  # 1MB cap; every schema-capped field is <=256B

# The five security headers pinned on EVERY console response (README §11;
# app.py's _security_headers middleware sets these on every app-handled
# response). They are defined HERE because the 413 rejection answers from
# THIS middleware — Starlette inserts it OUTERMOST, so its response bypasses
# every inner middleware, including the header middleware — and the reject
# lane must carry the headers itself or "every response" is falsified by one
# curl (audit M47: a >1MB POST answered 413 with none of them). One
# constant, read by both lanes, so the two can never drift apart.
# CSP note: the console ships inline <style>/<script> in its single page, so
# script/style need 'unsafe-inline'; the protective value is
# object-src/base-uri/frame-ancestors plus a default-src fence.
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"content-security-policy",
     b"default-src 'self'; script-src 'self' 'unsafe-inline'; "
     b"style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
     b"connect-src 'self'; object-src 'none'; base-uri 'self'; "
     b"frame-ancestors 'none'"),
    (b"strict-transport-security", b"max-age=31536000"),
)


class BodyTooLarge(Exception):
    """Internal: a streamed request body crossed the cap mid-flight."""


class BodySizeLimitMiddleware:
    """Refuse HTTP request bodies over ``max_bytes`` BEFORE the app buffers
    them (audit3/pentest-internal). Status contract, as pinned by
    tests/test_body_size_limit.py:

    - fast path: a Content-Length header over the cap is refused before any
      byte is read, answered 413 with the five security headers attached;
    - streaming path: chunked / unknown-length bodies are counted as they
      are relayed to the app, and aborted the moment the cap is exceeded.
      The abort is raised from ``receive`` — FastAPI's body reader catches
      it first and answers its own 400 "error parsing the body", so through
      FastAPI the middleware's chunked 413 lane is never observed by the
      client: on this path the rejection surfaces as 400, not 413 (pinned
      reality, audit M72/X62 — the README's old "413 before buffering on
      both paths" claim was true only for the Content-Length path). The
      bytes beyond the cap are never buffered either way.

    starlette/uvicorn impose no body-size limit by default: the request body
    is fully buffered into RAM for JSON parsing, so an unauthenticated client
    could stream an arbitrarily large body at any exposed instance (Render
    deployment) and drive memory exhaustion. Schema field caps (<=256B) stop
    oversized *field values* (422), but a hostile body carrying the bytes in
    an unknown extra field parsed fine and returned 200 — the total size was
    uncapped.
    """

    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        length = 0
        for key, value in scope.get("headers") or []:
            if key.lower() == b"content-length":
                try:
                    length = int(value)
                except ValueError:
                    length = 0
                break
        if length > self.max_bytes:
            await self._reject(send)
            return

        counted = 0

        async def counting_receive():
            nonlocal counted
            message = await receive()
            if message["type"] == "http.request":
                counted += len(message.get("body", b""))
                if counted > self.max_bytes:
                    raise BodyTooLarge()
            return message

        try:
            await self.app(scope, counting_receive, send)
        except BodyTooLarge:
            await self._reject(send)

    async def _reject(self, send) -> None:
        # audit M47: this response never passes through the app's header
        # middleware (this middleware is the outermost layer), so the five
        # security headers ship from SECURITY_HEADERS right here — a 413 is
        # trivially attacker-triggerable on the public URL and must not be
        # the one response class without them.
        body = (
            b'{"detail": "request body too large (max 1MB)"}'
        )
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]
                               + list(SECURITY_HEADERS)})
        await send({"type": "http.response.body", "body": body})
