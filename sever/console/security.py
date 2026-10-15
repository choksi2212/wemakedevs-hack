"""Console request-hardening middleware (audit3/pentest-internal).

Deliberately engine-free and import-cost-free so tests exercise it without a
FalkorDB connection.
"""
from __future__ import annotations

MAX_BODY_BYTES = 1_000_000  # 1MB cap; every schema-capped field is <=256B


class BodyTooLarge(Exception):
    """Internal: a streamed request body crossed the cap mid-flight."""


class BodySizeLimitMiddleware:
    """Refuse HTTP request bodies over ``max_bytes`` with 413 BEFORE the app
    buffers them (audit3/pentest-internal).

    starlette/uvicorn impose no body-size limit by default: the request body
    is fully buffered into RAM for JSON parsing, so an unauthenticated client
    could stream an arbitrarily large body at any exposed instance (Render
    deployment) and drive memory exhaustion. Schema field caps (<=256B) stop
    oversized *field values* (422), but a hostile body carrying the bytes in
    an unknown extra field parsed fine and returned 200 — the total size was
    uncapped. Two layers here:

    - fast path: a Content-Length header over the cap is refused before any
      byte is read;
    - streaming path: chunked / unknown-length bodies are counted as they are
      relayed to the app, and aborted the moment the cap is exceeded. The
      abort is raised from ``receive`` — for JSON routes the body is fully
      read before any response starts, so replying 413 afterwards is safe.
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
        body = (
            b'{"detail": "request body too large (max 1MB)"}'
        )
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
