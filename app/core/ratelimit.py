"""Small in-memory sliding-window rate limiter (per client IP)."""

import time
from collections import deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

_WINDOW_SECONDS = 60.0
_SWEEP_EVERY = 1000  # requests between full sweeps of idle keys


def client_ip(request: Request, trusted_proxy_count: int) -> str:
    """Resolve the client IP, trusting only `trusted_proxy_count` proxies' X-Forwarded-For hops."""
    peer = request.client.host if request.client else "unknown"
    if trusted_proxy_count <= 0:
        return peer
    forwarded = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if len(forwarded) >= trusted_proxy_count:
        return forwarded[-trusted_proxy_count]
    return peer


class RateLimitMiddleware(BaseHTTPMiddleware):
    # TODO(security): state is per-process. With multiple workers/replicas, enforce the limit at
    # the gateway/reverse proxy or back this with a shared store (e.g. Redis).
    def __init__(self, app, limit_per_minute: int, trusted_proxy_count: int = 0) -> None:
        super().__init__(app)
        self._limit = limit_per_minute
        self._proxies = trusted_proxy_count
        self._hits: dict[str, deque[float]] = {}
        self._count = 0

    def _sweep(self, now: float) -> None:
        cutoff = now - _WINDOW_SECONDS
        for key in [k for k, q in self._hits.items() if not q or q[-1] < cutoff]:
            del self._hits[key]

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS" or request.url.path == "/health":
            return await call_next(request)

        now = time.monotonic()
        self._count += 1
        if self._count % _SWEEP_EVERY == 0:
            self._sweep(now)

        key = client_ip(request, self._proxies)
        q = self._hits.setdefault(key, deque())
        while q and q[0] < now - _WINDOW_SECONDS:
            q.popleft()

        if len(q) >= self._limit:
            retry_after = max(1, int(_WINDOW_SECONDS - (now - q[0])))
            return JSONResponse(
                {"detail": "Too many requests"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        q.append(now)
        return await call_next(request)
