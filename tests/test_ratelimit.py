from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.core.ratelimit import RateLimitMiddleware


def _app(limit: int) -> TestClient:
    async def ok(_request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/x", ok), Route("/health", ok)])
    app.add_middleware(RateLimitMiddleware, limit_per_minute=limit)
    return TestClient(app)


def test_blocks_after_limit():
    c = _app(3)
    assert [c.get("/x").status_code for _ in range(3)] == [200, 200, 200]
    r = c.get("/x")
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1


def test_health_is_exempt():
    c = _app(1)
    assert all(c.get("/health").status_code == 200 for _ in range(5))
