import logging
from typing import Annotated

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from .config import Settings, get_settings
from .graph import acquire_graph_token, graph_get
from .ratelimit import RateLimitMiddleware
from .security import CurrentUser, get_current_user, require_roles

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

settings = get_settings()
is_dev = settings.environment == "development"

app = FastAPI(
    title="CoE API",
    # Interactive docs only in development; no schema exposure in production.
    docs_url="/docs" if is_dev else None,
    redoc_url=None,
    openapi_url="/openapi.json" if is_dev else None,
)


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    # Authenticated JSON must never be cached by browsers or intermediaries.
    response.headers["Cache-Control"] = "no-store"
    if not (is_dev and request.url.path in {"/docs", "/openapi.json"}):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


app.add_middleware(
    RateLimitMiddleware,
    limit_per_minute=settings.rate_limit_per_minute,
    trusted_proxy_count=settings.trusted_proxy_count,
)

# Added last => outermost, so CORS headers are also present on 429 / error responses.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,     # explicit origins, never "*"
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=False,                     # Bearer tokens, not cookies
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/me")
def me(user: Annotated[CurrentUser, Depends(get_current_user)]) -> dict:
    """Identity as derived from the validated access token."""
    return user.model_dump(exclude={"token"})


@app.get("/api/admin/ping")
def admin_ping(user: Annotated[CurrentUser, Depends(require_roles("Admin"))]) -> dict:
    return {"ok": True, "oid": user.oid}


@app.get("/api/graph/me")
def graph_me(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    cfg: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Calls Microsoft Graph as the signed-in user via OBO."""
    graph_token = acquire_graph_token(user.token, cfg, ["https://graph.microsoft.com/User.Read"])
    return graph_get("/me", graph_token)
