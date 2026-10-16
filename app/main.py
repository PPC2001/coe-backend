from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.services.anonymous.suggestions_repo import init_suggestions_db
from app.api.router import api_router
from app.services.authz.audit import init_audit_table
from app.services.authz.authz_repo import init_authz_tables
from app.core.config import get_settings
from app.core.ratelimit import RateLimitMiddleware
from app.services.documents.documents_repo import init_documents_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

settings = get_settings()
is_dev = settings.is_dev


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_authz_tables()
        init_documents_db()
        init_suggestions_db()
        init_audit_table()
    except Exception as exc:
        logging.getLogger("coe.main").warning("Database startup notice: %s", exc)
    yield


app = FastAPI(
    title="CoE Platform",
    description="ELAN Center of Excellence (CoE) Platform with Microsoft Entra ID Authentication and 5-Layer Authorization",
    version="1.0.0",
    lifespan=lifespan,
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
    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"
    if not (is_dev and request.url.path in {"/docs", "/openapi.json"}):
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


app.add_middleware(
    RateLimitMiddleware,
    limit_per_minute=settings.rate_limit_per_minute,
    trusted_proxy_count=settings.trusted_proxy_count,
)

# Outermost middleware handles CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-CoE-CSRF",
        "X-Session-Ticket",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "COE-Platform",
        "organization": settings.organization_name,
    }


# ---------------------------------------------------------------------------
# Mount Centralized API Router (Unified under /api)
# ---------------------------------------------------------------------------
app.include_router(api_router)
