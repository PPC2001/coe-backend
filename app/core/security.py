import logging
from functools import lru_cache
from typing import Annotated, Callable

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel, Field

from app.services.auth.session import load_session
from app.core.config import Settings, get_settings

logger = logging.getLogger("coe.security")

bearer_scheme = HTTPBearer(auto_error=False)


from app.schemas.users import CurrentUser


def _unauthorized(detail: str = "Invalid or missing access token") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


@lru_cache
def _jwks_client(jwks_uri: str) -> PyJWKClient:
    # In-process key cache; refetches automatically on an unknown `kid` (key rotation).
    return PyJWKClient(jwks_uri, cache_keys=True, lifespan=3600, timeout=10)


def validate_access_token(token: str, settings: Settings) -> dict:
    """Validate a Microsoft-issued v2.0 access token. Fails closed on any problem."""
    try:
        signing_key = _jwks_client(settings.jwks_uri).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],            # hardcoded: never allow "none" or HS*
            audience=settings.audiences,
            leeway=60,
            options={"require": ["exp", "iat", "nbf", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        # Never leak the reason to clients; log only the error class (never the token).
        logger.warning("access token rejected: %s", type(exc).__name__)
        raise _unauthorized() from None

    tid = str(claims.get("tid", "")).lower()
    if not tid or claims.get("iss") != f"https://login.microsoftonline.com/{tid}/v2.0":
        logger.warning("access token rejected: bad issuer")
        raise _unauthorized("Invalid token issuer")
    if claims.get("ver") != "2.0":
        logger.warning("access token rejected: unsupported version %r", claims.get("ver"))
        raise _unauthorized("Unsupported token version (set requestedAccessTokenVersion=2)")

    # Fail closed: an empty allow-list (e.g. multi-tenant without ALLOWED_TENANT_IDS) denies all.
    if tid not in settings.allowed_tenants:
        logger.warning("access token rejected: tenant %s not allowed", tid)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Tenant not allowed")

    # Only accept tokens that were issued to our own SPA.
    if settings.spa_client_id and str(claims.get("azp", "")).lower() != settings.spa_client_id.lower():
        logger.warning("access token rejected: unexpected client (azp)")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Client application not allowed")

    # Delegated user tokens must identify the user. App-only tokens (no scp/oid) are rejected.
    if not claims.get("oid") or not claims.get("sub"):
        logger.warning("access token rejected: missing oid/sub")
        raise _unauthorized()
    return claims


def get_current_user(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> CurrentUser:
    # 1. Bearer Token Authentication (API clients & automated test suites)
    if creds is not None and creds.scheme.lower() == "bearer":
        claims = validate_access_token(creds.credentials, settings)
        scopes = str(claims.get("scp", "")).split()
        if settings.required_scope not in scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing scope: {settings.required_scope}")

        roles = claims.get("roles", [])
        return CurrentUser(
            oid=claims["oid"],
            tid=claims["tid"],
            sub=claims["sub"],
            name=claims.get("name"),
            username=claims.get("preferred_username"),
            scopes=scopes,
            roles=roles if isinstance(roles, list) else [],
            token=creds.credentials,
        )

    # 2. BFF Session Cookie Authentication (Browser SPA sessions - Decision D2)
    sid = request.cookies.get("__Host-coe_session") or request.cookies.get("coe_session")
    if sid:
        sess = load_session(sid)
        if sess and sess.get("oid"):
            roles = sess.get("roles")
            if not roles:
                try:
                    from app.services.authz.authz_repo import resolve_roles
                    snap = sess.get("authz", {})
                    roles = sorted(list(resolve_roles(set(snap.get("groups", [])), sess["oid"])))
                except Exception:
                    roles = ["employee"]
            return CurrentUser(
                oid=sess["oid"],
                tid=sess.get("tid", settings.tenant_id),
                sub=sess.get("sub", sess["oid"]),
                name=sess.get("name"),
                username=sess.get("upn"),
                scopes=[settings.required_scope, "access_as_user"],
                roles=roles if isinstance(roles, list) else [],
                token="",
            )

    raise _unauthorized()


def require_roles(*required: str) -> Callable[[CurrentUser], CurrentUser]:
    """Authorize by Entra App Roles defined on COE-API."""

    def dependency(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        if not set(required).issubset(user.roles):
            logger.warning("authorization denied for oid=%s tid=%s", user.oid, user.tid)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user

    return dependency
