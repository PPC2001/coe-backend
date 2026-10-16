import logging
from urllib.parse import quote

import msal
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from app.services.auth.deps import AuthContext, get_auth_context
from app.services.auth.graph_profile import build_snapshot
from app.services.auth.msal_client import GRAPH_SCOPES, build_msal
from app.services.auth.session import (
    FLOW_COOKIE,
    SESSION_COOKIE,
    create_session,
    delete_by_entra_sid,
    delete_session,
    pop_flow,
    save_flow,
    seal,
)
from app.services.authz.audit import audit
from app.services.authz.authz_repo import resolve_roles
from app.core.config import get_settings

logger = logging.getLogger("coe.api.auth")

router = APIRouter()


def _safe_return_to(value: str) -> str:
    """Relative paths only; blocks open redirects such as //evil.com or https://evil.com."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/"


def _set_cookie(resp: Response, name: str, value: str, max_age: int, path: str = "/") -> None:
    s = get_settings()
    resp.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=True,
        secure=s.cookie_secure,
        samesite="lax",
        path=path,
    )


@router.get("/login")
def login(return_to: str = "/", stepup: bool = False):
    s = get_settings()
    app = build_msal()
    flow = app.initiate_auth_code_flow(
        GRAPH_SCOPES,
        redirect_uri=s.redirect_uri,
        prompt="login" if stepup else None,  # step-up forces fresh authentication
    )
    if "auth_uri" not in flow:
        logger.error("Failed to initiate auth code flow with MSAL: %s", flow)
        raise HTTPException(status_code=500, detail="Authentication service configuration error")

    flow["return_to"] = _safe_return_to(return_to)
    flow["stepup"] = stepup

    resp = RedirectResponse(flow["auth_uri"], status_code=302)
    _set_cookie(resp, FLOW_COOKIE, save_flow(flow), max_age=600, path="/")
    return resp


@router.get("/callback")
def callback(request: Request, coe_flow: str | None = Cookie(default=None)):
    s = get_settings()
    flow = pop_flow(coe_flow)
    if flow is None:  # expired, replayed, or login CSRF
        logger.warning("Auth callback received without valid coe_flow cookie")
        return RedirectResponse("/api/auth/login", status_code=302)

    cache = msal.SerializableTokenCache()
    app = build_msal(cache)
    try:
        result = app.acquire_token_by_auth_code_flow(
            flow,
            dict(request.query_params),
            scopes=GRAPH_SCOPES,
        )
    except ValueError as ve:
        logger.warning("State mismatch or malformed response: %s", ve)
        raise HTTPException(status_code=400, detail="Invalid sign-in response")

    if "error" in result or "id_token_claims" not in result:
        err_reason = result.get("error_description") or result.get("error", "unknown")
        audit("auth.login_failed", decision="deny", reason=err_reason)
        raise HTTPException(status_code=401, detail=f"Sign-in failed: {err_reason}")

    claims = result["id_token_claims"]
    tid = claims.get("tid", "").lower()
    if tid not in s.tenants:
        audit("auth.login_failed", actor_oid=claims.get("oid"), decision="deny", reason="tenant")
        raise HTTPException(status_code=403, detail="Tenant not allowed")

    # Fetch user snapshot and enforce D8: no guests, no disabled accounts
    try:
        snap = build_snapshot(result["access_token"])
    except Exception as e:
        logger.critical("Identity snapshot generation failed for oid=%s: %s", claims.get("oid"), e)
        audit("auth.login_failed", actor_oid=claims.get("oid"), decision="deny", reason="graph_unavailable")
        raise HTTPException(
            status_code=503,
            detail="Identity verification service temporarily unavailable. Please try again shortly.",
        )

    if snap.get("user_type") != "Member" or not snap.get("enabled", True):
        audit("auth.login_failed", actor_oid=claims.get("oid"), decision="deny", reason="account_type")
        raise HTTPException(status_code=403, detail="This account cannot use the CoE")

    accounts = app.get_accounts()
    home_account_id = accounts[0]["home_account_id"] if accounts else claims.get("oid", "")

    user_roles = sorted(list(resolve_roles(set(snap.get("groups", [])), claims.get("oid") or "")))

    sid = create_session({
        "oid": claims.get("oid"),
        "tid": tid,
        "name": claims.get("name"),
        "upn": claims.get("preferred_username") or claims.get("upn"),
        "entra_sid": claims.get("sid"),
        "home_account_id": home_account_id,
        "token_cache": seal(cache.serialize()),
        "roles": user_roles,
        "authz": snap,
    })

    audit(
        "auth.login",
        actor_oid=claims.get("oid"),
        decision="allow",
        details={"stepup": flow.get("stepup", False)},
    )

    target = flow.get("return_to", "/")
    if not target or target == "/login":
        target = "/"
    resp = RedirectResponse(target, status_code=302)
    resp.delete_cookie(FLOW_COOKIE, path="/")
    resp.delete_cookie(FLOW_COOKIE, path="/auth")
    _set_cookie(resp, SESSION_COOKIE, sid, s.session_absolute_hours * 3600)
    return resp


from app.schemas.auth import AuthMeResponse, LogoutResponse


@router.get("/me", response_model=AuthMeResponse)
def me(ctx: AuthContext = Depends(get_auth_context)) -> dict:
    return {
        "oid": ctx.oid,
        "tid": ctx.tid,
        "name": ctx.name,
        "upn": ctx.upn,
        "roles": sorted(ctx.subject.roles),
        "language": ctx.subject.attrs.get("preferredLanguage", "en"),
        "csrf": ctx.csrf,
    }


@router.post("/logout")
def logout(ctx: AuthContext = Depends(get_auth_context)):
    s = get_settings()
    delete_session(ctx.sid)
    audit("auth.logout", actor_oid=ctx.oid, decision="allow")
    post_logout_url = quote(s.portal_origin.rstrip("/") + "/")
    entra_logout_url = f"{s.authority}/oauth2/v2.0/logout?post_logout_redirect_uri={post_logout_url}"
    resp = JSONResponse({"logout_url": entra_logout_url})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/frontchannel-logout")
def frontchannel_logout(sid: str | None = None):
    """Entra calls this (inside an iframe) when the user signs out of another app.

    Terminates the matching session on the server keyed by Entra session ID.
    """
    if sid:
        delete_by_entra_sid(sid)
    return Response(status_code=200)
