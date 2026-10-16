import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request

from app.services.authz.audit import audit
from app.services.authz.engine import Decision, Subject, evaluate
from app.services.authz.authz_repo import get_rules, resolve_roles
from app.core.config import get_settings
from app.services.auth.graph_profile import GraphError, build_snapshot
from app.services.auth.msal_client import graph_token
from app.services.auth.session import SESSION_COOKIE, delete_session, load_session, save_session

logger = logging.getLogger("coe.auth.deps")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass(frozen=True)
class AuthContext:
    sid: str
    oid: str
    tid: str
    name: str | None
    upn: str | None
    csrf: str
    authenticated_at: int
    subject: Subject


def _reauth(reason: str = "reauth") -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Sign in required",
        headers={"X-Auth-Reason": reason, "WWW-Authenticate": "Bearer"},
    )


def _refresh_authz(sid: str, sess: dict[str, Any]) -> None:
    token = graph_token(sid, sess)
    if token is None:
        delete_session(sid)
        raise _reauth()
    try:
        snap = build_snapshot(token)
    except GraphError as e:
        logger.warning("Could not refresh authz snapshot: %s", e)
        return  # keep the last snapshot; retry on the next request

    if snap.get("user_type") != "Member" or not snap.get("enabled", True):
        delete_session(sid)  # leaver or disabled account: terminate session immediately
        raise _reauth("account_disabled")

    sess["authz"] = snap
    sess["roles"] = sorted(list(resolve_roles(set(snap.get("groups", [])), sess.get("oid", ""))))
    save_session(sid, sess)


def get_auth_context(request: Request) -> AuthContext:
    s = get_settings()
    sid = request.cookies.get(SESSION_COOKIE)

    # Fallback to alternative cookie name if secure cookie flag differs in dev
    if not sid and not s.cookie_secure:
        sid = request.cookies.get("__Host-coe_session") or request.cookies.get("coe_session")

    sess = load_session(sid) if sid else None

    # Optional Bearer token compatibility for API clients / test fixtures
    if not sess:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            from app.core.security import validate_access_token as validate_token_claims
            raw_token = auth_header[7:].strip()
            try:
                claims = validate_token_claims(raw_token, s)
                roles = claims.get("roles", ["Employee"])
                clean_roles = {r.lower().replace(" ", "_") for r in roles} | {"employee"}
                subj = Subject(
                    oid=claims.get("oid", ""),
                    tid=claims.get("tid", s.tenant_id),
                    roles=frozenset(clean_roles),
                    groups=frozenset(claims.get("groups", [])),
                    attrs={"preferredLanguage": "en"},
                    report_oids=frozenset(),
                )
                return AuthContext(
                    sid="bearer-session",
                    oid=claims.get("oid", ""),
                    tid=claims.get("tid", s.tenant_id),
                    name=claims.get("name"),
                    upn=claims.get("preferred_username") or claims.get("upn"),
                    csrf="bearer-csrf-exempt",
                    authenticated_at=int(claims.get("iat", time.time())),
                    subject=subj,
                )
            except Exception as ex:
                logger.debug("Bearer token validation failed: %s", ex)
                raise _reauth()

        raise _reauth()

    now = int(time.time())
    if now - sess.get("last_seen", 0) > s.session_idle_minutes * 60:
        delete_session(sid)
        raise _reauth("idle")

    # CSRF check: state-changing methods require CSRF token and valid Origin
    if request.method not in SAFE_METHODS:
        sent_csrf = request.headers.get("x-coe-csrf", "")
        origin = request.headers.get("origin")
        expected_csrf = sess.get("csrf", "")
        if not (sent_csrf and secrets.compare_digest(sent_csrf, expected_csrf)):
            raise HTTPException(status_code=403, detail="CSRF check failed: invalid or missing token")
        if origin and origin.rstrip("/") != s.portal_origin.rstrip("/"):
            raise HTTPException(status_code=403, detail="CSRF check failed: untrusted origin")

    # Sliding idle window: throttle session updates to at most once per minute
    if now - sess.get("last_seen", 0) > 60:
        sess["last_seen"] = now
        save_session(sid, sess)

    # Periodic background authz snapshot refresh
    snap = sess.get("authz", {})
    if now - snap.get("refreshed_at", 0) > s.authz_refresh_minutes * 60:
        _refresh_authz(sid, sess)
        snap = sess.get("authz", {})

    roles = resolve_roles(set(snap.get("groups", [])), sess["oid"])
    subject = Subject(
        oid=sess["oid"],
        tid=sess.get("tid", s.tenant_id),
        roles=frozenset(roles),
        groups=frozenset(snap.get("groups", [])),
        attrs=snap.get("attrs", {}),
        report_oids=frozenset(snap.get("report_oids", [])),
    )

    return AuthContext(
        sid=sid,
        oid=sess["oid"],
        tid=sess.get("tid", s.tenant_id),
        name=sess.get("name"),
        upn=sess.get("upn"),
        csrf=sess.get("csrf", ""),
        authenticated_at=sess.get("authenticated_at", now),
        subject=subject,
    )


def require(permission: str) -> Callable[[AuthContext], AuthContext]:
    """Route dependency: evaluates policy rules with default-deny and audits decisions."""

    def dep(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        decision: Decision = evaluate(get_rules(), ctx.subject, permission)
        audit(
            event="authz.decision",
            actor_oid=ctx.oid,
            permission=permission,
            decision="allow" if decision.allow else "deny",
            reason=decision.reason,
            rule_id=decision.rule_id,
        )
        if not decision.allow:
            raise HTTPException(status_code=403, detail="Not permitted")
        return ctx

    return dep


def require_recent_auth(ctx: AuthContext, max_age_seconds: int = 300) -> None:
    """Step-up authentication: for sensitive financial/personal actions, require fresh sign-in."""
    if time.time() - ctx.authenticated_at > max_age_seconds:
        raise HTTPException(
            status_code=401,
            detail="Re-authentication required",
            headers={"X-Auth-Reason": "stepup"},
        )
