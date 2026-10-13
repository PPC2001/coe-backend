import logging
from functools import lru_cache

import httpx
import msal
from fastapi import HTTPException, status

from .config import Settings

logger = logging.getLogger("coe.graph")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


@lru_cache
def _confidential_app(client_id: str, authority: str, secret: str) -> msal.ConfidentialClientApplication:
    # One instance per process so MSAL's in-memory token cache is reused across requests.
    return msal.ConfidentialClientApplication(
        client_id=client_id, authority=authority, client_credential=secret
    )


def acquire_graph_token(user_access_token: str, settings: Settings, scopes: list[str]) -> str:
    """On-Behalf-Of exchange: the user's COE-API token -> a Graph token."""
    if not settings.api_client_secret:
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "OBO is not configured")

    cca = _confidential_app(settings.api_client_id, settings.authority, settings.api_client_secret)
    result = cca.acquire_token_on_behalf_of(user_assertion=user_access_token, scopes=scopes)

    if "access_token" in result:
        return result["access_token"]

    error = result.get("error")
    if error in {"invalid_grant", "interaction_required", "consent_required"}:
        # Consent missing, or MFA / Conditional Access claims challenge -> SPA must interact.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"error": "interaction_required", "claims": result.get("claims")},
        )
    logger.error("OBO token exchange failed: %s", error)
    raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Token exchange failed")


def graph_get(path: str, graph_token: str) -> dict:
    try:
        r = httpx.get(
            f"{GRAPH_BASE}{path}",
            headers={"Authorization": f"Bearer {graph_token}"},
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        logger.error("Graph request failed: %s", type(exc).__name__)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Microsoft Graph unavailable") from None

    if r.status_code >= 400:
        # Log upstream detail server-side; return a generic message.
        logger.error("Graph error %s on %s: %s", r.status_code, path, r.text[:200])
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY if r.status_code >= 500 else r.status_code,
            "Microsoft Graph request failed",
        )
    return r.json()
