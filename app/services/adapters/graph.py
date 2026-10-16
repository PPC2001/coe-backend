import logging
from functools import lru_cache
from typing import Any

import httpx
import msal
from fastapi import HTTPException, status

from app.core.config import Settings

logger = logging.getLogger("coe.adapters.graph")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


_MSAL_APPS: dict[str, msal.ConfidentialClientApplication] = {}


def get_msal_app(client_id: str, authority: str, client_credential: Any) -> msal.ConfidentialClientApplication:
    """One instance per process so MSAL's in-memory token cache is reused across requests."""
    key = f"{client_id}:{authority}"
    if key not in _MSAL_APPS:
        _MSAL_APPS[key] = msal.ConfidentialClientApplication(
            client_id=client_id, authority=authority, client_credential=client_credential
        )
    return _MSAL_APPS[key]


def acquire_graph_token(
    user_access_token: str,
    settings: Settings,
    scopes: list[str] | None = None,
) -> str:
    """Acquires a delegated Microsoft Graph access token using the OAuth 2.0 On-Behalf-Of flow."""
    if not settings.api_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="OBO is not configured (API_CLIENT_SECRET is missing)",
        )

    target_scopes = scopes or settings.graph_scopes_obo
    cca = get_msal_app(settings.effective_client_id, settings.authority, settings.client_credential)
    result = cca.acquire_token_on_behalf_of(user_assertion=user_access_token, scopes=target_scopes)

    if "access_token" in result:
        return result["access_token"]

    error = result.get("error")
    # Claims challenge or consent required must trigger an interaction signal to the frontend
    if error in {"invalid_grant", "interaction_required", "consent_required"}:
        logger.warning(
            "OBO interaction required: %s (description: %s, suberror: %s)",
            error,
            result.get("error_description"),
            result.get("suberror"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "interaction_required",
                "claims": result.get("claims"),
                "description": result.get("error_description"),
            },
        )
    logger.error("OBO token exchange failed: %s (description: %s)", error, result.get("error_description"))
    raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"OBO failure: {error}")


def graph_get(path: str, graph_token: str) -> dict:
    """Makes a GET request to Microsoft Graph on behalf of the authenticated user."""
    url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
    try:
        r = httpx.get(
            url,
            headers={"Authorization": f"Bearer {graph_token}"},
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        logger.error("Graph request failed: %s", type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Microsoft Graph unavailable") from None

    if r.status_code >= 400:
        logger.error("Graph error %s on %s: %s", r.status_code, path, r.text[:200])
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY if r.status_code >= 500 else r.status_code,
            detail="Microsoft Graph request failed",
        )
    return r.json()


def list_user_sharepoint_files(graph_token: str) -> list[dict]:
    """Retrieves the user's active SharePoint and OneDrive documents via OBO delegation.

    Combines recent drive items with root children so users immediately see their active documents.
    """
    seen_ids: set[str] = set()
    documents: list[dict] = []

    def _normalize(item: dict) -> dict:
        parent = item.get("parentReference", {})
        file_info = item.get("file", {})
        return {
            "id": item["id"],
            "name": item.get("name", "Untitled"),
            "webUrl": item.get("webUrl", ""),
            "size": item.get("size", 0),
            "lastModifiedDateTime": item.get("lastModifiedDateTime", ""),
            "driveId": parent.get("driveId", ""),
            "siteId": parent.get("siteId", ""),
            "mimeType": file_info.get("mimeType", "application/octet-stream") if "file" in item else "folder",
            "isFolder": "folder" in item,
            "createdBy": item.get("createdBy", {}).get("user", {}).get("displayName", "Unknown"),
            "lastModifiedBy": item.get("lastModifiedBy", {}).get("user", {}).get("displayName", "Unknown"),
        }

    # 1. Fetch recent documents across SharePoint and OneDrive
    try:
        recent_res = graph_get("/me/drive/recent?$top=30", graph_token)
        for item in recent_res.get("value", []):
            if item.get("id") and item["id"] not in seen_ids:
                seen_ids.add(item["id"])
                documents.append(_normalize(item))
    except HTTPException as exc:
        logger.warning("Could not fetch recent drive items: %s", exc.detail)

    # 2. Fetch root drive children
    try:
        root_res = graph_get("/me/drive/root/children?$top=30", graph_token)
        for item in root_res.get("value", []):
            if item.get("id") and item["id"] not in seen_ids:
                seen_ids.add(item["id"])
                documents.append(_normalize(item))
    except HTTPException as exc:
        logger.warning("Could not fetch root drive items: %s", exc.detail)

    return documents


def get_sharepoint_item(drive_id: str, item_id: str, graph_token: str) -> dict:
    """Gets metadata for a specific SharePoint drive item."""
    path = f"/drives/{drive_id}/items/{item_id}" if drive_id else f"/me/drive/items/{item_id}"
    return graph_get(path, graph_token)


def get_sharepoint_edit_link(drive_id: str, item_id: str, graph_token: str) -> str:
    """Retrieves direct webUrl for native Microsoft 365 online viewing/editing."""
    item = get_sharepoint_item(drive_id, item_id, graph_token)
    return item.get("webUrl", "")


async def stream_sharepoint_file(drive_id: str, item_id: str, graph_token: str):
    """Streams a file directly from SharePoint using the user's delegated identity (Zero-Trust Native Delegation)."""
    url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item_id}/content" if drive_id else f"{GRAPH_BASE}/me/drive/items/{item_id}/content"
    client = httpx.AsyncClient(timeout=30.0)
    req = client.build_request("GET", url, headers={"Authorization": f"Bearer {graph_token}"})
    res = await client.send(req, stream=True)

    if res.status_code == 403:
        await res.aclose()
        await client.aclose()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied in SharePoint")
    if res.status_code >= 400:
        await res.aclose()
        await client.aclose()
        raise HTTPException(status_code=res.status_code, detail="SharePoint file fetch failed")

    return res, client

