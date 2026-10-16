import logging
import time
from typing import Any

import httpx

logger = logging.getLogger("coe.graph")

GRAPH: str = "https://graph.microsoft.com/v1.0"

ME_SELECT: str = (
    "id,displayName,userPrincipalName,mail,department,jobTitle,companyName,officeLocation,"
    "country,employeeId,employeeType,userType,preferredLanguage,accountEnabled,"
    "onPremisesExtensionAttributes"
)


class GraphError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"Graph {status}: {body[:200]}")
        self.status = status
        self.body = body


def graph_get(token: str, path: str, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    hdr = {"Authorization": f"Bearer {token}", **(headers or {})}
    url = path if path.startswith("http") else f"{GRAPH}{path}"
    for attempt in (1, 2):
        try:
            r = httpx.get(
                url,
                params=params if not path.startswith("http") else None,
                headers=hdr,
                timeout=10.0,
            )
        except Exception as exc:
            logger.warning("Graph HTTP error on attempt %d: %s", attempt, exc)
            if attempt == 2:
                raise GraphError(502, f"Network error contacting Graph: {exc}")
            continue

        if r.status_code == 429 and attempt == 1:  # honour throttling once
            retry_after = min(int(r.headers.get("Retry-After", "1")), 5)
            logger.warning("Graph 429 throttling received; sleeping %d seconds", retry_after)
            time.sleep(retry_after)
            continue

        if r.status_code >= 400:
            raise GraphError(r.status_code, r.text[:300])
        return r.json()
    raise GraphError(429, "Throttled by Microsoft Graph")


def graph_paged(token: str, path: str, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    page = graph_get(token, path, params, headers)
    items.extend(page.get("value", []))
    while "@odata.nextLink" in page:
        page = graph_get(token, page["@odata.nextLink"], headers=headers)
        items.extend(page.get("value", []))
    return items


def build_snapshot(token: str) -> dict[str, Any]:
    """Identity snapshot the policy engine needs.

    `/me/transitiveMemberOf` needs only User.Read (delegated).
    The cast to groups requires ConsistencyLevel: eventual and $count.
    """
    me = graph_get(token, "/me", {"$select": ME_SELECT})
    try:
        groups = graph_paged(
            token,
            "/me/transitiveMemberOf/microsoft.graph.group",
            {"$select": "id", "$top": "999", "$count": "true"},
            {"ConsistencyLevel": "eventual"},
        )
    except Exception as e:
        logger.warning("Could not fetch transitiveMemberOf (%s); falling back to empty groups list", e)
        groups = []

    ext = me.get("onPremisesExtensionAttributes") or {}
    return {
        "user_type": me.get("userType", "Member"),
        "enabled": me.get("accountEnabled", True),
        "groups": sorted(g["id"] for g in groups if "id" in g),
        "attrs": {
            "division": me.get("companyName"),
            "department": me.get("department"),
            "country": me.get("country"),
            "officeLocation": me.get("officeLocation"),
            "employeeId": me.get("employeeId"),
            "employeeType": me.get("employeeType"),
            "preferredLanguage": me.get("preferredLanguage") or "en",
            "costCenter": ext.get("extensionAttribute1"),
            "grade": ext.get("extensionAttribute2"),
        },
        "refreshed_at": int(time.time()),
    }
