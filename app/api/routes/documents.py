import io
import logging
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from app.services.auth.deps import AuthContext, require
from app.services.auth.graph_profile import GRAPH
from app.services.auth.msal_client import graph_token
from app.services.auth.session import load_session
from app.services.authz.audit import audit
from app.services.documents.documents_repo import repo

logger = logging.getLogger("coe.api.documents")

router = APIRouter()


def principals(ctx: AuthContext) -> list[str]:
    """Builds the security principal list for the caller."""
    return [ctx.oid, *ctx.subject.groups, "ALL_EMPLOYEES"]


from app.schemas.documents import DocumentSearchResponse


@router.get("/search", response_model=DocumentSearchResponse)
def search_documents(
    q: str = Query(default="", description="Search query string"),
    ctx: AuthContext = Depends(require("documents:search")),
) -> dict:
    """ACL-trimmed document search across curated libraries."""
    user_principals = principals(ctx)
    results = repo.search_documents(q, user_principals)
    return {"results": results, "count": len(results)}


@router.get("/{document_id}/content")
async def open_document(
    document_id: str,
    ctx: AuthContext = Depends(require("documents:open")),
):
    """Opens a document with a live SharePoint permission check as the signed-in user."""
    doc = repo.get_document(document_id)

    # 1) Cheap local check against the synced ACL.
    # Return 404, not 403, so document existence is not revealed to unauthorized callers.
    if doc is None or not repo.can_read(doc, principals(ctx)):
        audit(
            event="documents.open",
            actor_oid=ctx.oid,
            resource_type="document",
            resource_id=document_id,
            decision="deny",
            reason="acl",
        )
        raise HTTPException(status_code=404, detail="Document not found")

    # 2) Authoritative check: ask SharePoint live as the user.
    sess = load_session(ctx.sid)
    token = graph_token(ctx.sid, sess) if sess else None

    # Handle mock / local dev mode when drive_id starts with "drive-dev"
    if not token and doc.drive_id.startswith("drive-dev"):
        content_bytes = f"# {doc.title}\n\n[Dev Mock Content for verified user {ctx.name or ctx.oid}]\n".encode("utf-8")
        audit(
            event="documents.open",
            actor_oid=ctx.oid,
            resource_type="document",
            resource_id=document_id,
            decision="allow",
            details={"mock": True},
        )
        return StreamingResponse(
            io.BytesIO(content_bytes),
            media_type=doc.mime or "text/plain",
            headers={
                "Content-Disposition": f"inline; filename*=UTF-8''{quote(doc.title or 'document')}",
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    if token is None:
        raise HTTPException(status_code=401, detail="Sign-in required", headers={"X-Auth-Reason": "reauth"})

    url = f"{GRAPH}/drives/{doc.drive_id}/items/{doc.item_id}/content"
    client = httpx.AsyncClient(follow_redirects=True, timeout=30.0)
    try:
        req = client.build_request("GET", url, headers={"Authorization": f"Bearer {token}"})
        resp = await client.send(req, stream=True)
    except Exception as exc:
        await client.aclose()
        logger.error("Failed to connect to SharePoint for document %s: %s", document_id, exc)
        raise HTTPException(status_code=502, detail="SharePoint service unavailable")

    if resp.status_code in (401, 403, 404):
        await resp.aclose()
        await client.aclose()
        repo.flag_acl_drift(doc.id)
        audit(
            event="documents.open",
            actor_oid=ctx.oid,
            resource_type="document",
            resource_id=document_id,
            decision="deny",
            reason="sharepoint",
        )
        raise HTTPException(status_code=404, detail="Document not found")

    if resp.status_code >= 400:
        await resp.aclose()
        await client.aclose()
        raise HTTPException(status_code=502, detail="SharePoint unavailable")

    audit(
        event="documents.open",
        actor_oid=ctx.oid,
        resource_type="document",
        resource_id=document_id,
        decision="allow",
    )

    async def _stream_bytes():
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()
            await client.aclose()

    return StreamingResponse(
        _stream_bytes(),
        media_type=doc.mime or "application/octet-stream",
        headers={
            "Content-Disposition": f"inline; filename*=UTF-8''{quote(doc.title or 'document')}",
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
