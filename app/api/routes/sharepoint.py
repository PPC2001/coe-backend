import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from app.core.config import Settings, get_settings
from app.core.security import CurrentUser, get_current_user
from app.schemas.sharepoint import SharePointEditLinkResponse, SharePointFileItem
from app.services.adapters.graph import (
    acquire_graph_token,
    get_sharepoint_edit_link,
    get_sharepoint_item,
    graph_get,
    list_user_sharepoint_files,
    stream_sharepoint_file,
)

logger = logging.getLogger("coe.api.sharepoint")

router = APIRouter()


@router.get("/graph/me")
def graph_me(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    cfg: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Calls Microsoft Graph as the signed-in user via OBO."""
    graph_token = acquire_graph_token(user.token, cfg, ["https://graph.microsoft.com/User.Read"])
    return graph_get("/me", graph_token)


@router.get("/sharepoint/files", response_model=list[SharePointFileItem])
def get_my_sharepoint_files(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    cfg: Annotated[Settings, Depends(get_settings)],
) -> list[dict]:
    """Retrieves real SharePoint and OneDrive files for the signed-in user via OBO delegation."""
    graph_token = acquire_graph_token(user.token, cfg)
    return list_user_sharepoint_files(graph_token)


@router.get("/sharepoint/files/{item_id}")
def get_file_metadata(
    item_id: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    cfg: Annotated[Settings, Depends(get_settings)],
    drive_id: str = "",
) -> dict:
    """Gets metadata for a specific SharePoint drive item via OBO delegation."""
    graph_token = acquire_graph_token(user.token, cfg)
    return get_sharepoint_item(drive_id, item_id, graph_token)


@router.get("/sharepoint/files/{item_id}/stream")
async def stream_file(
    item_id: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    cfg: Annotated[Settings, Depends(get_settings)],
    drive_id: str = "",
):
    """Streams a SharePoint document directly on behalf of the user (Zero-Trust Native Delegation)."""
    graph_token = acquire_graph_token(user.token, cfg)
    res, client = await stream_sharepoint_file(drive_id, item_id, graph_token)

    async def _iter():
        try:
            async for chunk in res.aiter_bytes():
                yield chunk
        finally:
            await res.aclose()
            await client.aclose()

    headers = {
        "Content-Disposition": res.headers.get("Content-Disposition", f'inline; filename="{item_id}"'),
        "Content-Type": res.headers.get("Content-Type", "application/octet-stream"),
    }
    return StreamingResponse(_iter(), headers=headers)


@router.get("/sharepoint/files/{item_id}/edit-link", response_model=SharePointEditLinkResponse)
def get_file_edit_link(
    item_id: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    cfg: Annotated[Settings, Depends(get_settings)],
    drive_id: str = "",
) -> SharePointEditLinkResponse:
    """Returns the webUrl to open and edit the document in Word, Excel, or PowerPoint Online."""
    graph_token = acquire_graph_token(user.token, cfg)
    link = get_sharepoint_edit_link(drive_id, item_id, graph_token)
    return SharePointEditLinkResponse(edit_link=link)
