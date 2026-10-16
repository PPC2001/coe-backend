from pydantic import BaseModel, Field


class SharePointFileItem(BaseModel):
    """Metadata item for a SharePoint / OneDrive document."""
    id: str
    name: str
    webUrl: str
    size: int | None = None
    lastModifiedDateTime: str | None = None
    driveId: str | None = None
    siteId: str | None = None
    mimeType: str | None = None
    isFolder: bool = False
    createdBy: str | None = None
    lastModifiedBy: str | None = None


class SharePointEditLinkResponse(BaseModel):
    """Web edit link for Word, Excel, or PowerPoint Online."""
    edit_link: str
