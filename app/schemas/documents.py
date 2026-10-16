from typing import Any
from pydantic import BaseModel, Field


class DocumentItem(BaseModel):
    """Document record representation in search results."""
    id: str
    title: str
    library_id: str
    drive_id: str
    item_id: str
    mime: str
    path: str | None = None


class DocumentSearchResponse(BaseModel):
    """ACL-trimmed document search response contract."""
    results: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0
