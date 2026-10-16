from pydantic import BaseModel, Field


class EntitlementsResponse(BaseModel):
    """Effective enterprise permissions and assigned roles for caller."""
    permissions: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    oid: str
