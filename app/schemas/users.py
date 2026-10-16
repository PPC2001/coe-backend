from pydantic import BaseModel, Field


class CurrentUser(BaseModel):
    """Authenticated user context derived from Microsoft Entra ID JWT or BFF session."""
    oid: str                       # stable object id of the user in the tenant
    tid: str                       # tenant id
    sub: str                       # pairwise subject (unique per app)
    name: str | None = None
    username: str | None = None    # preferred_username (UPN / email); mutable, display only
    scopes: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    token: str = Field(repr=False)  # raw access token, needed for OBO; never serialized/logged


class UserProfileResponse(BaseModel):
    """Response contract for /api/me (token-derived identity, sensitive token excluded)."""
    oid: str
    tid: str
    sub: str
    name: str | None = None
    username: str | None = None
    scopes: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)


class AdminPingResponse(BaseModel):
    """Response contract for /api/admin/ping."""
    ok: bool = True
    oid: str
