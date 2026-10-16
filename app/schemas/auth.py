from pydantic import BaseModel, Field


class AuthMeResponse(BaseModel):
    """Session-authenticated user identity details."""
    oid: str
    tid: str
    name: str | None = None
    upn: str | None = None
    roles: list[str] = Field(default_factory=list)
    language: str = "en"
    csrf: str


class LogoutResponse(BaseModel):
    """Logout redirect URL response."""
    logout_url: str
