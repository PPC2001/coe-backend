import re
from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_TENANT_ALIASES = {"common", "organizations", "consumers"}


def _is_guid(value: str) -> bool:
    return bool(_GUID.match(value))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["development", "production"] = "production"

    tenant_id: str                       # GUID, or common / organizations / consumers
    api_client_id: str
    spa_client_id: str | None = None     # when set, the token's `azp` must match it
    api_client_secret: str | None = None
    required_scope: str = "access_as_user"
    cors_origins: str = "http://localhost:5173"
    allowed_tenant_ids: str = ""

    trusted_proxy_count: int = 0         # trusted reverse proxies in front of the app
    rate_limit_per_minute: int = 120

    @field_validator("tenant_id")
    @classmethod
    def _validate_tenant(cls, v: str) -> str:
        v = v.strip()
        if not (_is_guid(v) or v.lower() in _TENANT_ALIASES):
            raise ValueError("TENANT_ID must be a GUID or one of common/organizations/consumers")
        return v

    @field_validator("api_client_id", "spa_client_id")
    @classmethod
    def _validate_client_id(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        v = v.strip()
        if not _is_guid(v):
            raise ValueError("client ids must be GUIDs")
        return v

    @field_validator("api_client_secret")
    @classmethod
    def _empty_secret_is_none(cls, v: str | None) -> str | None:
        return v or None

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard_cors(cls, v: str) -> str:
        if "*" in v:
            raise ValueError("Wildcard CORS origins are not allowed")
        return v

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def jwks_uri(self) -> str:
        return f"{self.authority}/discovery/v2.0/keys"

    @property
    def audiences(self) -> list[str]:
        # v2 tokens carry the client-id GUID in `aud`; accept the api:// form too for safety.
        return [self.api_client_id, f"api://{self.api_client_id}"]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_tenants(self) -> set[str]:
        explicit = {t.strip().lower() for t in self.allowed_tenant_ids.split(",") if t.strip()}
        if explicit:
            return explicit
        if _is_guid(self.tenant_id):
            return {self.tenant_id.lower()}   # single tenant: only our tenant
        # TODO(security): multi-tenant deployments MUST set ALLOWED_TENANT_IDS; fail closed.
        return set()


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment
