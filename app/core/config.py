import logging
import os
import re
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("coe.config")


class ENVIRONMENT_NAME(str, Enum):
    DEV = "DEV"
    QA = "QA"
    PROD = "PROD"


_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_TENANT_ALIASES = {"common", "organizations", "consumers"}
_DEV_FERNET_KEY = Fernet.generate_key().decode()

# Ephemeral RSA fallback for dev/testing when key files are absent
_dev_rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_DEV_RSA_PRIVATE_PEM = _dev_rsa_priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()


def _is_guid(value: str) -> bool:
    return bool(_GUID.match(value))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment_name: ENVIRONMENT_NAME = Field(
        default=None,
        validation_alias=AliasChoices("ENVIRONMENT_NAME", "environment_name"),
    )
    organization_name: str = "End Point IT Services Pvt Ltd"

    # Microsoft Entra single-app configuration
    tenant_id: str
    client_id: str = "1e25729f-ed30-4262-8ae7-bea3abe9d376"
    api_client_id: str | None = None
    spa_client_id: str | None = None
    client_cert_thumbprint: str = ""
    client_cert_private_key_path: str | None = None
    client_cert_private_key: str | None = None
    api_client_secret: str | None = None
    client_secret: str | None = None
    allowed_tenant_ids: str = ""

    # Origin & network
    portal_origin: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173"
    trusted_proxy_count: int = 0
    rate_limit_per_minute: int = 1000

    # Sessions
    redis_url: str = "redis://localhost:6379/0"
    session_enc_key: str = ""
    cookie_secure: bool = False
    session_idle_minutes: int = 30
    session_absolute_hours: int = 10
    authz_refresh_minutes: int = 10
    max_sessions_per_user: int = 5

    # Databases & persistence
    identity_db_path: str = "identity_store.db"
    required_scope: str = "access_as_user"

    # Delegated Microsoft Graph scopes
    graph_scopes_obo: list[str] = [
        "https://graph.microsoft.com/User.Read",
        "https://graph.microsoft.com/Files.Read",
        "https://graph.microsoft.com/Files.ReadWrite",
    ]

    @field_validator("environment_name", mode="before")
    @classmethod
    def validate_env_name(cls, v: Any) -> ENVIRONMENT_NAME:
        if not v:
            v = os.getenv("ENVIRONMENT_NAME") or os.getenv("environment_name")
        if not v:
            raise ValueError("ENVIRONMENT_NAME is not found. Must be one of: DEV, QA, PROD")
        if isinstance(v, ENVIRONMENT_NAME):
            return v
        if isinstance(v, str):
            clean = v.strip().upper()
            if clean in ENVIRONMENT_NAME.__members__:
                return ENVIRONMENT_NAME[clean]
            raise ValueError(f"ENVIRONMENT_NAME '{clean}' is invalid. Must be one of: DEV, QA, PROD")
        raise ValueError("ENVIRONMENT_NAME is not found. Must be one of: DEV, QA, PROD")

    @property
    def is_dev(self) -> bool:
        return self.environment_name == ENVIRONMENT_NAME.DEV

    @property
    def is_qa(self) -> bool:
        return self.environment_name == ENVIRONMENT_NAME.QA

    @property
    def is_prod(self) -> bool:
        return self.environment_name == ENVIRONMENT_NAME.PROD

    @field_validator("tenant_id")
    @classmethod
    def _validate_tenant(cls, v: str) -> str:
        v = v.strip()
        if not (_is_guid(v) or v.lower() in _TENANT_ALIASES):
            raise ValueError("TENANT_ID must be a GUID or one of common/organizations/consumers")
        return v

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard_cors(cls, v: str) -> str:
        if "*" in v:
            raise ValueError("Wildcard CORS origins are not allowed")
        return v

    @property
    def effective_client_id(self) -> str:
        return self.client_id or self.api_client_id or "1e25729f-ed30-4262-8ae7-bea3abe9d376"

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def redirect_uri(self) -> str:
        return f"{self.portal_origin}/api/auth/callback"

    @property
    def jwks_uri(self) -> str:
        return f"{self.authority}/discovery/v2.0/keys"

    @property
    def audiences(self) -> list[str]:
        cid = self.effective_client_id
        return [cid, f"api://{cid}"]

    @property
    def cors_origin_list(self) -> list[str]:
        origins = self.cors_origins or self.portal_origin
        return [o.strip() for o in origins.split(",") if o.strip()]

    @property
    def allowed_tenants(self) -> set[str]:
        return self.tenants

    @property
    def tenants(self) -> set[str]:
        explicit = {t.strip().lower() for t in self.allowed_tenant_ids.split(",") if t.strip()}
        if explicit:
            return explicit
        return {self.tenant_id.lower()} if _is_guid(self.tenant_id) else set()

    @property
    def client_credential(self) -> dict[str, str] | str:
        """Certificate credential. Fallback to client secret if certificate not configured."""
        if self.client_cert_private_key:
            pk = self.client_cert_private_key.strip().replace("\\n", "\n")
            return {"private_key": pk, "thumbprint": self.client_cert_thumbprint}
        if self.client_cert_private_key_path:
            p = Path(self.client_cert_private_key_path)
            if p.exists():
                return {"private_key": p.read_text(), "thumbprint": self.client_cert_thumbprint}
        # Fallback for dev/existing secrets
        sec = self.client_secret or self.api_client_secret
        if sec:
            return sec
        if self.is_dev:
            return {"private_key": _DEV_RSA_PRIVATE_PEM, "thumbprint": "DEV_EPHEMERAL_CERT"}
        raise RuntimeError("Set CLIENT_CERT_PRIVATE_KEY or CLIENT_CERT_PRIVATE_KEY_PATH (or CLIENT_SECRET)")

    @property
    def fernet_key(self) -> str:
        if self.session_enc_key and len(self.session_enc_key.strip()) >= 32:
            return self.session_enc_key.strip()
        if self.is_dev:
            logger.warning("Using ephemeral Fernet session encryption key for development")
            return _DEV_FERNET_KEY
        raise RuntimeError("SESSION_ENC_KEY must be set in production")


@lru_cache
def get_settings() -> Settings:
    return Settings()
