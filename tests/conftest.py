import os
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

os.environ["TENANT_ID"] = "c472075b-7c10-4a14-8e44-3549e146c37a"
os.environ["CLIENT_ID"] = "1e25729f-ed30-4262-8ae7-bea3abe9d376"
os.environ["API_CLIENT_ID"] = "1e25729f-ed30-4262-8ae7-bea3abe9d376"
os.environ["SPA_CLIENT_ID"] = "e5fd27da-4e01-40d0-aeaf-8a10411d9a23"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"
os.environ["ENVIRONMENT_NAME"] = "DEV"
os.environ["API_CLIENT_SECRET"] = ""
os.environ["ALLOWED_TENANT_IDS"] = ""
os.environ["RATE_LIMIT_PER_MINUTE"] = "1000"

from app.core import security
from app.main import app

TENANT = "c472075b-7c10-4a14-8e44-3549e146c37a"
API_ID = "1e25729f-ed30-4262-8ae7-bea3abe9d376"
SPA_ID = "e5fd27da-4e01-40d0-aeaf-8a10411d9a23"


@pytest.fixture(scope="session")
def session_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def fake_jwks(monkeypatch, session_private_key):
    class _Key:
        key = session_private_key.public_key()

    class _Client:
        def get_signing_key_from_jwt(self, _token):
            return _Key()

    monkeypatch.setattr(security, "_jwks_client", lambda _uri: _Client())


def make_test_token(private_key, **overrides) -> str:
    now = int(time.time())
    claims = {
        "aud": API_ID,
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "tid": TENANT,
        "oid": "oid-1",
        "sub": "sub-1",
        "ver": "2.0",
        "azp": SPA_ID,
        "scp": "access_as_user",
        "name": "Test User",
        "preferred_username": "t@enpointe.io",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, private_key, algorithm="RS256")


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

