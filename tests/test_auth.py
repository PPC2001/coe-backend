import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import security
from app.main import app

TENANT = "c472075b-7c10-4a14-8e44-3549e146c37a"
API_ID = "1e25729f-ed30-4262-8ae7-bea3abe9d376"
SPA_ID = "e5fd27da-4e01-40d0-aeaf-8a10411d9a23"

client = TestClient(app)


@pytest.fixture(scope="module")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def fake_jwks(monkeypatch, private_key):
    class _Key:
        key = private_key.public_key()

    class _Client:
        def get_signing_key_from_jwt(self, _token):
            return _Key()

    monkeypatch.setattr(security, "_jwks_client", lambda _uri: _Client())


def make_token(private_key, **overrides):
    now = int(time.time())
    claims = {
        "aud": API_ID, "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "tid": TENANT, "oid": "oid-1", "sub": "sub-1", "ver": "2.0", "azp": SPA_ID,
        "scp": "access_as_user", "name": "Test User", "preferred_username": "t@enpointe.io",
        "iat": now, "nbf": now, "exp": now + 3600,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, private_key, algorithm="RS256")


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_health_is_public():
    assert client.get("/health").status_code == 200


def test_missing_token_is_401():
    r = client.get("/api/me")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_valid_token(private_key):
    r = client.get("/api/me", headers=auth(make_token(private_key)))
    assert r.status_code == 200
    body = r.json()
    assert body["oid"] == "oid-1"
    assert "token" not in body


def test_security_headers_present(private_key):
    r = client.get("/api/me", headers=auth(make_token(private_key)))
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_wrong_audience(private_key):
    assert client.get("/api/me", headers=auth(make_token(private_key, aud="someone-else"))).status_code == 401


def test_expired(private_key):
    t = make_token(private_key, exp=int(time.time()) - 3600)
    assert client.get("/api/me", headers=auth(t)).status_code == 401


def test_wrong_tenant(private_key):
    other = "99999999-9999-9999-9999-999999999999"
    t = make_token(private_key, tid=other, iss=f"https://login.microsoftonline.com/{other}/v2.0")
    assert client.get("/api/me", headers=auth(t)).status_code == 403


def test_issuer_mismatch(private_key):
    t = make_token(private_key, iss="https://sts.windows.net/%s/" % TENANT)
    assert client.get("/api/me", headers=auth(t)).status_code == 401


def test_missing_scope(private_key):
    assert client.get("/api/me", headers=auth(make_token(private_key, scp="other"))).status_code == 403


def test_v1_token_rejected(private_key):
    assert client.get("/api/me", headers=auth(make_token(private_key, ver="1.0"))).status_code == 401


def test_unexpected_client_rejected(private_key):
    t = make_token(private_key, azp="00000000-0000-0000-0000-000000000000")
    assert client.get("/api/me", headers=auth(t)).status_code == 403


def test_missing_oid_rejected(private_key):
    assert client.get("/api/me", headers=auth(make_token(private_key, oid=None))).status_code == 401


def test_wrong_signature_rejected():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert client.get("/api/me", headers=auth(make_token(other))).status_code == 401


def test_alg_none_rejected():
    now = int(time.time())
    t = jwt.encode({"aud": API_ID, "exp": now + 60}, None, algorithm="none")
    assert client.get("/api/me", headers=auth(t)).status_code == 401


def test_garbage_token_rejected():
    assert client.get("/api/me", headers=auth("not.a.jwt")).status_code == 401


def test_role_required(private_key):
    assert client.get("/api/admin/ping", headers=auth(make_token(private_key))).status_code == 403
    t = make_token(private_key, roles=["Admin"])
    assert client.get("/api/admin/ping", headers=auth(t)).status_code == 200


def test_obo_not_configured_returns_501(private_key):
    assert client.get("/api/graph/me", headers=auth(make_token(private_key))).status_code == 501


def test_cors_preflight_allowed_origin():
    r = client.options(
        "/api/me",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET",
                 "Access-Control-Request-Headers": "authorization"},
    )
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_preflight_disallowed_origin():
    r = client.options(
        "/api/me",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in r.headers
