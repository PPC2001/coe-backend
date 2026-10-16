"""Tests for User Profile & Admin Role Verification.

Verifies:
- /api/me returns token-derived Entra ID claims (excluding raw bearer token).
- /api/admin/ping checks the caller's Entra App role 'Admin'.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import auth_header, make_test_token

client = TestClient(app)


def test_me_unauthorized():
    """/api/me requires valid Entra ID token."""
    res = client.get("/api/me")
    assert res.status_code == 401


def test_me_authenticated(session_private_key):
    """/api/me returns authenticated user identity."""
    token = make_test_token(session_private_key, oid="user-entra-123", roles=["User"])
    res = client.get("/api/me", headers=auth_header(token))
    assert res.status_code == 200
    data = res.json()
    assert data["oid"] == "user-entra-123"
    assert "token" not in data


def test_admin_ping_allowed(session_private_key):
    """/api/admin/ping succeeds for Admin role."""
    token = make_test_token(session_private_key, oid="admin-1", roles=["Admin"])
    res = client.get("/api/admin/ping", headers=auth_header(token))
    assert res.status_code == 200
    assert res.json()["ok"] is True


def test_admin_ping_forbidden_for_regular_user(session_private_key):
    """/api/admin/ping rejects non-admins with 403."""
    token = make_test_token(session_private_key, oid="user-1", roles=["User"])
    res = client.get("/api/admin/ping", headers=auth_header(token))
    assert res.status_code == 403
