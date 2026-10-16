import sqlite3
import time
import pytest
from fastapi.testclient import TestClient

from app.services.auth.session import SESSION_COOKIE, create_session, delete_session
from app.core.config import get_settings
from app.main import app

client = TestClient(app)


@pytest.fixture
def user_session():
    import uuid
    sid = create_session({
        "oid": f"user-anon-test-{uuid.uuid4().hex[:8]}",
        "tid": "tenant-1",
        "name": "Anon Tester",
        "authz": {"groups": [], "attrs": {}, "refreshed_at": int(time.time())},
    })
    yield sid
    delete_session(sid)


def test_anonymous_suggestion_requires_auth():
    # Unauthenticated request fails
    res = client.post("/api/suggestions", json={"category": "HR", "text": "Improve cafeteria coffee"})
    assert res.status_code == 401


def test_anonymous_suggestion_stores_unattributed_record(user_session):
    client.cookies.set(SESSION_COOKIE, user_session)
    s = get_settings()
    from app.services.auth.session import load_session
    sess = load_session(user_session)
    csrf_token = sess["csrf"]
    res = client.post(
        "/api/suggestions",
        json={"category": "Facilities", "text": "Add more ergonomic desk chairs on 4th floor"},
        headers={"X-CoE-CSRF": csrf_token, "Origin": s.portal_origin},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "received"

    # Verify directly from database that NO user identity or IP was stored
    s = get_settings()
    conn = sqlite3.connect(s.identity_db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM anonymous_suggestions WHERE category = 'Facilities'")
        row = cur.fetchone()
        assert row is not None
        assert row["suggestion_text"] == "Add more ergonomic desk chairs on 4th floor"
        # Table schema has only id, submission_date, category, suggestion_text
        cols = [col[0] for col in cur.description]
        assert "user_id" not in cols
        assert "oid" not in cols
        assert "actor_oid" not in cols
        assert "ip" not in cols
    finally:
        conn.close()
