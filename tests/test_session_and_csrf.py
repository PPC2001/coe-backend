import time
import pytest
from fastapi.testclient import TestClient

from app.services.auth import session
from app.services.auth.session import (
    SESSION_COOKIE,
    create_session,
    delete_all_for_user,
    delete_session,
    load_session,
    save_session,
)
from app.core.config import get_settings
from app.main import app

client = TestClient(app)


def test_session_lifecycle():
    oid = "user-test-lifecycle-1"
    sid = create_session({
        "oid": oid,
        "tid": "tenant-1",
        "name": "Lifecycle Tester",
        "upn": "test@elan.qa",
        "authz": {
            "groups": [],
            "attrs": {"preferredLanguage": "en"},
            "refreshed_at": int(time.time()),
        },
    })

    sess = load_session(sid)
    assert sess is not None
    assert sess["oid"] == oid
    assert "csrf" in sess
    assert len(sess["csrf"]) > 16

    # Test save session
    sess["last_seen"] = int(time.time()) + 10
    save_session(sid, sess)
    reloaded = load_session(sid)
    assert reloaded["last_seen"] == sess["last_seen"]

    # Test delete session
    delete_session(sid)
    assert load_session(sid) is None


def test_session_cap_enforcement():
    s = get_settings()
    oid = "user-cap-test-1"
    sids = []
    for i in range(s.max_sessions_per_user + 2):
        sid = create_session({
            "oid": oid,
            "tid": "tenant-1",
            "name": f"User Cap {i}",
            "created": int(time.time()) + i,
            "authz": {"groups": [], "attrs": {}, "refreshed_at": int(time.time())},
        })
        sids.append(sid)

    # Oldest 2 sessions must have been evicted
    assert load_session(sids[0]) is None
    assert load_session(sids[1]) is None
    # Latest sessions must still exist
    for sid in sids[2:]:
        assert load_session(sid) is not None

    delete_all_for_user(oid)


def test_admin_kill_switch():
    oid = "user-kill-switch-1"
    sids = [
        create_session({"oid": oid, "tid": "t1", "authz": {"groups": [], "attrs": {}, "refreshed_at": int(time.time())}})
        for _ in range(3)
    ]

    for sid in sids:
        assert load_session(sid) is not None

    delete_all_for_user(oid)

    for sid in sids:
        assert load_session(sid) is None


def test_csrf_protection_on_state_changing_methods():
    sid = create_session({
        "oid": "user-csrf-1",
        "tid": "t1",
        "name": "CSRF Tester",
        "authz": {"groups": [], "attrs": {"preferredLanguage": "en"}, "refreshed_at": int(time.time())},
    })
    sess = load_session(sid)
    csrf_token = sess["csrf"]

    cookies = {SESSION_COOKIE: sid}

    # Safe method (GET) requires no CSRF token
    r_get = client.get("/api/auth/me", cookies=cookies)
    assert r_get.status_code == 200

    # Unsafe method (POST) without CSRF header fails with 403
    r_post_fail = client.post("/api/auth/logout", cookies=cookies)
    assert r_post_fail.status_code == 403
    assert "CSRF" in r_post_fail.text

    # Unsafe method with invalid Origin fails with 403
    r_post_bad_origin = client.post(
        "/api/auth/logout",
        cookies=cookies,
        headers={"X-CoE-CSRF": csrf_token, "Origin": "http://evil-attacker.com"},
    )
    assert r_post_bad_origin.status_code == 403

    # Unsafe method with valid CSRF token and trusted Origin succeeds
    s = get_settings()
    r_post_ok = client.post(
        "/api/auth/logout",
        cookies=cookies,
        headers={"X-CoE-CSRF": csrf_token, "Origin": s.portal_origin},
    )
    assert r_post_ok.status_code == 200
    assert "logout_url" in r_post_ok.json()
