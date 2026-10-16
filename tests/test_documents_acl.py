import time
import pytest
from fastapi.testclient import TestClient

from app.services.auth.session import SESSION_COOKIE, create_session, delete_session
from app.services.documents.documents_repo import repo
from app.main import app

client = TestClient(app)


@pytest.fixture
def aisha_session():
    # Aisha: standard employee, member of no special role groups
    sid = create_session({
        "oid": "oid-aisha",
        "tid": "tenant-1",
        "name": "Aisha Al-Kuwari",
        "upn": "aisha@elan.qa",
        "authz": {
            "groups": ["group-entertainment-division"],
            "attrs": {"division": "Entertainment", "preferredLanguage": "ar"},
            "refreshed_at": int(time.time()),
        },
    })
    yield sid
    delete_session(sid)


@pytest.fixture
def sara_session():
    # Sara: member of HR group
    sid = create_session({
        "oid": "oid-sara",
        "tid": "tenant-1",
        "name": "Sara Al-Thani",
        "upn": "sara@elan.qa",
        "authz": {
            "groups": ["group-hr-analytics"],
            "attrs": {"department": "HR", "preferredLanguage": "en"},
            "refreshed_at": int(time.time()),
        },
    })
    yield sid
    delete_session(sid)


def test_aisha_searches_curated_libraries(aisha_session):
    client.cookies.set(SESSION_COOKIE, aisha_session)
    res = client.get("/api/documents/search?q=")
    assert res.status_code == 200
    data = res.json()
    titles = [d["title"] for d in data["results"]]

    # Aisha should see Code of Conduct (ALL_EMPLOYEES)
    assert any("Code of Conduct" in t for t in titles)
    # Aisha must NOT see HR confidential compensation documents
    assert not any("Executive Compensation" in t for t in titles)


def test_sara_searches_curated_libraries(sara_session):
    client.cookies.set(SESSION_COOKIE, sara_session)
    res = client.get("/api/documents/search?q=")
    assert res.status_code == 200
    data = res.json()
    titles = [d["title"] for d in data["results"]]

    # Sara sees both Code of Conduct (ALL_EMPLOYEES) and HR Compensation (group-hr-analytics)
    assert any("Code of Conduct" in t for t in titles)
    assert any("Executive Compensation" in t for t in titles)


def test_aisha_unauthorized_document_returns_404(aisha_session):
    client.cookies.set(SESSION_COOKIE, aisha_session)
    # doc-hr-salaries is in lib-hr-confidential-002 which Aisha has no access to
    res = client.get("/api/documents/doc-hr-salaries/content")
    # Per spec §7.5: 404, not 403, so existence is not revealed
    assert res.status_code == 404


def test_aisha_authorized_document_live_open(aisha_session):
    client.cookies.set(SESSION_COOKIE, aisha_session)
    res = client.get("/api/documents/doc-policy-2026/content")
    assert res.status_code == 200
    assert res.headers["cache-control"] == "private, no-store"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert "inline" in res.headers["content-disposition"]
