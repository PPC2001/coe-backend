from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from tests.conftest import auth_header, make_test_token

client = TestClient(app)


def test_sharepoint_files_unauthorized():
    res = client.get("/api/sharepoint/files")
    assert res.status_code == 401


def test_sharepoint_files_obo_not_configured(session_private_key):
    token = make_test_token(session_private_key, oid="user-sp-1")
    res = client.get("/api/sharepoint/files", headers=auth_header(token))
    # In tests, API_CLIENT_SECRET is empty by default, so it returns 501
    assert res.status_code == 501
    assert "OBO is not configured" in res.json()["detail"]


@patch("app.api.routes.sharepoint.acquire_graph_token")
@patch("app.api.routes.sharepoint.list_user_sharepoint_files")
def test_sharepoint_files_success(mock_list_files, mock_acquire_token, session_private_key):
    mock_acquire_token.return_value = "mock-graph-token-123"
    mock_list_files.return_value = [
        {
            "id": "file-101",
            "name": "Project_Proposal.docx",
            "webUrl": "https://tenant.sharepoint.com/:w:/r/sites/Project_Proposal.docx",
            "size": 1048576,
            "lastModifiedDateTime": "2026-10-14T10:00:00Z",
            "driveId": "drive-abc",
            "siteId": "site-xyz",
            "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "isFolder": False,
            "createdBy": "Pratik Chavan",
            "lastModifiedBy": "Pratik Chavan",
        }
    ]

    token = make_test_token(session_private_key, oid="user-sp-1")
    res = client.get("/api/sharepoint/files", headers=auth_header(token))
    assert res.status_code == 200
    files = res.json()
    assert len(files) == 1
    assert files[0]["id"] == "file-101"
    assert files[0]["name"] == "Project_Proposal.docx"


@patch("app.api.routes.sharepoint.acquire_graph_token")
@patch("app.api.routes.sharepoint.get_sharepoint_edit_link")
def test_sharepoint_edit_link(mock_get_link, mock_acquire_token, session_private_key):
    mock_acquire_token.return_value = "mock-graph-token-123"
    mock_get_link.return_value = "https://tenant.sharepoint.com/:w:/r/sites/Project_Proposal.docx?web=1"

    token = make_test_token(session_private_key, oid="user-sp-1")
    res = client.get("/api/sharepoint/files/file-101/edit-link", headers=auth_header(token))
    assert res.status_code == 200
    assert res.json()["edit_link"] == "https://tenant.sharepoint.com/:w:/r/sites/Project_Proposal.docx?web=1"


def test_acquire_graph_token_uses_client_credential():
    from app.services.adapters.graph import acquire_graph_token
    from app.core.config import Settings
    from unittest.mock import MagicMock

    cfg = Settings(
        tenant_id="c472075b-7c10-4a14-8e44-3549e146c37a",
        client_id="1e25729f-ed30-4262-8ae7-bea3abe9d376",
        api_client_secret="test-secret-123456",
        ENVIRONMENT_NAME="DEV",
    )
    with patch("app.services.adapters.graph.get_msal_app") as mock_get_app:
        mock_cca = MagicMock()
        mock_cca.acquire_token_on_behalf_of.return_value = {"access_token": "obo-token-abc"}
        mock_get_app.return_value = mock_cca

        token = acquire_graph_token("user-jwt-assertion", cfg)
        assert token == "obo-token-abc"
        # Verify get_msal_app was invoked with client_credential and didn't crash with NameError
        mock_get_app.assert_called_once_with(
            cfg.effective_client_id,
            cfg.authority,
            cfg.client_credential,
        )
