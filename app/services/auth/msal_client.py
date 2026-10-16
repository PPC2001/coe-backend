from typing import Any
import msal

from app.core.config import get_settings
from app.services.auth.session import save_session, seal, unseal

# Delegated Graph scopes requested at login.
# For local development without tenant admin consent, User.Read is sufficient.
# Re-enable the full scopes once your tenant administrator grants admin consent.
GRAPH_SCOPES = [
    "User.Read",
]

# Full production scopes for M365 suite (requires Admin Consent in Entra ID)
FULL_M365_SCOPES = [
    "User.Read",
    "Sites.Selected",
    "Mail.Read",
    "Mail.Send",
    "Calendars.Read",
    "Chat.Read",
    "ChatMessage.Send",
]

_HTTP_CACHE: dict[str, Any] = {}  # shared metadata cache so we don't re-discover the authority per request


def build_msal(cache: msal.SerializableTokenCache | None = None) -> msal.ConfidentialClientApplication:
    """Constructs MSAL ConfidentialClientApplication with certificate or secret credentials."""
    s = get_settings()
    return msal.ConfidentialClientApplication(
        s.effective_client_id,
        authority=s.authority,
        client_credential=s.client_credential,
        token_cache=cache,
        http_cache=_HTTP_CACHE,
    )


def graph_token(sid: str, sess: dict[str, Any]) -> str | None:
    """Silent Graph token for this session's user; persists the cache if MSAL refreshed it.

    Returns None when the user must sign in again (revoked, expired, MFA required).
    """
    if not sess or "token_cache" not in sess:
        return None

    cache = msal.SerializableTokenCache()
    try:
        cache.deserialize(unseal(sess["token_cache"]))
    except Exception:
        return None

    app = build_msal(cache)
    account = next(
        (a for a in app.get_accounts() if a.get("home_account_id") == sess.get("home_account_id")),
        None,
    )
    if account is None:
        return None

    result = app.acquire_token_silent(GRAPH_SCOPES, account=account)
    if cache.has_state_changed:
        sess["token_cache"] = seal(cache.serialize())
        save_session(sid, sess)

    if result and "access_token" in result:
        return result["access_token"]
    return None
