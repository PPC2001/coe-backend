from datetime import date
import hashlib
import hmac
import logging
import secrets
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.services.auth.deps import AuthContext, get_auth_context
from app.services.auth.session import _r
from app.core.config import get_settings

logger = logging.getLogger("coe.api.suggestions")

router = APIRouter()


def _get_daily_salt() -> bytes:
    today_str = date.today().isoformat()
    redis_key = f"coe:suggestion_salt:{today_str}"
    try:
        salt = _r.get(redis_key)
        if not salt:
            new_salt = secrets.token_hex(32)
            _r.set(redis_key, new_salt, ex=90000)
            return new_salt.encode()
        return salt.encode() if isinstance(salt, str) else salt
    except Exception:
        # Fallback if Redis is temporarily unavailable
        return hashlib.sha256(f"coe_salt_{today_str}".encode()).digest()


from app.schemas.suggestions import SuggestionReceivedResponse, SuggestionRequest


@router.post("", response_model=SuggestionReceivedResponse)
def submit_suggestion(
    payload: SuggestionRequest,
    ctx: AuthContext = Depends(get_auth_context),
) -> SuggestionReceivedResponse:
    """Submits an authenticated yet completely unattributed employee suggestion.

    Identity (OID, IP, user-agent) is deliberately stripped before database insertion.
    Spam protection is enforced via one-way daily HMAC with rotating salt.
    """
    salt = _get_daily_salt()
    rate_hash = hmac.new(salt, ctx.oid.encode(), hashlib.sha256).hexdigest()
    redis_key = f"spam_protect:suggestion:{rate_hash}"

    # Rate limit: max 5 suggestions per user per day
    curr_count = _r.get(redis_key)
    if curr_count and int(curr_count) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Daily anonymous suggestion limit reached. Please try again tomorrow.",
        )

    # Persist completely unattributed row: date, category, text only.
    s = get_settings()
    try:
        conn = sqlite3.connect(s.identity_db_path, check_same_thread=False)
        with conn:
            conn.execute(
                """
                INSERT INTO anonymous_suggestions (submission_date, category, suggestion_text)
                VALUES (?, ?, ?)
                """,
                (date.today().isoformat(), payload.category.strip(), payload.text.strip()),
            )
        conn.close()
    except Exception as e:
        logger.error("Failed to store suggestion: %s", e)
        raise HTTPException(status_code=500, detail="Could not record suggestion")

    pipe = _r.pipeline()
    if curr_count is None:
        pipe.set(redis_key, "1", ex=86400)
    else:
        pipe.set(redis_key, str(int(curr_count) + 1), ex=86400)
    pipe.execute()

    return {"status": "received", "date": date.today().isoformat()}
