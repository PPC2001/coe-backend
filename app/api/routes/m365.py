from datetime import datetime, timezone
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.services.auth.deps import AuthContext, require
from app.services.auth.graph_profile import GraphError, graph_get
from app.services.auth.msal_client import graph_token
from app.services.auth.session import load_session

logger = logging.getLogger("coe.api.m365")

router = APIRouter()


from app.schemas.m365 import CalendarEventsResponse, MailSummaryResponse, TeamsChatsResponse


@router.get("/mail", response_model=MailSummaryResponse)
def get_user_mail(ctx: AuthContext = Depends(require("m365:mail:read"))) -> dict[str, Any]:
    """Retrieves delegated email status and recent message headers. Content is never stored."""
    sess = load_session(ctx.sid)
    token = graph_token(ctx.sid, sess) if sess else None

    if not token:
        # Dev mock for local testing
        return {
            "unread_count": 3,
            "messages": [
                {
                    "id": "msg-001",
                    "subject": "ELAN Executive Briefing - Q4 Priorities",
                    "sender": "CEO Office <ceo@elan.qa>",
                    "received": datetime.now(timezone.utc).isoformat(),
                    "is_read": False,
                },
                {
                    "id": "msg-002",
                    "subject": "All-Hands Meeting Reminder",
                    "sender": "Internal Communications <comms@elan.qa>",
                    "received": datetime.now(timezone.utc).isoformat(),
                    "is_read": True,
                },
            ],
        }

    try:
        inbox = graph_get(token, "/me/mailFolders/inbox", {"$select": "unreadItemCount"})
        messages = graph_get(
            token,
            "/me/messages",
            {"$select": "id,subject,from,receivedDateTime,isRead", "$top": "10"},
        )
        return {
            "unread_count": inbox.get("unreadItemCount", 0),
            "messages": [
                {
                    "id": m.get("id"),
                    "subject": m.get("subject"),
                    "sender": (m.get("from") or {}).get("emailAddress", {}).get("name", "Unknown"),
                    "received": m.get("receivedDateTime"),
                    "is_read": m.get("isRead", True),
                }
                for m in messages.get("value", [])
            ],
        }
    except GraphError as e:
        logger.warning("Graph error retrieving mail: %s", e)
        raise HTTPException(status_code=e.status if e.status < 500 else 502, detail="Error contacting Exchange")


@router.get("/calendar", response_model=CalendarEventsResponse)
def get_user_calendar(ctx: AuthContext = Depends(require("m365:calendar:read"))) -> dict[str, Any]:
    """Retrieves today's calendar events as the signed-in user."""
    sess = load_session(ctx.sid)
    token = graph_token(ctx.sid, sess) if sess else None

    if not token:
        return {
            "events": [
                {
                    "id": "cal-001",
                    "subject": "CoE Platform Sprint Review",
                    "start": "2026-10-15T09:00:00Z",
                    "end": "2026-10-15T10:00:00Z",
                    "location": "Teams Meeting",
                },
                {
                    "id": "cal-002",
                    "subject": "Media Division Strategy Sync",
                    "start": "2026-10-15T13:00:00Z",
                    "end": "2026-10-15T14:00:00Z",
                    "location": "Boardroom 2, Doha",
                },
            ]
        }

    try:
        events = graph_get(
            token,
            "/me/events",
            {"$select": "id,subject,start,end,location,isAllDay", "$top": "10"},
        )
        return {
            "events": [
                {
                    "id": ev.get("id"),
                    "subject": ev.get("subject"),
                    "start": (ev.get("start") or {}).get("dateTime"),
                    "end": (ev.get("end") or {}).get("dateTime"),
                    "location": (ev.get("location") or {}).get("displayName", "Online"),
                }
                for ev in events.get("value", [])
            ]
        }
    except GraphError as e:
        logger.warning("Graph error retrieving calendar: %s", e)
        raise HTTPException(status_code=e.status if e.status < 500 else 502, detail="Error contacting Calendar")


@router.get("/teams", response_model=TeamsChatsResponse)
def get_user_teams(ctx: AuthContext = Depends(require("m365:teams:read"))) -> dict[str, Any]:
    """Retrieves recent Teams chat channels."""
    sess = load_session(ctx.sid)
    token = graph_token(ctx.sid, sess) if sess else None

    if not token:
        return {
            "chats": [
                {
                    "id": "chat-001",
                    "topic": "CoE Engineering & Architecture",
                    "chat_type": "group",
                    "last_updated": "2026-10-15T08:15:00Z",
                },
                {
                    "id": "chat-002",
                    "topic": "ELAN Qatar Townhall Q&A",
                    "chat_type": "group",
                    "last_updated": "2026-10-14T16:40:00Z",
                },
            ]
        }

    try:
        chats = graph_get(
            token,
            "/me/chats",
            {"$select": "id,topic,chatType,lastUpdatedDateTime", "$top": "10"},
        )
        return {
            "chats": [
                {
                    "id": c.get("id"),
                    "topic": c.get("topic") or "1-on-1 Chat",
                    "chat_type": c.get("chatType"),
                    "last_updated": c.get("lastUpdatedDateTime"),
                }
                for c in chats.get("value", [])
            ]
        }
    except GraphError as e:
        logger.warning("Graph error retrieving Teams chats: %s", e)
        raise HTTPException(status_code=e.status if e.status < 500 else 502, detail="Error contacting Teams")
