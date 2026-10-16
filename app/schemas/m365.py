from pydantic import BaseModel, Field


class MailMessageItem(BaseModel):
    id: str
    subject: str
    sender: str
    received: str | None = None
    is_read: bool = True


class MailSummaryResponse(BaseModel):
    unread_count: int = 0
    messages: list[MailMessageItem] = Field(default_factory=list)


class CalendarEventItem(BaseModel):
    id: str
    subject: str
    start: str | None = None
    end: str | None = None
    location: str | None = None


class CalendarEventsResponse(BaseModel):
    events: list[CalendarEventItem] = Field(default_factory=list)


class TeamsChatItem(BaseModel):
    id: str
    topic: str
    chat_type: str | None = None
    last_updated: str | None = None


class TeamsChatsResponse(BaseModel):
    chats: list[TeamsChatItem] = Field(default_factory=list)
