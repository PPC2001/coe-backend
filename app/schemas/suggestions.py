from pydantic import BaseModel, Field


class SuggestionRequest(BaseModel):
    """Payload to submit an unattributed employee suggestion."""
    category: str = Field(min_length=2, max_length=50, description="Department or topic category")
    text: str = Field(min_length=5, max_length=2000, description="Suggestion content")


class SuggestionReceivedResponse(BaseModel):
    """Acknowledgement of anonymous suggestion receipt."""
    status: str = "received"
    date: str
