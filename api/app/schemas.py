from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field


# Ticket schemas
class TicketCreate(BaseModel):
    """Schema for creating a new ticket with validated input."""
    title: str = Field(min_length=3, max_length=200)
    body: str = Field(min_length=1, max_length=5000)


class TicketUpdate(BaseModel):
    """Schema for updating a ticket."""
    status: Optional[Literal["open", "in_progress", "resolved"]] = None
    title: Optional[str] = Field(None, min_length=3, max_length=200)
    body: Optional[str] = Field(None, min_length=1, max_length=5000)


class TicketOut(BaseModel):
    """Schema for ticket response output."""
    id: int
    title: str
    body: str
    status: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TicketListOut(BaseModel):
    """Schema for ticket list response."""
    tickets: List[TicketOut]
    total: int


# Comment schemas
class CommentCreate(BaseModel):
    """Schema for creating a comment."""
    body: str = Field(min_length=1, max_length=2000)


class CommentOut(BaseModel):
    """Schema for comment response."""
    id: int
    ticket_id: int
    author_upn: Optional[str] = None
    body: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True
