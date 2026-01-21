from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .db import Base


class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    body = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="open")  # open/in_progress/resolved
    owner_sub = Column(String(128), nullable=False, index=True)  # token 'sub'
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    comments = relationship("Comment", back_populates="ticket", lazy="dynamic")


class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(Integer, ForeignKey("tickets.id"), nullable=False, index=True)
    author_sub = Column(String(128), nullable=False)
    author_upn = Column(String(256), nullable=True)
    body = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    ticket = relationship("Ticket", back_populates="comments")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime(timezone=True), server_default=func.now())
    actor_sub = Column(String(128), nullable=True, index=True)
    actor_upn = Column(String(256), nullable=True)
    ip = Column(String(64), nullable=True)
    action = Column(String(64), nullable=False)
    target = Column(String(256), nullable=True)
    result = Column(String(16), nullable=False)  # success/fail
    reason = Column(String(256), nullable=True)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime(timezone=True), server_default=func.now())
    rule_id = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)  # low/med/high
    context = Column(Text, nullable=False)  # JSON string
    triage_status = Column(String(16), nullable=False, default="new")
    trigger_event_id = Column(Integer, nullable=True)  # ID of audit event that triggered this
    ticket_id = Column(Integer, nullable=True)  # ID of incident ticket created from this alert
