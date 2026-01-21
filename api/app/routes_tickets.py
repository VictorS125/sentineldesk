from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional

from .db import get_db
from .auth import verify_bearer_token
from .rbac import require_perm, roles_from_claims
from .models import Ticket, Comment, AuditEvent
from .schemas import TicketCreate, TicketUpdate, TicketOut, TicketListOut, CommentCreate, CommentOut
from .audit import write_audit
from .detections import run_detections_for_event

router = APIRouter(prefix="/tickets", tags=["tickets"])


def actor_from_claims(claims: dict):
    """Extract actor identifiers from JWT claims."""
    sub = claims.get("sub")
    upn = claims.get("preferred_username") or claims.get("upn") or claims.get("email")
    return sub, upn


def client_ip(request: Request) -> str | None:
    """Extract client IP from request."""
    return request.client.host if request.client else None


def audit_and_detect(db: Session, **kwargs):
    """Write audit event and run detection rules."""
    write_audit(db, **kwargs)
    last = db.query(AuditEvent).order_by(desc(AuditEvent.id)).first()
    if last:
        run_detections_for_event(db, last)


# ========== TICKET ENDPOINTS ==========

@router.get("", response_model=TicketListOut)
async def list_tickets(
    request: Request,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    claims: dict = Depends(verify_bearer_token),
):
    """List tickets. Viewers see only their own; analysts/admins see all."""
    sub, upn = actor_from_claims(claims)
    ip = client_ip(request)

    try:
        require_perm(claims, "tickets:read")
    except HTTPException as e:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target="tickets:list",
            result="fail", reason=str(e.detail)
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    query = db.query(Ticket)
    
    # Filter by ownership for non-privileged users
    roles = roles_from_claims(claims)
    privileged = any(r in ("analyst", "admin") for r in roles)
    if not privileged:
        query = query.filter(Ticket.owner_sub == sub)
    
    # Optional status filter
    if status:
        query = query.filter(Ticket.status == status)
    
    tickets = query.order_by(desc(Ticket.created_at)).all()
    
    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="tickets:list", target=f"count:{len(tickets)}",
        result="success", reason=None
    )
    
    return {"tickets": tickets, "total": len(tickets)}


@router.post("", response_model=TicketOut)
async def create_ticket(
    request: Request,
    payload: TicketCreate,
    db: Session = Depends(get_db),
    claims: dict = Depends(verify_bearer_token),
):
    """Create a new ticket. Requires tickets:create permission."""
    sub, upn = actor_from_claims(claims)
    ip = client_ip(request)

    try:
        require_perm(claims, "tickets:create")
    except HTTPException as e:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target="tickets:create",
            result="fail", reason=str(e.detail)
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    t = Ticket(title=payload.title.strip(), body=payload.body.strip(), owner_sub=sub)
    db.add(t)
    db.commit()
    db.refresh(t)

    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="tickets:create", target=f"ticket:{t.id}",
        result="success", reason=None
    )
    return t


@router.patch("/{ticket_id}", response_model=TicketOut)
async def update_ticket(
    ticket_id: int,
    payload: TicketUpdate,
    request: Request,
    db: Session = Depends(get_db),
    claims: dict = Depends(verify_bearer_token),
):
    """Update a ticket (status, title, body). Requires ownership or analyst/admin role."""
    sub, upn = actor_from_claims(claims)
    ip = client_ip(request)

    t = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not t:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="tickets:update", target=f"ticket:{ticket_id}",
            result="fail", reason="not_found"
        )
        raise HTTPException(status_code=404, detail="Not found")

    # Check ownership or privileged role
    roles = roles_from_claims(claims)
    privileged = any(r in ("analyst", "admin") for r in roles)
    if not privileged and t.owner_sub != sub:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target=f"ticket:{ticket_id}",
            result="fail", reason="not owner"
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    # Apply updates
    if payload.status:
        t.status = payload.status
    if payload.title:
        t.title = payload.title.strip()
    if payload.body:
        t.body = payload.body.strip()
    
    db.commit()
    db.refresh(t)

    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="tickets:update", target=f"ticket:{t.id}",
        result="success", reason=None
    )
    return t


@router.delete("/{ticket_id}")
async def delete_ticket(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    claims: dict = Depends(verify_bearer_token),
):
    """Delete a ticket. Requires ownership or admin role."""
    sub, upn = actor_from_claims(claims)
    ip = client_ip(request)

    t = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not t:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="tickets:delete", target=f"ticket:{ticket_id}",
            result="fail", reason="not_found"
        )
        raise HTTPException(status_code=404, detail="Not found")

    # Only owner or admin can delete
    roles = roles_from_claims(claims)
    is_admin = "admin" in roles
    if not is_admin and t.owner_sub != sub:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target=f"tickets:delete ticket:{ticket_id}",
            result="fail", reason="not owner"
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    # Delete comments first
    db.query(Comment).filter(Comment.ticket_id == ticket_id).delete()
    db.delete(t)
    db.commit()

    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="tickets:delete", target=f"ticket:{ticket_id}",
        result="success", reason=None
    )
    return {"message": "Ticket deleted"}


@router.get("/insecure/{ticket_id}")
async def get_ticket_insecure(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    claims: dict = Depends(verify_bearer_token),
):
    """
    INTENTIONALLY INSECURE (IDOR):
    Returns any ticket by ID with no authorization checks beyond having a valid token.
    """
    sub, upn = actor_from_claims(claims)
    ip = client_ip(request)

    t = db.query(Ticket).filter(Ticket.id == ticket_id).first()

    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="tickets:read_insecure", target=f"ticket:{ticket_id}",
        result="success" if t else "fail",
        reason=None if t else "not_found"
    )

    if not t:
        raise HTTPException(status_code=404, detail="Not found")

    return {"id": t.id, "title": t.title, "body": t.body, "status": t.status, "owner_sub": t.owner_sub}


@router.get("/{ticket_id}", response_model=TicketOut)
async def get_ticket_secure(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    claims: dict = Depends(verify_bearer_token),
):
    """
    SECURE: Enforces tickets:read and prevents IDOR for non-privileged roles.
    """
    sub, upn = actor_from_claims(claims)
    ip = client_ip(request)

    try:
        require_perm(claims, "tickets:read")
    except HTTPException as e:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target=f"tickets:read ticket:{ticket_id}",
            result="fail", reason=str(e.detail)
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    t = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not t:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="tickets:read", target=f"ticket:{ticket_id}",
            result="fail", reason="not_found"
        )
        raise HTTPException(status_code=404, detail="Not found")

    # IDOR prevention: viewers can only read their own tickets
    roles = roles_from_claims(claims)
    privileged = any(r in ("analyst", "admin") for r in roles)
    if not privileged and t.owner_sub != sub:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target=f"ticket:{ticket_id}",
            result="fail", reason="IDOR prevented"
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="tickets:read", target=f"ticket:{ticket_id}",
        result="success", reason=None
    )
    return t


# ========== COMMENT ENDPOINTS ==========

@router.post("/{ticket_id}/comments", response_model=CommentOut)
async def add_comment(
    ticket_id: int,
    payload: CommentCreate,
    request: Request,
    db: Session = Depends(get_db),
    claims: dict = Depends(verify_bearer_token),
):
    """Add a comment to a ticket. Requires tickets:comment permission."""
    sub, upn = actor_from_claims(claims)
    ip = client_ip(request)

    try:
        require_perm(claims, "tickets:comment")
    except HTTPException as e:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target=f"tickets:comment ticket:{ticket_id}",
            result="fail", reason=str(e.detail)
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    t = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Ticket not found")

    comment = Comment(
        ticket_id=ticket_id,
        author_sub=sub,
        author_upn=upn,
        body=payload.body.strip()
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)

    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="tickets:comment", target=f"ticket:{ticket_id} comment:{comment.id}",
        result="success", reason=None
    )
    return comment


@router.get("/{ticket_id}/comments", response_model=list[CommentOut])
async def list_comments(
    ticket_id: int,
    request: Request,
    db: Session = Depends(get_db),
    claims: dict = Depends(verify_bearer_token),
):
    """List comments for a ticket. Requires tickets:read permission."""
    sub, upn = actor_from_claims(claims)

    try:
        require_perm(claims, "tickets:read")
    except HTTPException:
        raise HTTPException(status_code=403, detail="Forbidden")

    t = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Ticket not found")

    comments = db.query(Comment).filter(Comment.ticket_id == ticket_id).order_by(Comment.created_at).all()
    return comments
