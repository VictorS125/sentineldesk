from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from .db import get_db
from .auth import verify_bearer_token
from .rbac import require_perm
from .models import AuditEvent, SecurityAlert, Ticket
from .audit import write_audit, audit_and_detect
from .detections import run_detections_for_event

router = APIRouter(prefix="/admin", tags=["admin"])


def actor(claims: dict):
    """Extract actor identifiers from JWT claims."""
    sub = claims.get("sub")
    upn = claims.get("preferred_username") or claims.get("upn") or claims.get("email")
    return sub, upn





@router.patch("/alerts/{alert_id}")
async def update_alert_status(alert_id: int, request: Request, db: Session = Depends(get_db)):
    """Update alert triage status."""
    claims = await verify_bearer_token(request)
    sub, upn = actor(claims)
    ip = ip_of(request)
    
    try:
        require_perm(claims, "admin:export_audit")
    except HTTPException:
        raise HTTPException(status_code=403, detail="Forbidden")

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    body = await request.json()
    new_status = body.get("status")
    if new_status not in ["new", "investigating", "resolved", "false_positive"]:
        raise HTTPException(status_code=400, detail="Invalid status")
        
    old_status = alert.triage_status
    alert.triage_status = new_status
    db.commit()
    
    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="alert:triage", target=f"alert:{alert_id}",
        result="success", reason=f"changed status from {old_status} to {new_status}"
    )
    
    return {"message": "Alert status updated", "status": new_status}


@router.post("/alerts/{alert_id}/escalate")
async def escalate_alert(alert_id: int, request: Request, db: Session = Depends(get_db)):
    """Create a ticket from an alert."""
    claims = await verify_bearer_token(request)
    sub, upn = actor(claims)
    ip = ip_of(request)
    
    try:
        require_perm(claims, "admin:export_audit")
    except HTTPException:
        raise HTTPException(status_code=403, detail="Forbidden")

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    if alert.ticket_id:
        return {"message": "Ticket already exists", "ticket_id": alert.ticket_id}
        
    # Create ticket
    title = f"[Security Incident] {alert.rule_id} Detected"
    body = f"""**Security Alert**: {alert.rule_id}
**Severity**: {alert.severity}
**Context**:
{alert.context}

**Time**: {alert.ts}
**Source Alert ID**: {alert.id}

This ticket was automatically created from a security alert."""
    
    ticket = Ticket(
        title=title,
        body=body,
        status="open",
        owner_sub=sub # Assign to the admin who clicked the button
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    
    # Link back and update status
    alert.ticket_id = ticket.id
    alert.triage_status = "investigating"
    db.commit()
    
    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="alert:escalate", target=f"ticket:{ticket.id}",
        result="success", reason=f"escalated alert {alert_id}"
    )
    
    return {"message": "Ticket created", "ticket_id": ticket.id}


def ip_of(request: Request) -> str | None:
    """Extract client IP from request."""
    return request.client.host if request.client else None


def audit_and_detect(db: Session, **kwargs):
    """Write audit event and run detection rules."""
    write_audit(db, **kwargs)
    last = db.query(AuditEvent).order_by(desc(AuditEvent.id)).first()
    if last:
        run_detections_for_event(db, last)


@router.post("/simulate-attacks")
async def simulate_attacks(request: Request, db: Session = Depends(get_db)):
    """
    Simulate real attacks to trigger detection rules.
    This creates actual audit events that the detection engine will flag.
    """
    claims = await verify_bearer_token(request)
    sub, upn = actor(claims)
    ip = ip_of(request)
    
    try:
        require_perm(claims, "admin:export_audit")
    except HTTPException:
        raise HTTPException(status_code=403, detail="Forbidden")

    # 1. Trigger AUTH_FAIL_BURST (10+ invalid tokens from same IP)
    # We simulate this by directly writing audit logs since we can't self-DOS easily
    print(f"⚡ Simulating AUTH_FAIL_BURST from {ip}")
    for _ in range(12):
        audit_and_detect(
            db,
            actor_sub=None, actor_upn=None, ip=ip,
            action="auth:token_invalid", target="api",
            result="fail", reason="simulated_attack"
        )
    
    # 2. Trigger IMPOSSIBLE_TRAVEL (Same user, different IPs)
    print(f"⚡ Simulating IMPOSSIBLE_TRAVEL for {upn}")
    # Login from New York
    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip="203.0.113.10", # New York IP
        action="auth:login", target="api",
        result="success", reason="simulated_travel"
    )
    # Login from Tokyo 1 second later
    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip="192.0.2.20", # Tokyo IP
        action="auth:login", target="api",
        result="success", reason="simulated_travel"
    )

    # 3. Trigger REPEATED_AUTHZ_DENIED (5+ denials)
    print(f"⚡ Simulating REPEATED_AUTHZ_DENIED for {upn}")
    for i in range(6):
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target=f"resource:{i}",
            result="fail", reason="simulated_denial"
        )

    # 4. Trigger PRIVILEGE_ESCALATION_ATTEMPT (3+ admin denials)
    print(f"⚡ Simulating PRIVILEGE_ESCALATION for {upn}")
    for i in range(4):
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target=f"admin:resource:{i}",
            result="fail", reason="simulated_privilege_escalation"
        )

    return {"message": "Simulated attacks executed. Check alerts tab."}


@router.get("/audit")
async def export_audit(request: Request, db: Session = Depends(get_db)):
    """
    Export audit log entries. Admin-only endpoint.
    Returns up to 200 most recent audit events.
    """
    claims = await verify_bearer_token(request)
    sub, upn = actor(claims)
    ip = ip_of(request)

    try:
        require_perm(claims, "admin:export_audit")
    except HTTPException as e:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target="admin:export_audit",
            result="fail", reason=str(e.detail)
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    rows = db.query(AuditEvent).order_by(desc(AuditEvent.ts)).limit(200).all()
    
    # Note: We don't audit successful reads of the audit log itself to prevent
    # infinite entries when viewing/refreshing. Failed auth attempts are still logged.

    return {
        "events": [
            {
                "id": r.id,
                "ts": str(r.ts),
                "actor": r.actor_upn,
                "ip": r.ip,
                "action": r.action,
                "target": r.target,
                "result": r.result,
                "reason": r.reason
            }
            for r in rows
        ]
    }


@router.delete("/audit")
async def clear_audit_log(request: Request, db: Session = Depends(get_db)):
    """Clear all audit log entries."""
    claims = await verify_bearer_token(request)
    sub, upn = actor(claims)
    ip = ip_of(request)

    try:
        require_perm(claims, "admin:export_audit")
    except HTTPException:
        # Log the failed attempt to clear audit logs
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target="admin:clear_audit",
            result="fail", reason="forbidden"
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    count = db.query(AuditEvent).delete()
    db.commit()

    # Log that the audit log was cleared (this will be the first new entry)
    audit_and_detect(
        db,
        actor_sub=sub, actor_upn=upn, ip=ip,
        action="admin:clear_audit", target="audit_events",
        result="success", reason=f"deleted {count} events"
    )
    
    return {"message": f"Cleared {count} audit events"}


@router.get("/alerts")
async def list_alerts(request: Request, db: Session = Depends(get_db)):
    """
    List security alerts. Admin-only endpoint.
    Returns up to 200 most recent security alerts.
    """
    claims = await verify_bearer_token(request)
    sub, upn = actor(claims)
    ip = ip_of(request)

    try:
        require_perm(claims, "admin:export_audit")
    except HTTPException as e:
        audit_and_detect(
            db,
            actor_sub=sub, actor_upn=upn, ip=ip,
            action="authz:denied", target="admin:alerts",
            result="fail", reason=str(e.detail)
        )
        raise HTTPException(status_code=403, detail="Forbidden")

    rows = db.query(SecurityAlert).order_by(desc(SecurityAlert.ts)).limit(200).all()
    return {
        "alerts": [
            {
                "id": r.id,
                "ts": str(r.ts),
                "rule_id": r.rule_id,
                "severity": r.severity,
                "status": r.triage_status,
                "context": r.context,
                "trigger_event_id": r.trigger_event_id,
                "ticket_id": r.ticket_id
            }
            for r in rows
        ]
    }


@router.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: int, request: Request, db: Session = Depends(get_db)):
    """Delete a single security alert."""
    claims = await verify_bearer_token(request)
    sub, upn = actor(claims)
    
    try:
        require_perm(claims, "admin:export_audit")
    except HTTPException:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    db.delete(alert)
    db.commit()
    return {"message": "Alert deleted"}


@router.delete("/alerts")
async def clear_all_alerts(request: Request, db: Session = Depends(get_db)):
    """Clear all security alerts."""
    claims = await verify_bearer_token(request)
    sub, upn = actor(claims)
    
    try:
        require_perm(claims, "admin:export_audit")
    except HTTPException:
        raise HTTPException(status_code=403, detail="Forbidden")
    
    count = db.query(SecurityAlert).delete()
    db.commit()
    return {"message": f"Deleted {count} alerts"}
