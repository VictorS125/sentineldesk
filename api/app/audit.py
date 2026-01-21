from sqlalchemy.orm import Session
from .models import AuditEvent

def write_audit(
    db: Session,
    *,
    actor_sub: str | None,
    actor_upn: str | None,
    ip: str | None,
    action: str,
    target: str | None,
    result: str,
    reason: str | None = None,
):
    ev = AuditEvent(
        actor_sub=actor_sub,
        actor_upn=actor_upn,
        ip=ip,
        action=action,
        target=target,
        result=result,
        reason=reason,
    )
    db.add(ev)
    db.commit()


def audit_and_detect(
    db: Session,
    *,
    actor_sub: str | None,
    actor_upn: str | None,
    ip: str | None,
    action: str,
    target: str | None,
    result: str,
    reason: str | None = None,
):
    """Write audit log and immediately run detection rules."""
    from .detections import run_detections_for_event
    
    ev = AuditEvent(
        actor_sub=actor_sub,
        actor_upn=actor_upn,
        ip=ip,
        action=action,
        target=target,
        result=result,
        reason=reason,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    
    run_detections_for_event(db, ev)
