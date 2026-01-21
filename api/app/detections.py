import json
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc, distinct

from .models import AuditEvent, SecurityAlert


def _create_alert(db: Session, rule_id: str, severity: str, context: dict, event_id: int = None):
    """Create a security alert and persist to database."""
    alert = SecurityAlert(
        rule_id=rule_id, 
        severity=severity, 
        context=json.dumps(context),
        trigger_event_id=event_id
    )
    db.add(alert)
    db.commit()
    print(f"🚨 SECURITY ALERT: {rule_id} (severity: {severity}) - {context}")


def run_detections_for_event(db: Session, event: AuditEvent):
    """Run all detection rules against the given audit event."""
    
    # Rule 1: Auth failure burst from same IP
    if event.action == "auth:token_invalid" and event.ip:
        cutoff = datetime.utcnow() - timedelta(minutes=5)
        recent = (
            db.query(AuditEvent)
            .filter(AuditEvent.action == "auth:token_invalid")
            .filter(AuditEvent.ip == event.ip)
            .filter(AuditEvent.ts >= cutoff)
            .count()
        )
        if recent >= 10:
            _create_alert(db, "AUTH_FAIL_BURST", "high", {"ip": event.ip, "count_5m": recent}, event.id)

    # Rule 2: Privileged action outside business hours (disabled for demo)
    # Uncomment for production and adjust hours for your timezone
    # if event.action.startswith("admin:"):
    #     hour = datetime.utcnow().hour
    #     if hour < 9 or hour > 18:
    #         _create_alert(db, "ADMIN_OFF_HOURS", "med", {"action": event.action, "hour_utc": hour})

    # Rule 3: Repeated authorization failures
    if event.action == "authz:denied" and event.actor_sub:
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        recent = (
            db.query(AuditEvent)
            .filter(AuditEvent.action == "authz:denied")
            .filter(AuditEvent.actor_sub == event.actor_sub)
            .filter(AuditEvent.ts >= cutoff)
            .count()
        )
        if recent >= 5:
            _create_alert(db, "REPEATED_AUTHZ_DENIED", "med", {
                "actor_sub": event.actor_sub,
                "count_10m": recent
            }, event.id)

    # Rule 4: Impossible Travel - Same user, different IPs, within 5 minutes
    # We only check this on login events to avoid spamming alerts for every subsequent action
    if event.action == "auth:login" and event.actor_sub and event.ip:
        cutoff = datetime.utcnow() - timedelta(minutes=5)
        recent_ips = (
            db.query(distinct(AuditEvent.ip))
            .filter(AuditEvent.actor_sub == event.actor_sub)
            .filter(AuditEvent.ip.isnot(None))
            .filter(AuditEvent.ts >= cutoff)
            .all()
        )
        unique_ips = [ip[0] for ip in recent_ips if ip[0]]
        if len(unique_ips) >= 2:
            _create_alert(db, "IMPOSSIBLE_TRAVEL", "high", {
                "actor_sub": event.actor_sub,
                "ips": unique_ips,
                "window_minutes": 5
            }, event.id)

    # Rule 5: Privilege Escalation Attempts - Multiple admin endpoint denials
    if event.action == "authz:denied" and event.target and "admin:" in event.target:
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        admin_denials = (
            db.query(AuditEvent)
            .filter(AuditEvent.action == "authz:denied")
            .filter(AuditEvent.actor_sub == event.actor_sub)
            .filter(AuditEvent.target.contains("admin:"))
            .filter(AuditEvent.ts >= cutoff)
            .count()
        )
        if admin_denials >= 3:
            _create_alert(db, "PRIVILEGE_ESCALATION_ATTEMPT", "high", {
                "actor_sub": event.actor_sub,
                "denied_admin_actions": admin_denials,
                "window_minutes": 10
            }, event.id)

    # Rule 6: IDOR Vulnerability Usage
    # Detects use of the insecure endpoint or blocked IDOR attempts
    if event.action == "tickets:read_insecure":
        _create_alert(db, "INSECURE_IDOR_ACCESS", "high", {
            "actor_sub": event.actor_sub,
            "target": event.target,
            "endpoint": "insecure_endpoint"
        }, event.id)
    
    if event.action == "authz:denied" and event.reason == "IDOR prevented":
        _create_alert(db, "BLOCKED_IDOR_ATTEMPT", "medium", {
            "actor_sub": event.actor_sub,
            "target": event.target,
            "reason": "access_control_enforced"
        }, event.id)
