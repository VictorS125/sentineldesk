import pytest
from app.models import Ticket, AuditEvent, SecurityAlert
from app.audit import audit_and_detect

def test_idor_detection_rule(client, db_session):
    """
    Verify that accessing the insecure endpoint triggers an IDOR alert.
    """
    # 1. Create a ticket owner by someone else so it's a true IDOR if accessed
    t = Ticket(title="Secret Ticket", body="Hidden info", owner_sub="victim-user", status="open")
    db_session.add(t)
    db_session.commit()
    db_session.refresh(t)

    # 2. Access via insecure endpoint (client is mocked as 'test-user-id')
    response = client.get(f"/tickets/insecure/{t.id}")
    assert response.status_code == 200
    
    # 3. Check for Audit Event
    event = db_session.query(AuditEvent).filter(AuditEvent.action == "tickets:read_insecure").first()
    assert event is not None
    assert event.target == f"ticket:{t.id}"

    # 4. Check for Security Alert
    alert = db_session.query(SecurityAlert).filter(SecurityAlert.rule_id == "INSECURE_IDOR_ACCESS").first()
    assert alert is not None
    assert alert.severity == "high"
    assert "insecure_endpoint" in alert.context


def test_impossible_travel_detection(client, db_session):
    """
    Verify that logins from different IPs within 5 minutes trigger an alert.
    """
    user_sub = "traveling-hacker"
    
    # 1. First Login (San Francisco)
    audit_and_detect(
        db_session,
        actor_sub=user_sub,
        actor_upn="hacker@example.com",
        ip="192.168.1.100",
        action="auth:login",
        target="system",
        result="success"
    )
    
    # Confirm no alert yet
    # Note: Our rule checks for >= 2 DISTINCT IPs. The first one is just one.
    alerts = db_session.query(SecurityAlert).filter(SecurityAlert.rule_id == "IMPOSSIBLE_TRAVEL").all()
    assert len(alerts) == 0

    # 2. Second Login (New York) - moments later
    audit_and_detect(
        db_session,
        actor_sub=user_sub,
        actor_upn="hacker@example.com",
        ip="10.0.0.50",
        action="auth:login",
        target="system",
        result="success"
    )

    # 3. Check for Impossible Travel Alert
    alert = db_session.query(SecurityAlert).filter(SecurityAlert.rule_id == "IMPOSSIBLE_TRAVEL").first()
    assert alert is not None
    assert alert.severity == "high"
    # Verify both IPs are mentioned in the context (order might vary)
    assert "192.168.1.100" in alert.context
    assert "10.0.0.50" in alert.context
