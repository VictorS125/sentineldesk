# Security Finding: IDOR in Ticket Read Endpoint

## Overview

| Attribute | Value |
|-----------|-------|
| **Title** | Insecure Direct Object Reference (IDOR) in Ticket Retrieval |
| **Severity** | High |
| **CVSS Score** | 6.5 (Medium-High) |
| **CWE** | CWE-639: Authorization Bypass Through User-Controlled Key |
| **Status** | Remediated |

## Summary

The `/tickets/insecure/{ticket_id}` endpoint allows any authenticated user to access any ticket by ID, regardless of ownership. This demonstrates a classic IDOR vulnerability where authorization checks are missing.

## Impact

- **Confidentiality**: Unauthorized access to ticket data (titles, bodies) belonging to other users
- **Privacy**: Exposure of `owner_sub` field reveals the ticket owner's identity
- **Compliance**: Potential violation of data protection requirements

## Vulnerable Code

**File:** `api/app/routes_tickets.py`

```python
@router.get("/insecure/{ticket_id}")
async def get_ticket_insecure(ticket_id: int, request: Request, db: Session = Depends(get_db)):
    claims = await verify_bearer_token(request)
    # No authorization check - only token validation!
    t = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    return {"id": t.id, "title": t.title, "body": t.body, "owner_sub": t.owner_sub}
```

## Reproduction Steps

1. Sign in as **User A** (any role)
2. Create a ticket → note the returned `ticket_id`
3. Sign out
4. Sign in as **User B** (different user, viewer role)
5. Call: `GET /tickets/insecure/{ticket_id}`
6. **Result**: Returns full ticket data including `owner_sub` (User A's ID)

## Remediation

The secure endpoint `/tickets/{ticket_id}` implements proper authorization:

```python
@router.get("/{ticket_id}", response_model=TicketOut)
async def get_ticket_secure(ticket_id: int, request: Request, db: Session = Depends(get_db)):
    # ... token verification and permission check ...
    
    # IDOR prevention: viewers can only read their own tickets
    roles = roles_from_claims(claims)
    privileged = any(r in ("analyst", "admin") for r in roles)
    if not privileged and t.owner_sub != sub:
        raise HTTPException(status_code=403, detail="Forbidden")
```

**Key controls:**
1. Permission check via `require_perm(claims, "tickets:read")`
2. Role-based access: analysts/admins can read all; viewers restricted to own tickets
3. Audit logging of denied access attempts

## Verification

1. Sign in as viewer user
2. Call `GET /tickets/{ticket_id}` for another user's ticket
3. **Expected**: 403 Forbidden response
4. **Audit log**: Shows `authz:denied` event with reason "IDOR prevented"

## References

- [OWASP IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
