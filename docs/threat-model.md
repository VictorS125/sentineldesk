# Threat Model: SentinelDesk

## Overview

SentinelDesk is a secure ticket management application demonstrating enterprise security patterns with Microsoft Entra ID authentication and role-based access control.

## Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Tickets | User-submitted support tickets | Medium - may contain sensitive operational data |
| Audit Logs | Security event records | High - critical for incident response |
| Security Alerts | Detection rule triggers | High - security intelligence |
| User Tokens | OAuth access tokens | High - identity credentials |

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet (Untrusted)                      │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Browser (User Device)                        │
│  ┌─────────────────┐    ┌──────────────────┐                    │
│  │ React Frontend  │◄───│  MSAL.js Client  │                    │
│  └─────────────────┘    └──────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
                                 │ Bearer Token
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      API Server (Trusted)                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ JWT Auth │  │   RBAC   │  │  Audit   │  │    Detections    │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Database (Protected)                        │
│       Tickets │ Audit Events │ Security Alerts                   │
└─────────────────────────────────────────────────────────────────┘
```

## Threats & Mitigations

### T1: Token Theft / Session Hijacking

| Aspect | Details |
|--------|---------|
| **Threat** | Attacker obtains valid access token |
| **Impact** | Impersonation, unauthorized access |
| **Mitigations** | Short token lifetime, HTTPS-only, secure token storage in MSAL |

### T2: IDOR (Insecure Direct Object Reference)

| Aspect | Details |
|--------|---------|
| **Threat** | User accesses resources belonging to others |
| **Impact** | Data breach, privacy violation |
| **Mitigations** | Server-side ownership checks, role-based access (see `security-findings.md`) |

### T3: Privilege Escalation

| Aspect | Details |
|--------|---------|
| **Threat** | User gains higher privileges than assigned |
| **Impact** | Unauthorized admin actions, data export |
| **Mitigations** | Server-side RBAC from JWT groups, no client-side role trust |

### T4: Log Tampering

| Aspect | Details |
|--------|---------|
| **Threat** | Attacker modifies audit trail |
| **Impact** | Cover tracks, destroy evidence |
| **Mitigations** | Database-level logging, append-only semantics (no delete API) |

### T5: API Abuse / Brute Force

| Aspect | Details |
|--------|---------|
| **Threat** | Automated attacks against endpoints |
| **Impact** | Account lockout, resource exhaustion |
| **Mitigations** | Detection rules for auth failures, alerting on bursts |

## Security Controls Summary

| Control | Implementation |
|---------|----------------|
| Authentication | Microsoft Entra ID (OIDC), JWKS verification |
| Authorization | Server-side RBAC, group-to-role mapping |
| Audit Logging | All security-relevant actions logged |
| Detection Rules | AUTH_FAIL_BURST, ADMIN_OFF_HOURS, REPEATED_AUTHZ_DENIED |
| Input Validation | Pydantic schemas with length limits |
