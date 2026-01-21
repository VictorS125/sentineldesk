import json
from typing import Any, Dict, Optional

import httpx
from jose import jwt
from jose.exceptions import JWTError
from fastapi import HTTPException, Request

from .config import settings

_jwks_cache: Optional[Dict[str, Any]] = None

async def _get_jwks() -> Dict[str, Any]:
    global _jwks_cache
    if _jwks_cache:
        return _jwks_cache
    url = settings.jwks_url.format(tenant_id=settings.tenant_id)
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url)
        r.raise_for_status()
        _jwks_cache = r.json()
        return _jwks_cache

def _issuer() -> str:
    return settings.allowed_issuers.format(tenant_id=settings.tenant_id)

async def verify_bearer_token(request: Request) -> Dict[str, Any]:
    auth = request.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = auth.split(" ", 1)[1].strip()
    jwks = await _get_jwks()

    # Microsoft Entra ID can use different issuer formats
    valid_issuers = [
        f"https://login.microsoftonline.com/{settings.tenant_id}/v2.0",
        f"https://login.microsoftonline.com/{settings.tenant_id}/v2.0/",
        f"https://sts.windows.net/{settings.tenant_id}/",
        f"https://sts.windows.net/{settings.tenant_id}",
    ]

    try:
        # Decode without issuer validation first, then check manually
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=settings.api_audience,
            options={"verify_iss": False, "verify_at_hash": False},
        )
        
        # Manual issuer check
        token_issuer = claims.get("iss", "")
        if token_issuer not in valid_issuers:
            raise HTTPException(status_code=401, detail=f"Invalid token: Invalid issuer: {token_issuer}")
        
        return claims
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
