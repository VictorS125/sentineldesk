"""Simple in-memory rate limiting middleware."""
import time
from collections import defaultdict
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiter using sliding window counter.
    Limits requests per IP address.
    """
    
    def __init__(self, app, requests_per_minute: int = 100):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.window_seconds = 60
        # Dict of IP -> list of timestamps
        self.request_log: dict[str, list[float]] = defaultdict(list)
    
    def _clean_old_requests(self, ip: str, now: float):
        """Remove requests older than the window."""
        cutoff = now - self.window_seconds
        self.request_log[ip] = [ts for ts in self.request_log[ip] if ts > cutoff]
    
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        
        # Clean old requests
        self._clean_old_requests(client_ip, now)
        
        # Check rate limit
        if len(self.request_log[client_ip]) >= self.requests_per_minute:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {self.requests_per_minute} requests per minute."
            )
        
        # Log this request
        self.request_log[client_ip].append(now)
        
        # Continue with request
        response = await call_next(request)
        return response
