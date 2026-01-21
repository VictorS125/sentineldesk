from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .db import Base, engine
from .routes_tickets import router as tickets_router
from .routes_admin import router as admin_router
from .rate_limit import RateLimitMiddleware


Base.metadata.create_all(bind=engine)

app = FastAPI(title="SentinelDesk API")

# Rate limiting middleware (100 requests/minute per IP)
app.add_middleware(RateLimitMiddleware, requests_per_minute=100)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # Basic CSP - in production this should be tighter
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self' http://localhost:3000"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Hide server header (Uvicorn adds it by default, hard to remove fully without proxy, but we can try overwriting)
    response.headers["Server"] = "SentinelDesk-Shield"
    return response

# CORS configuration for Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tickets_router)
app.include_router(admin_router)
