from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .db import Base, engine
from .routes_tickets import router as tickets_router
from .routes_admin import router as admin_router
from .rate_limit import RateLimitMiddleware
from .config import settings


Base.metadata.create_all(bind=engine)

app = FastAPI(title="SentinelDesk API")

# Health check endpoint for Railway
@app.get("/health", tags=["monitoring"])
async def health_check():
    return {"status": "healthy"}

# Rate limiting middleware (100 requests/minute per IP)
app.add_middleware(RateLimitMiddleware, requests_per_minute=100)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # Dynamic CSP - allows connecting to frontend
    response.headers["Content-Security-Policy"] = f"default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src {settings.csp_connect_src}"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Server"] = "SentinelDesk-Shield"
    return response

# CORS configuration
origins = settings.allowed_origins.split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tickets_router)
app.include_router(admin_router)
