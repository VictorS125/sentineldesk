import pytest
import asyncio
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db import Base, get_db
from app.auth import verify_bearer_token

# Use in-memory SQLite for tests
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    """
    Creates a fresh database session for a test.
    Creates tables before the test and drops them after.
    """
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db_session):
    """
    TestClient with overridden database and auth dependencies.
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    # Mock Auth: Return a "test-user" by default
    async def override_verify_token():
        return {
            "sub": "test-user-id",
            "preferred_username": "tester@sentineldesk.com",
            "roles": ["viewer"]
        }

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[verify_bearer_token] = override_verify_token
    
    with TestClient(app) as c:
        yield c
    
    app.dependency_overrides.clear()
