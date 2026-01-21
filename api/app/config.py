from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    tenant_id: str
    api_audience: str  # api://<api-client-id>
    allowed_issuers: str = "https://login.microsoftonline.com/{tenant_id}/v2.0"
    jwks_url: str = "https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    db_url: str = "sqlite:///./sentineldesk.db"

    class Config:
        env_file = ".env"

settings = Settings()
