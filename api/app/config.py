from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    tenant_id: str
    api_audience: str  # api://<api-client-id>
    allowed_issuers: str = "https://login.microsoftonline.com/{tenant_id}/v2.0"
    jwks_url: str = "https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    db_url: str = "sqlite:///./sentineldesk.db"
    
    # Production Security
    allowed_origins: str = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:5173"
    csp_connect_src: str = "self http://localhost:3000"

    class Config:
        env_file = ".env"

settings = Settings()
