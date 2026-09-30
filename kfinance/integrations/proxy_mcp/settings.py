from pydantic import BaseModel, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseModel):
    refresh_token: str | None = None
    client_id: str | None = None
    private_key: str | None = None
    okta_host: str = "https://kensho.okta.com"
    refresh_url: str = "https://kfinance.kensho.com/oauth2/refresh"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_nested_delimiter="_", env_nested_max_split=1)

    backend_url: str = "https://kfinance.kensho.com/integrations/mcp"
    auth: AuthSettings = AuthSettings()
    # Pre-shared token MCP clients must send as `Authorization: Bearer <token>`.
    inbound_auth_token: SecretStr | None = None
    # Extra Host header values to accept on /mcp (loopback and the bind address always are).
    allowed_hosts: list[str] = []
    # Browser origins allowed by CORS and by the /mcp Origin check.
    cors_allowed_origins: list[str] = []


settings = Settings()
