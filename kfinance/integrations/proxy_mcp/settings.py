from pydantic import BaseModel, SecretStr, field_validator
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
    # Shared secret MCP clients must send as `Authorization: Bearer <key>`.
    proxy_api_key: SecretStr | None = None
    # Browser origins allowed to call the proxy (CORS and Origin validation).
    cors_allowed_origins: list[str] = []
    # Extra Host header values accepted in addition to loopback names and the bind address.
    allowed_hosts: list[str] = []

    @field_validator("proxy_api_key")
    @classmethod
    def _reject_empty_api_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().strip():
            raise ValueError("PROXY_API_KEY must not be empty")
        return value

    @field_validator("cors_allowed_origins", "allowed_hosts")
    @classmethod
    def _reject_wildcards(cls, values: list[str]) -> list[str]:
        if any("*" in value for value in values):
            raise ValueError("Wildcards are not allowed; list each trusted value explicitly")
        return values


settings = Settings()
