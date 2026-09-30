from urllib.parse import urlsplit

from pydantic import BaseModel, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


TRUSTED_UPSTREAM_HOSTS = frozenset({"kfinance.kensho.com", "kensho.okta.com"})


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
    # Allow backend/auth URLs that are not https URLs on TRUSTED_UPSTREAM_HOSTS.
    # Credentials are sent to these URLs, so only enable this for hosts you trust.
    dangerously_allow_untrusted_upstream_urls: bool = False

    @model_validator(mode="after")
    def validate_upstream_urls(self) -> "Settings":
        """Ensure credentials are only sent to trusted https hosts unless explicitly overridden."""
        if self.dangerously_allow_untrusted_upstream_urls:
            return self
        for name, url in (
            ("backend_url", self.backend_url),
            ("auth.okta_host", self.auth.okta_host),
            ("auth.refresh_url", self.auth.refresh_url),
        ):
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.hostname not in TRUSTED_UPSTREAM_HOSTS
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError(
                    f"{name} must be an https URL on one of {sorted(TRUSTED_UPSTREAM_HOSTS)}. "
                    "Set DANGEROUSLY_ALLOW_UNTRUSTED_UPSTREAM_URLS=true to use another host."
                )
        return self


settings = Settings()
