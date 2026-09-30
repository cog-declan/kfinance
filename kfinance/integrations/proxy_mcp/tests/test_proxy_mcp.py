from typing import Generator
from unittest.mock import patch

from click.testing import CliRunner
import httpx2
from pydantic import SecretStr, ValidationError
import pytest
from respx import Router

from kfinance.integrations.proxy_mcp import proxy_mcp
from kfinance.integrations.proxy_mcp.proxy_mcp import create_app, run_proxy_mcp
from kfinance.integrations.proxy_mcp.settings import Settings


DUMMY_TOKEN = "dummy-inbound-token-0123456789abcdef"
ALLOWED_ORIGIN = "https://app.example"
INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Host": "127.0.0.1:8000"}


@pytest.fixture
def proxy_settings(httpx2_mock: Router) -> Generator[Settings, None, None]:
    """Settings with dummy credentials. httpx2_mock fails the test on any backend request."""
    test_settings = Settings(
        auth={"refresh_token": "dummy-refresh-token"},
        inbound_auth_token=SecretStr(DUMMY_TOKEN),
        cors_allowed_origins=[ALLOWED_ORIGIN],
    )
    with patch.object(proxy_mcp, "settings", test_settings):
        yield test_settings


async def _request(method: str, path: str, **kwargs: object) -> httpx2.Response:
    app = create_app()
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as client:
            return await client.request(method, path, **kwargs)  # type: ignore[arg-type]


class TestSettings:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in ("INBOUND_AUTH_TOKEN", "CORS_ALLOWED_ORIGINS", "ALLOWED_HOSTS"):
            monkeypatch.delenv(var, raising=False)
        default_settings = Settings()
        assert default_settings.inbound_auth_token is None
        assert default_settings.cors_allowed_origins == []
        assert default_settings.allowed_hosts == []

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("INBOUND_AUTH_TOKEN", DUMMY_TOKEN)
        monkeypatch.setenv("CORS_ALLOWED_ORIGINS", f'["{ALLOWED_ORIGIN}"]')
        monkeypatch.setenv("ALLOWED_HOSTS", '["mcp.example"]')
        env_settings = Settings()
        assert env_settings.inbound_auth_token is not None
        assert env_settings.inbound_auth_token.get_secret_value() == DUMMY_TOKEN
        assert DUMMY_TOKEN not in repr(env_settings)
        assert env_settings.cors_allowed_origins == [ALLOWED_ORIGIN]
        assert env_settings.allowed_hosts == ["mcp.example"]

    @pytest.mark.parametrize(
        "field, url",
        [
            ("backend_url", "https://evil.example/integrations/mcp"),
            ("backend_url", "http://kfinance.kensho.com/integrations/mcp"),
            ("backend_url", "https://user:pw@kfinance.kensho.com/integrations/mcp"),
            ("okta_host", "https://kensho.okta.com.evil.example"),
            ("refresh_url", "http://kfinance.kensho.com/oauth2/refresh"),
        ],
    )
    def test_untrusted_upstream_url_is_rejected(self, field: str, url: str) -> None:
        kwargs: dict[str, object] = (
            {"backend_url": url} if field == "backend_url" else {"auth": {field: url}}
        )
        with pytest.raises(ValidationError, match="DANGEROUSLY_ALLOW_UNTRUSTED_UPSTREAM_URLS"):
            Settings(**kwargs)  # type: ignore[arg-type]

    def test_untrusted_upstream_url_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BACKEND_URL", "http://localhost:9000/mcp")
        monkeypatch.setenv("AUTH_REFRESH_URL", "https://auth.example/refresh")
        monkeypatch.setenv("DANGEROUSLY_ALLOW_UNTRUSTED_UPSTREAM_URLS", "true")
        env_settings = Settings()
        assert env_settings.backend_url == "http://localhost:9000/mcp"
        assert env_settings.auth.refresh_url == "https://auth.example/refresh"


@pytest.mark.usefixtures("proxy_settings")
class TestInboundProtection:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "extra_headers, expected_status",
        [
            pytest.param({}, 401, id="missing token"),
            pytest.param({"Authorization": "Bearer wrong-token"}, 401, id="wrong token"),
            pytest.param(
                {"Authorization": f"Bearer {DUMMY_TOKEN}", "Host": "attacker.example"},
                421,
                id="DNS rebinding host",
            ),
            pytest.param(
                {"Authorization": f"Bearer {DUMMY_TOKEN}", "Origin": "https://attacker.example"},
                403,
                id="cross-site origin",
            ),
        ],
    )
    async def test_mcp_rejects(self, extra_headers: dict[str, str], expected_status: int) -> None:
        resp = await _request(
            "POST", "/mcp", json=INITIALIZE_REQUEST, headers={**MCP_HEADERS, **extra_headers}
        )
        assert resp.status_code == expected_status

    @pytest.mark.asyncio
    async def test_health_is_public(self) -> None:
        resp = await _request("GET", "/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "origin, allowed",
        [
            pytest.param(ALLOWED_ORIGIN, True, id="allowlisted origin"),
            pytest.param("https://attacker.example", False, id="other origin"),
        ],
    )
    async def test_cors_allowlist(self, origin: str, allowed: bool) -> None:
        resp = await _request(
            "OPTIONS",
            "/mcp",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Host": "127.0.0.1:8000",
            },
        )
        assert (resp.headers.get("access-control-allow-origin") == origin) is allowed


class TestRunProxyMcpCli:
    def test_non_loopback_without_auth_refuses_to_start(self, httpx2_mock: Router) -> None:
        no_auth_settings = Settings(auth={"refresh_token": "dummy-refresh-token"})
        with (
            patch.object(proxy_mcp, "settings", no_auth_settings),
            patch.object(proxy_mcp.uvicorn, "run") as run,
        ):
            result = CliRunner().invoke(run_proxy_mcp, ["--host", "0.0.0.0"])
        assert result.exit_code == 2
        assert "without inbound authentication" in result.output
        run.assert_not_called()

    @pytest.mark.parametrize(
        "extra_args",
        [
            pytest.param([], id="loopback"),
            pytest.param(
                ["--host", "0.0.0.0", "--dangerously-allow-unauthenticated-network-access"],
                id="explicit opt-out",
            ),
        ],
    )
    def test_starts(self, extra_args: list[str], httpx2_mock: Router) -> None:
        no_auth_settings = Settings(auth={"refresh_token": "dummy-refresh-token"})
        with (
            patch.object(proxy_mcp, "settings", no_auth_settings),
            patch.object(proxy_mcp.uvicorn, "run") as run,
        ):
            result = CliRunner().invoke(run_proxy_mcp, extra_args)
        assert result.exit_code == 0, result.output
        run.assert_called_once()

    def test_non_loopback_with_auth_starts(self, proxy_settings: Settings) -> None:
        with patch.object(proxy_mcp.uvicorn, "run") as run:
            result = CliRunner().invoke(run_proxy_mcp, ["--host", "0.0.0.0"])
        assert result.exit_code == 0, result.output
        run.assert_called_once()
