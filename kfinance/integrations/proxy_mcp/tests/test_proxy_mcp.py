from typing import Generator
from unittest.mock import MagicMock

from click.testing import CliRunner
from pydantic import SecretStr, ValidationError
import pytest
from respx import Router
from starlette.testclient import TestClient

from kfinance.integrations.proxy_mcp import proxy_mcp
from kfinance.integrations.proxy_mcp.proxy_mcp import create_app, run_proxy_mcp
from kfinance.integrations.proxy_mcp.settings import Settings, settings


DUMMY_REFRESH_TOKEN = "dummy-refresh-token"
DUMMY_PROXY_API_KEY = "dummy-proxy-api-key"
LOOPBACK_BASE_URL = "http://127.0.0.1:8000"
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "0.0.1"},
    },
}


@pytest.fixture(autouse=True)
def proxy_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings.auth, "refresh_token", DUMMY_REFRESH_TOKEN)
    monkeypatch.setattr(settings.auth, "client_id", None)
    monkeypatch.setattr(settings.auth, "private_key", None)
    monkeypatch.setattr(settings, "proxy_api_key", None)
    monkeypatch.setattr(settings, "cors_allowed_origins", [])
    monkeypatch.setattr(settings, "allowed_hosts", [])


@pytest.fixture
def client(httpx2_mock: Router) -> Generator[TestClient, None, None]:
    """A test client for the proxy app.

    `httpx2_mock` has no routes registered, so any request the proxy makes to the token
    endpoint or the kfinance backend fails the test.
    """
    with TestClient(create_app(), base_url=LOOPBACK_BASE_URL) as test_client:
        yield test_client


def _assert_nothing_forwarded(httpx2_mock: Router) -> None:
    assert httpx2_mock.calls.call_count == 0


class TestHostOriginValidation:
    def test_dns_rebinding_host_is_rejected(self, client: TestClient, httpx2_mock: Router) -> None:
        """
        GIVEN a proxy bound to loopback
        WHEN a request arrives with an attacker-controlled Host header (DNS rebinding)
        THEN it is rejected before anything is forwarded to the backend.
        """
        resp = client.post(
            "/mcp",
            json=INITIALIZE_REQUEST,
            headers={**MCP_HEADERS, "Host": "attacker.example:8000"},
        )
        assert resp.status_code == 421
        _assert_nothing_forwarded(httpx2_mock)

    def test_cross_origin_request_is_rejected(
        self, client: TestClient, httpx2_mock: Router
    ) -> None:
        """
        WHEN a browser on an untrusted origin calls the proxy
        THEN the request is rejected and no CORS grant is returned.
        """
        resp = client.post(
            "/mcp",
            json=INITIALIZE_REQUEST,
            headers={**MCP_HEADERS, "Origin": "https://evil.example"},
        )
        assert resp.status_code == 403
        assert "access-control-allow-origin" not in resp.headers
        assert "access-control-allow-credentials" not in resp.headers
        _assert_nothing_forwarded(httpx2_mock)

    def test_cors_preflight_from_untrusted_origin_is_not_granted(
        self, client: TestClient, httpx2_mock: Router
    ) -> None:
        resp = client.options(
            "/mcp",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert resp.headers.get("access-control-allow-origin") != "https://evil.example"
        assert "access-control-allow-credentials" not in resp.headers
        _assert_nothing_forwarded(httpx2_mock)

    def test_allowed_host_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, httpx2_mock: Router
    ) -> None:
        monkeypatch.setattr(settings, "allowed_hosts", ["proxy.internal"])
        with TestClient(create_app(), base_url="http://proxy.internal") as test_client:
            assert test_client.get("/health").status_code == 200

    def test_allowlisted_origin_gets_cors_grant_without_credentials(
        self, monkeypatch: pytest.MonkeyPatch, httpx2_mock: Router
    ) -> None:
        monkeypatch.setattr(settings, "cors_allowed_origins", ["https://app.example"])
        with TestClient(create_app(), base_url=LOOPBACK_BASE_URL) as test_client:
            resp = test_client.options(
                "/mcp",
                headers={
                    "Origin": "https://app.example",
                    "Access-Control-Request-Method": "POST",
                },
            )
        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == "https://app.example"
        assert "access-control-allow-credentials" not in resp.headers
        _assert_nothing_forwarded(httpx2_mock)


class TestInboundAuth:
    @pytest.fixture
    def authed_client(
        self, monkeypatch: pytest.MonkeyPatch, httpx2_mock: Router
    ) -> Generator[TestClient, None, None]:
        monkeypatch.setattr(settings, "proxy_api_key", SecretStr(DUMMY_PROXY_API_KEY))
        with TestClient(create_app(), base_url=LOOPBACK_BASE_URL) as test_client:
            yield test_client

    @pytest.mark.parametrize(
        "extra_headers",
        [{}, {"Authorization": "Bearer wrong-key"}, {"Authorization": DUMMY_PROXY_API_KEY}],
    )
    def test_missing_or_wrong_api_key_is_rejected(
        self, authed_client: TestClient, httpx2_mock: Router, extra_headers: dict[str, str]
    ) -> None:
        resp = authed_client.post(
            "/mcp", json=INITIALIZE_REQUEST, headers={**MCP_HEADERS, **extra_headers}
        )
        assert resp.status_code == 401
        _assert_nothing_forwarded(httpx2_mock)

    def test_correct_api_key_is_accepted(self, authed_client: TestClient) -> None:
        resp = authed_client.post(
            "/mcp",
            json=INITIALIZE_REQUEST,
            headers={**MCP_HEADERS, "Authorization": f"Bearer {DUMMY_PROXY_API_KEY}"},
        )
        assert resp.status_code == 200

    def test_health_does_not_require_api_key(self, authed_client: TestClient) -> None:
        resp = authed_client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "healthy"}


class TestRunProxyMcp:
    @pytest.fixture
    def uvicorn_run(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        mock = MagicMock()
        monkeypatch.setattr(proxy_mcp.uvicorn, "run", mock)
        return mock

    @pytest.mark.parametrize("host", ["0.0.0.0", "10.1.2.3", "::", "proxy.internal"])
    def test_non_loopback_without_auth_is_refused(self, uvicorn_run: MagicMock, host: str) -> None:
        result = CliRunner().invoke(run_proxy_mcp, ["--host", host])
        assert result.exit_code != 0
        assert "PROXY_API_KEY" in result.output
        uvicorn_run.assert_not_called()

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    def test_loopback_without_auth_is_allowed(self, uvicorn_run: MagicMock, host: str) -> None:
        result = CliRunner().invoke(run_proxy_mcp, ["--host", host])
        assert result.exit_code == 0, result.output
        uvicorn_run.assert_called_once()

    def test_non_loopback_with_api_key_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch, uvicorn_run: MagicMock
    ) -> None:
        monkeypatch.setattr(settings, "proxy_api_key", SecretStr(DUMMY_PROXY_API_KEY))
        result = CliRunner().invoke(run_proxy_mcp, ["--host", "0.0.0.0"])
        assert result.exit_code == 0, result.output
        uvicorn_run.assert_called_once()

    def test_non_loopback_with_explicit_insecure_opt_out_is_allowed(
        self, uvicorn_run: MagicMock
    ) -> None:
        result = CliRunner().invoke(
            run_proxy_mcp, ["--host", "0.0.0.0", "--insecure-allow-unauthenticated-non-loopback"]
        )
        assert result.exit_code == 0, result.output
        uvicorn_run.assert_called_once()


class TestSettingsValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"cors_allowed_origins": ["*"]},
            {"cors_allowed_origins": ["https://*.example"]},
            {"allowed_hosts": ["*"]},
            {"proxy_api_key": ""},
        ],
    )
    def test_rejects_wildcards_and_empty_api_key(self, kwargs: dict) -> None:
        with pytest.raises(ValidationError):
            Settings(**kwargs)

    def test_defaults_to_no_allowed_origins(self) -> None:
        assert Settings().cors_allowed_origins == []
