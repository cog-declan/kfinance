from typing import Any, Optional

from click.testing import CliRunner
import fastmcp
from fastmcp import FastMCP
import httpx2
import pytest
from respx import Router

from kfinance.client.kfinance import Client
from kfinance.integrations.local_mcp import local_mcp
from kfinance.integrations.local_mcp.local_mcp import (
    build_http_middleware,
    build_kfinance_mcp,
    check_bind_host_is_safe,
    is_loopback_host,
    run_mcp,
)


DUMMY_AUTH_TOKEN = "dummy-inbound-token"
SERVER_URL = "http://127.0.0.1:8000"


async def _request(
    app: Any,
    method: str,
    path: str,
    headers: Optional[dict[str, str]] = None,
    json: Optional[dict] = None,
) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=SERVER_URL
    ) as client:
        return await client.request(method, path, headers=headers, json=json)


def build_kfinance_mcp_without_tools(auth_token: Optional[str]) -> FastMCP:
    class _NoToolsClient:
        langchain_tools: list = []

    return build_kfinance_mcp(_NoToolsClient(), auth_token=auth_token)  # type: ignore[arg-type]


def _sse_app(
    auth_token: Optional[str] = None,
    allowed_hosts: tuple[str, ...] = (),
    allowed_origins: tuple[str, ...] = (),
) -> Any:
    mcp = build_kfinance_mcp_without_tools(auth_token)
    return mcp.http_app(
        transport="sse", middleware=build_http_middleware(allowed_hosts, allowed_origins)
    )


class TestHostOriginValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("transport", ["sse", "streamable-http"])
    async def test_dns_rebinding_host_rejected(self, transport: str) -> None:
        """A rebound attacker hostname in the Host header is rejected before reaching MCP."""
        mcp = build_kfinance_mcp_without_tools(auth_token=None)
        app = mcp.http_app(transport=transport, middleware=build_http_middleware())  # type: ignore[arg-type]
        path = "/sse" if transport == "sse" else "/mcp"
        resp = await _request(app, "GET", path, headers={"Host": "evil.example:8000"})
        assert resp.status_code == 421

    @pytest.mark.asyncio
    async def test_dns_rebinding_message_post_rejected(self) -> None:
        resp = await _request(
            _sse_app(),
            "POST",
            "/messages/?session_id=00000000000000000000000000000000",
            headers={"Host": "evil.example:8000", "Origin": "http://evil.example:8000"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert resp.status_code == 421

    @pytest.mark.asyncio
    async def test_cross_origin_request_rejected(self) -> None:
        resp = await _request(
            _sse_app(),
            "POST",
            "/messages/",
            headers={"Origin": "https://evil.example"},
            json={},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_loopback_request_reaches_endpoint(self) -> None:
        resp = await _request(_sse_app(), "POST", "/messages/", json={})
        # The SSE transport rejects the missing session id, proving the guard let it through.
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_explicitly_allowed_host_and_origin_accepted(self) -> None:
        resp = await _request(
            _sse_app(allowed_hosts=("mcp.internal",), allowed_origins=("https://app.internal",)),
            "POST",
            "/messages/",
            headers={"Host": "mcp.internal:8000", "Origin": "https://app.internal"},
            json={},
        )
        assert resp.status_code == 400


class TestInboundAuth:
    @pytest.mark.asyncio
    async def test_missing_token_rejected(self) -> None:
        resp = await _request(_sse_app(auth_token=DUMMY_AUTH_TOKEN), "POST", "/messages/", json={})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_token_rejected(self) -> None:
        resp = await _request(
            _sse_app(auth_token=DUMMY_AUTH_TOKEN),
            "POST",
            "/messages/",
            headers={"Authorization": "Bearer wrong-token"},
            json={},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_token_accepted(self) -> None:
        resp = await _request(
            _sse_app(auth_token=DUMMY_AUTH_TOKEN),
            "POST",
            "/messages/",
            headers={"Authorization": f"Bearer {DUMMY_AUTH_TOKEN}"},
            json={},
        )
        assert resp.status_code == 400


class TestBindHostSafety:
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]"])
    def test_loopback_hosts(self, host: str) -> None:
        assert is_loopback_host(host)
        check_bind_host_is_safe(host, auth_token=None, allow_unauthenticated_remote_access=False)

    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5", "example.com"])
    def test_non_loopback_without_auth_refused(self, host: str) -> None:
        with pytest.raises(Exception, match="Refusing to bind"):
            check_bind_host_is_safe(
                host, auth_token=None, allow_unauthenticated_remote_access=False
            )

    def test_non_loopback_with_auth_or_opt_out_allowed(self) -> None:
        check_bind_host_is_safe(
            "0.0.0.0", auth_token=DUMMY_AUTH_TOKEN, allow_unauthenticated_remote_access=False
        )
        check_bind_host_is_safe(
            "0.0.0.0", auth_token=None, allow_unauthenticated_remote_access=True
        )


class TestRunMcp:
    @pytest.fixture
    def captured_run(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        captured: dict[str, Any] = {}

        def fake_run(self: FastMCP, **kwargs: Any) -> None:
            captured["auth"] = self.auth
            captured.update(kwargs)

        monkeypatch.setattr(FastMCP, "run", fake_run)
        return captured

    @pytest.fixture
    def patched_client(
        self, monkeypatch: pytest.MonkeyPatch, mock_client: Client, httpx2_mock: Router
    ) -> None:
        httpx2_mock.get(f"{mock_client.kfinance_api_client.url_base}users/permissions").respond(
            json={"permissions": []}
        )
        monkeypatch.setattr(local_mcp, "Client", lambda **_: mock_client)

    @pytest.mark.parametrize("flag", ["--sse", "--streamable-http"])
    def test_http_transports_get_host_origin_guard(
        self, flag: str, captured_run: dict[str, Any], patched_client: None
    ) -> None:
        result = CliRunner().invoke(run_mcp, [flag, "--refresh-token", "dummy"])
        assert result.exit_code == 0, result.output
        middleware = captured_run["middleware"]
        assert [m.cls for m in middleware] == [m.cls for m in build_http_middleware()]
        assert captured_run["auth"] is None

    def test_auth_token_from_env_enables_inbound_auth(
        self, captured_run: dict[str, Any], patched_client: None
    ) -> None:
        result = CliRunner().invoke(
            run_mcp,
            ["--refresh-token", "dummy"],
            env={local_mcp.AUTH_TOKEN_ENV_VAR: DUMMY_AUTH_TOKEN},
        )
        assert result.exit_code == 0, result.output
        assert captured_run["auth"] is not None
        assert DUMMY_AUTH_TOKEN not in result.output

    def test_non_loopback_bind_without_auth_refused(
        self, monkeypatch: pytest.MonkeyPatch, captured_run: dict[str, Any]
    ) -> None:
        monkeypatch.setattr(fastmcp.settings, "host", "0.0.0.0")
        result = CliRunner().invoke(run_mcp, ["--refresh-token", "dummy"])
        assert result.exit_code != 0
        assert "Refusing to bind" in result.output
        assert captured_run == {}
