from typing import Any
from unittest.mock import patch

from click.testing import CliRunner
from fastmcp import Client as FastMCPClient
from fastmcp.exceptions import ToolError
import httpx2
import pytest
from respx import Router

from kfinance.client.kfinance import Client
from kfinance.client.permission_models import Permission
from kfinance.integrations.local_mcp.local_mcp import build_mcp_server, run_mcp
from kfinance.integrations.mcp_server_security import build_host_origin_guard


DUMMY_TOKEN = "dummy-inbound-token-0123456789abcdef"
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


class TestPerInvocationPermissions:
    @pytest.mark.asyncio
    async def test_tool_call_rejected_after_permission_revoked(
        self, mock_client: Client, httpx2_mock: Router
    ) -> None:
        """
        GIVEN an MCP server that registered a tool while the user held its permission
        WHEN the permission is revoked and the tool is called through MCP
        THEN the call fails without any request to the kfinance API.
        """
        mock_client.kfinance_api_client._user_permissions = {Permission.RelationshipPermission}  # noqa: SLF001
        server = build_mcp_server(kfinance_client=mock_client)

        async with FastMCPClient(server) as mcp_client:
            tool_names = {t.name for t in await mcp_client.list_tools()}
            assert "get_business_relationship_from_identifiers" in tool_names

            mock_client.kfinance_api_client._user_permissions = set()  # noqa: SLF001
            with pytest.raises(ToolError, match="does not have the permissions"):
                await mcp_client.call_tool(
                    "get_business_relationship_from_identifiers",
                    {"identifiers": ["SPGI"], "business_relationship": "supplier"},
                )
        assert not any(route.called for route in httpx2_mock.routes)


class TestInboundHttpProtection:
    async def _post(self, mock_client: Client, headers: dict[str, str]) -> httpx2.Response:
        mock_client.kfinance_api_client._user_permissions = set()  # noqa: SLF001
        server = build_mcp_server(kfinance_client=mock_client, auth_token=DUMMY_TOKEN)
        app = server.http_app(transport="streamable-http", middleware=[build_host_origin_guard()])
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
            ) as client:
                return await client.post("/mcp", json=INITIALIZE_REQUEST, headers=headers)

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
            pytest.param({"Authorization": f"Bearer {DUMMY_TOKEN}"}, 200, id="valid token"),
        ],
    )
    async def test_inbound_requests(
        self,
        mock_client: Client,
        extra_headers: dict[str, str],
        expected_status: int,
    ) -> None:
        resp = await self._post(mock_client, {**MCP_HEADERS, **extra_headers})
        assert resp.status_code == expected_status


class TestRunMcpCli:
    @pytest.mark.parametrize("transport_flag", ["--sse", "--streamable-http"])
    def test_non_loopback_without_auth_refuses_to_start(self, transport_flag: str) -> None:
        with (
            patch("kfinance.integrations.local_mcp.local_mcp.Client") as client_cls,
            patch("fastmcp.FastMCP.run") as run,
        ):
            result = CliRunner().invoke(
                run_mcp, [transport_flag, "--host", "0.0.0.0", "--refresh-token", "dummy"]
            )
        assert result.exit_code == 2
        assert "without inbound authentication" in result.output
        client_cls.assert_not_called()
        run.assert_not_called()

    @pytest.mark.parametrize(
        "extra_args, env",
        [
            pytest.param([], {"KFINANCE_MCP_AUTH_TOKEN": DUMMY_TOKEN}, id="auth token via env"),
            pytest.param(
                ["--dangerously-allow-unauthenticated-network-access"], {}, id="explicit opt-out"
            ),
        ],
    )
    def test_non_loopback_allowed(self, extra_args: list[str], env: dict[str, str]) -> None:
        with (
            patch("kfinance.integrations.local_mcp.local_mcp.Client") as client_cls,
            patch("fastmcp.FastMCP.run") as run,
        ):
            client_cls.return_value.langchain_tools = []
            result = CliRunner().invoke(
                run_mcp,
                ["--sse", "--host", "0.0.0.0", "--refresh-token", "dummy", *extra_args],
                env=env,
            )
        assert result.exit_code == 0, result.output
        run_kwargs: dict[str, Any] = run.call_args.kwargs
        assert run_kwargs["host"] == "0.0.0.0"
        assert run_kwargs["middleware"]

    def test_short_auth_token_rejected(self) -> None:
        with patch("kfinance.integrations.local_mcp.local_mcp.Client") as client_cls:
            result = CliRunner().invoke(
                run_mcp, ["--sse", "--auth-token", "short", "--refresh-token", "dummy"]
            )
        assert result.exit_code == 2
        assert "at least 32 characters" in result.output
        client_cls.assert_not_called()
