from typing import Literal, Optional

import click
import fastmcp
from fastmcp import FastMCP
from fastmcp.tools import FunctionTool
from fastmcp.utilities.logging import get_logger
from langchain_core.utils.function_calling import convert_to_openai_tool

from kfinance.client.kfinance import Client
from kfinance.integrations.mcp_server_security import (
    ALLOW_UNAUTHENTICATED_NETWORK_ACCESS_FLAG,
    INBOUND_AUTH_TOKEN_ENV_VAR,
    build_host_origin_guard,
    build_inbound_auth,
    check_network_exposure,
)
from kfinance.integrations.tool_calling.tool_calling_models import KfinanceTool


logger = get_logger(__name__)


def build_mcp_tool_from_kfinance_tool(kfinance_tool: KfinanceTool) -> FunctionTool:
    """Build an MCP FunctionTool from a langchain KfinanceTool."""

    return FunctionTool(
        name=kfinance_tool.name,
        description=kfinance_tool.description,
        # MCP expects a JSON schema for tool params, which we
        # can generate similar to how langchain generates openai json schemas.
        parameters=convert_to_openai_tool(kfinance_tool)["function"]["parameters"],
        # The langchain runner internally validates input arguments via the args_schema.
        # When running with mcp, we need to reproduce that validation ourselves in
        # arun_without_langchain (which then calls _arun).
        # If we pass in the underlying _arun method directly, mcp generates a schema from
        # the _arun type hints but bypasses our internal validation. This causes errors,
        # for example with integer literals, which our args models allow but the
        # mcp-internal validation disallows.
        # Use the async version to avoid event loop conflicts.
        # fn=kfinance_tool.arun_without_langchain,
        fn=kfinance_tool.arun_without_langchain,
    )


def build_mcp_server(kfinance_client: Client, auth_token: Optional[str] = None) -> FastMCP:
    """Build a FastMCP server exposing the tools the kfinance client has permission to use.

    If auth_token is set, HTTP clients must send it as `Authorization: Bearer <token>`.
    """
    kfinance_mcp: FastMCP = FastMCP("Kfinance", auth=build_inbound_auth(auth_token))
    for langchain_tool in kfinance_client.langchain_tools:
        logger.info("Adding %s to server", langchain_tool.name)
        kfinance_mcp.add_tool(build_mcp_tool_from_kfinance_tool(langchain_tool))
    return kfinance_mcp


@click.command()
@click.option("--stdio", "-s", "transport", flag_value="stdio", help="Use stdio transport")
@click.option(
    "--sse", "transport", flag_value="sse", default=True, help="Use SSE transport (default)"
)
@click.option(
    "--streamable-http",
    "transport",
    flag_value="streamable-http",
    help="Use streamable HTTP transport",
)
@click.option(
    "--host", default=None, help="Host to bind to for HTTP transports [default: 127.0.0.1]"
)
@click.option(
    "--port", default=None, type=int, help="Port to bind to for HTTP transports [default: 8000]"
)
@click.option(
    "--auth-token",
    envvar=INBOUND_AUTH_TOKEN_ENV_VAR,
    show_envvar=True,
    default=None,
    help="Pre-shared token HTTP clients must send as `Authorization: Bearer <token>`. "
    "Required when binding to a non-loopback host.",
)
@click.option(
    "--allowed-host",
    "allowed_hosts",
    multiple=True,
    help="Additional Host header value to accept (loopback and the bind address are always allowed).",
)
@click.option(
    "--allowed-origin",
    "allowed_origins",
    multiple=True,
    help="Browser Origin to accept (loopback origins are always allowed).",
)
@click.option(
    ALLOW_UNAUTHENTICATED_NETWORK_ACCESS_FLAG,
    "allow_unauthenticated_network_access",
    is_flag=True,
    default=False,
    help="Allow binding to a non-loopback host without inbound auth. Anyone who can reach "
    "the server can then act with your kfinance credentials.",
)
@click.option("--refresh-token", required=False)
@click.option("--client-id", required=False)
@click.option("--private-key", required=False)
def run_mcp(
    transport: Literal["stdio", "sse", "streamable-http"],
    host: Optional[str] = None,
    port: Optional[int] = None,
    auth_token: Optional[str] = None,
    allowed_hosts: tuple[str, ...] = (),
    allowed_origins: tuple[str, ...] = (),
    allow_unauthenticated_network_access: bool = False,
    refresh_token: Optional[str] = None,
    client_id: Optional[str] = None,
    private_key: Optional[str] = None,
) -> None:
    """Run the Kfinance MCP server with specified configuration.

    This function initializes and starts an MCP server that exposes Kfinance
    tools. The server supports multiple authentication methods and
    transport protocols to accommodate different deployment scenarios.

    Authentication Methods (in order of precedence):
    1. Refresh Token: Uses an existing refresh token for authentication
    2. Key Pair: Uses client ID and private key for authentication
    3. Browser: Falls back to browser-based authentication flow

    HTTP transports validate Host and Origin headers and refuse to bind to a non-loopback
    host without an inbound auth token unless explicitly opted out.

    :param transport: Transport protocol (stdio, sse, or streamable-http).
    :type transport: Literal["stdio", "sse", "streamable-http"]
    :param host: Host to bind to for HTTP transports.
    :type host: str
    :param port: Port to bind to for HTTP transports.
    :type port: int
    :param auth_token: Pre-shared bearer token required from HTTP clients.
    :type auth_token: str
    :param allowed_hosts: Additional accepted Host header values.
    :type allowed_hosts: tuple[str, ...]
    :param allowed_origins: Accepted browser origins.
    :type allowed_origins: tuple[str, ...]
    :param allow_unauthenticated_network_access: Allow a non-loopback bind without auth.
    :type allow_unauthenticated_network_access: bool
    :param refresh_token: OAuth refresh token for authentication
    :type refresh_token: str
    :param client_id: Client id for key-pair authentication
    :type client_id: str
    :param private_key: Private key for key-pair authentication.
    :type private_key: str
    """
    logger.info("Server will run with %s transport", transport)
    if transport != "stdio":
        host = host if host is not None else fastmcp.settings.host
        port = port if port is not None else fastmcp.settings.port
        check_network_exposure(
            host=host,
            auth_enabled=bool(auth_token),
            allow_unauthenticated_network_access=allow_unauthenticated_network_access,
        )
        # Validate the token before prompting for kfinance credentials.
        try:
            build_inbound_auth(auth_token)
        except ValueError as e:
            raise click.BadParameter(str(e), param_hint="--auth-token") from None
    elif auth_token:
        logger.info("Ignoring the inbound auth token because stdio transport has no HTTP clients")
        auth_token = None

    if refresh_token:
        logger.info("The client will be authenticated using a refresh token")
        kfinance_client = Client(refresh_token=refresh_token)
    elif client_id and private_key:
        logger.info("The client will be authenticated using a key pair")
        kfinance_client = Client(client_id=client_id, private_key=private_key)
    else:
        logger.info("The client will be authenticated using a browser")
        kfinance_client = Client()

    kfinance_mcp = build_mcp_server(kfinance_client=kfinance_client, auth_token=auth_token)

    logger.info("Server starting")
    if transport == "stdio":
        kfinance_mcp.run(transport=transport)
    else:
        kfinance_mcp.run(
            transport=transport,
            host=host,
            port=port,
            middleware=[build_host_origin_guard(allowed_hosts, allowed_origins)],
        )


if __name__ == "__main__":
    run_mcp()
