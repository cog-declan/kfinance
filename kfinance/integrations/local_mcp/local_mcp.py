import hmac
from ipaddress import ip_address
from typing import Literal, Optional, Sequence

import click
import fastmcp
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.http import HostOriginGuardMiddleware
from fastmcp.tools import FunctionTool
from fastmcp.utilities.logging import get_logger
from langchain_core.utils.function_calling import convert_to_openai_tool
from starlette.middleware import Middleware

from kfinance.client.kfinance import Client
from kfinance.integrations.tool_calling.tool_calling_models import KfinanceTool


logger = get_logger(__name__)

AUTH_TOKEN_ENV_VAR = "KFINANCE_MCP_AUTH_TOKEN"


class StaticBearerTokenVerifier(TokenVerifier):
    """Accept requests whose bearer token matches a single shared secret."""

    def __init__(self, token: str):
        """Initialize with the shared secret that clients must present."""
        super().__init__()
        self._token = token

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an access token if the bearer token matches the shared secret."""
        if not hmac.compare_digest(token.encode(), self._token.encode()):
            return None
        return AccessToken(token=token, client_id="kfinance-local-mcp", scopes=[])


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


def build_http_middleware(
    allowed_hosts: Sequence[str] = (), allowed_origins: Sequence[str] = ()
) -> list[Middleware]:
    """Build middleware that rejects requests with an unexpected Host or Origin header.

    Loopback hosts and same-origin/loopback origins are always allowed. Any other
    host or browser origin must be listed explicitly. This blocks DNS-rebinding and
    cross-origin browser requests from reaching the MCP endpoints.
    """
    return [
        Middleware(
            HostOriginGuardMiddleware,
            allowed_hosts=list(allowed_hosts),
            allowed_origins=list(allowed_origins),
            mode="strict",
        )
    ]


def is_loopback_host(host: str) -> bool:
    """Return True if host is localhost or a loopback IP address."""
    host = host.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def check_bind_host_is_safe(
    host: str, auth_token: Optional[str], allow_unauthenticated_remote_access: bool
) -> None:
    """Refuse to serve unauthenticated on a non-loopback address unless explicitly opted out."""
    if is_loopback_host(host) or auth_token:
        return
    if allow_unauthenticated_remote_access:
        logger.warning(
            "Serving kfinance tools WITHOUT inbound authentication on non-loopback host %s. "
            "Anyone who can reach this address can call tools with your kfinance credentials.",
            host,
        )
        return
    raise click.UsageError(
        f"Refusing to bind the MCP server to non-loopback host {host!r} without inbound "
        f"authentication. Set {AUTH_TOKEN_ENV_VAR} (or --auth-token), or pass "
        "--dangerously-allow-unauthenticated-remote-access."
    )


def build_kfinance_mcp(kfinance_client: Client, auth_token: Optional[str] = None) -> FastMCP:
    """Build a FastMCP server exposing the client's permitted kfinance tools."""
    auth = StaticBearerTokenVerifier(auth_token) if auth_token else None
    kfinance_mcp: FastMCP = FastMCP("Kfinance", auth=auth)
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
@click.option("--refresh-token", required=False)
@click.option("--client-id", required=False)
@click.option("--private-key", required=False)
@click.option(
    "--auth-token",
    envvar=AUTH_TOKEN_ENV_VAR,
    required=False,
    help=f"Bearer token that SSE/HTTP clients must send (env: {AUTH_TOKEN_ENV_VAR}).",
)
@click.option(
    "--allowed-host",
    "allowed_hosts",
    multiple=True,
    help="Additional Host header value accepted by SSE/HTTP transports (repeatable).",
)
@click.option(
    "--allowed-origin",
    "allowed_origins",
    multiple=True,
    help="Additional browser Origin accepted by SSE/HTTP transports (repeatable).",
)
@click.option(
    "--dangerously-allow-unauthenticated-remote-access",
    "allow_unauthenticated_remote_access",
    is_flag=True,
    default=False,
    help="Allow serving without --auth-token on a non-loopback host. Not recommended.",
)
def run_mcp(
    transport: Literal["stdio", "sse", "streamable-http"],
    refresh_token: Optional[str] = None,
    client_id: Optional[str] = None,
    private_key: Optional[str] = None,
    auth_token: Optional[str] = None,
    allowed_hosts: Sequence[str] = (),
    allowed_origins: Sequence[str] = (),
    allow_unauthenticated_remote_access: bool = False,
) -> None:
    """Run the Kfinance MCP server with specified configuration.

    This function initializes and starts an MCP server that exposes Kfinance
    tools. The server supports multiple authentication methods and
    transport protocols to accommodate different deployment scenarios.

    Authentication Methods (in order of precedence):
    1. Refresh Token: Uses an existing refresh token for authentication
    2. Key Pair: Uses client ID and private key for authentication
    3. Browser: Falls back to browser-based authentication flow

    The SSE and streamable HTTP transports bind to 127.0.0.1 by default (FASTMCP_HOST)
    and reject requests whose Host or Origin header is not loopback, same-origin or
    explicitly allowed. Binding to a non-loopback host requires an inbound auth token.

    :param transport: Transport protocol (stdio, sse, or streamable-http).
    :type transport: Literal["stdio", "sse", "streamable-http"]
    :param refresh_token: OAuth refresh token for authentication
    :type refresh_token: str
    :param client_id: Client id for key-pair authentication
    :type client_id: str
    :param private_key: Private key for key-pair authentication.
    :type private_key: str
    :param auth_token: Bearer token required from SSE/HTTP clients.
    :type auth_token: str
    :param allowed_hosts: Additional accepted Host header values.
    :type allowed_hosts: Sequence[str]
    :param allowed_origins: Additional accepted browser origins.
    :type allowed_origins: Sequence[str]
    :param allow_unauthenticated_remote_access: Allow unauthenticated non-loopback binds.
    :type allow_unauthenticated_remote_access: bool
    """
    logger.info("Server will run with %s transport", transport)
    if transport != "stdio":
        check_bind_host_is_safe(
            host=fastmcp.settings.host,
            auth_token=auth_token,
            allow_unauthenticated_remote_access=allow_unauthenticated_remote_access,
        )

    if refresh_token:
        logger.info("The client will be authenticated using a refresh token")
        kfinance_client = Client(refresh_token=refresh_token)
    elif client_id and private_key:
        logger.info("The client will be authenticated using a key pair")
        kfinance_client = Client(client_id=client_id, private_key=private_key)
    else:
        logger.info("The client will be authenticated using a browser")
        kfinance_client = Client()

    kfinance_mcp = build_kfinance_mcp(
        kfinance_client, auth_token=auth_token if transport != "stdio" else None
    )

    logger.info("Server starting")
    if transport == "stdio":
        kfinance_mcp.run(transport=transport)
    else:
        kfinance_mcp.run(
            transport=transport,
            middleware=build_http_middleware(allowed_hosts, allowed_origins),
        )


if __name__ == "__main__":
    run_mcp()
