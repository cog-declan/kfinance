from ipaddress import ip_address

import click
from fastmcp import Client
from fastmcp.server.http import StarletteWithLifespan
from fastmcp.server.providers.proxy import FastMCPProxy, ProxyClient
from fastmcp.utilities.logging import get_logger
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import uvicorn

from kfinance.integrations.proxy_mcp.auth import (
    ApiKeyTokenVerifier,
    Cache,
    ClientAccessToken,
    ClientAccessTokenDispenser,
    DynamicBearerAuth,
    PrivateKeyBasedAccessTokenDispenser,
    RefreshTokenDispenser,
)
from kfinance.integrations.proxy_mcp.settings import settings


logger = get_logger(__name__)


def _build_dispenser() -> ClientAccessTokenDispenser:
    """Build the appropriate token dispenser based on settings."""
    cache: Cache[ClientAccessToken] = Cache()

    if settings.auth.client_id and settings.auth.private_key:
        return PrivateKeyBasedAccessTokenDispenser(
            client_id=settings.auth.client_id,
            private_key=settings.auth.private_key,
            cache=cache,
            access_token_cache_key="proxy_mcp_token",
            okta_host=settings.auth.okta_host,
        )
    elif settings.auth.refresh_token:
        return RefreshTokenDispenser(
            refresh_token=settings.auth.refresh_token,
            refresh_url=settings.auth.refresh_url,
            cache=cache,
            access_token_cache_key="proxy_mcp_token",
        )
    else:
        raise ValueError(
            "Either AUTH_CLIENT_ID and AUTH_PRIVATE_KEY, or AUTH_REFRESH_TOKEN must be set"
        )


def build_proxy() -> FastMCPProxy:
    """Build a FastMCPProxy that injects a Bearer token into every request to the backend."""
    logger.info("Proxy will forward to %s", settings.backend_url)

    dispenser = _build_dispenser()
    auth = DynamicBearerAuth(dispenser)

    base_client: ProxyClient = ProxyClient(settings.backend_url, auth=auth)

    def client_factory() -> Client:
        return base_client.new()

    inbound_auth = (
        ApiKeyTokenVerifier(settings.proxy_api_key.get_secret_value())
        if settings.proxy_api_key is not None
        else None
    )
    proxy = FastMCPProxy(client_factory=client_factory, name="Kfinance Proxy", auth=inbound_auth)

    @proxy.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "healthy"})

    return proxy


def create_app() -> StarletteWithLifespan:
    """Create the ASGI application wrapping the MCP proxy.

    Host and Origin headers are validated on every request to block DNS rebinding, and CORS
    only admits origins listed in CORS_ALLOWED_ORIGINS (none by default).
    """
    proxy = build_proxy()
    return proxy.http_app(
        path="/mcp",
        transport="streamable-http",
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=settings.cors_allowed_origins,
                allow_credentials=False,
                allow_methods=["GET", "POST", "DELETE"],
                allow_headers=[
                    "Authorization",
                    "Content-Type",
                    "Last-Event-ID",
                    "Mcp-Protocol-Version",
                    "Mcp-Session-Id",
                ],
                expose_headers=["Mcp-Session-Id"],
            )
        ],
        host_origin_protection=True,
        allowed_hosts=settings.allowed_hosts,
        allowed_origins=settings.cors_allowed_origins,
    )


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option(
    "--insecure-allow-unauthenticated-non-loopback",
    is_flag=True,
    default=False,
    help=(
        "Allow binding to a non-loopback address without PROXY_API_KEY. Anyone who can reach "
        "the port can use the proxy with the operator's credentials. Only use behind an "
        "authenticating gateway."
    ),
)
def run_proxy_mcp(host: str, port: int, insecure_allow_unauthenticated_non_loopback: bool) -> None:
    """Run the proxy MCP server."""
    if not _is_loopback_host(host) and settings.proxy_api_key is None:
        if not insecure_allow_unauthenticated_non_loopback:
            raise click.UsageError(
                f"Refusing to bind to non-loopback host {host!r} without inbound authentication. "
                "Set PROXY_API_KEY, or pass --insecure-allow-unauthenticated-non-loopback if the "
                "proxy is fronted by an authenticating gateway."
            )
        logger.warning(
            "INSECURE: proxy is bound to %s without inbound authentication; any client that can "
            "reach it can use the operator's kfinance credentials",
            host,
        )

    app = create_app()

    logger.info("Proxy server starting on %s:%s", host, port)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_proxy_mcp()
