import click
from fastmcp import Client
from fastmcp.server.providers.proxy import FastMCPProxy, ProxyClient
from fastmcp.utilities.logging import get_logger
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
import uvicorn

from kfinance.integrations.mcp_server_security import (
    ALLOW_UNAUTHENTICATED_NETWORK_ACCESS_FLAG,
    build_inbound_auth,
    check_network_exposure,
)
from kfinance.integrations.proxy_mcp.auth import (
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

    inbound_token = settings.inbound_auth_token
    return FastMCPProxy(
        client_factory=client_factory,
        name="Kfinance Proxy",
        auth=build_inbound_auth(inbound_token.get_secret_value() if inbound_token else None),
    )


async def health(request: Request) -> JSONResponse:
    """Health check stub. Does not verify backend connectivity or token validity."""
    return JSONResponse({"status": "healthy"})


def create_app() -> Starlette:
    """Create the ASGI application wrapping the MCP proxy.

    /mcp requires the inbound bearer token (if configured) and validates Host and Origin
    headers. CORS only allows the configured origins.
    """
    proxy = build_proxy()
    mcp_http_app = proxy.http_app(
        path="/mcp",
        transport="streamable-http",
        host_origin_protection=True,
        allowed_hosts=settings.allowed_hosts,
        allowed_origins=settings.cors_allowed_origins,
    )

    return Starlette(
        routes=[Route("/health", health, methods=["GET"]), Mount("/", app=mcp_http_app)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=settings.cors_allowed_origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        ],
        lifespan=mcp_http_app.lifespan,
    )


@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option(
    ALLOW_UNAUTHENTICATED_NETWORK_ACCESS_FLAG,
    "allow_unauthenticated_network_access",
    is_flag=True,
    default=False,
    help="Allow binding to a non-loopback host without INBOUND_AUTH_TOKEN. Anyone who can "
    "reach the proxy can then act with its kfinance credentials.",
)
def run_proxy_mcp(host: str, port: int, allow_unauthenticated_network_access: bool) -> None:
    """Run the proxy MCP server."""
    check_network_exposure(
        host=host,
        auth_enabled=bool(
            settings.inbound_auth_token and settings.inbound_auth_token.get_secret_value()
        ),
        allow_unauthenticated_network_access=allow_unauthenticated_network_access,
    )
    app = create_app()

    logger.info("Proxy server starting on %s:%s", host, port)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_proxy_mcp()
