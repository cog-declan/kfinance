"""Inbound request protection shared by the kfinance MCP servers."""

import hmac
from ipaddress import ip_address
from typing import Sequence

import click
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.http import HostOriginGuardMiddleware
from fastmcp.utilities.logging import get_logger
from starlette.middleware import Middleware


logger = get_logger(__name__)

MIN_INBOUND_AUTH_TOKEN_LENGTH = 32
INBOUND_AUTH_TOKEN_ENV_VAR = "KFINANCE_MCP_AUTH_TOKEN"
ALLOW_UNAUTHENTICATED_NETWORK_ACCESS_FLAG = "--dangerously-allow-unauthenticated-network-access"


class StaticBearerTokenVerifier(TokenVerifier):
    """Accept requests whose `Authorization: Bearer <token>` matches a pre-shared secret."""

    def __init__(self, token: str) -> None:
        """Initialize with the pre-shared token."""
        if len(token) < MIN_INBOUND_AUTH_TOKEN_LENGTH:
            raise ValueError(
                f"The inbound auth token must be at least {MIN_INBOUND_AUTH_TOKEN_LENGTH} "
                "characters long. Generate one with "
                '`python -c "import secrets; print(secrets.token_urlsafe(32))"`.'
            )
        super().__init__()
        self._token = token.encode()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an AccessToken if the token matches the pre-shared secret (constant time)."""
        if hmac.compare_digest(token.encode(), self._token):
            return AccessToken(token=token, client_id="kfinance-mcp-client", scopes=[])
        return None


def build_inbound_auth(token: str | None) -> StaticBearerTokenVerifier | None:
    """Return a verifier for the pre-shared inbound token, or None if no token is set."""
    if not token:
        return None
    return StaticBearerTokenVerifier(token)


def is_loopback_host(host: str) -> bool:
    """Return True if the bind host only accepts connections from the local machine."""
    host = host.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def check_network_exposure(
    host: str, auth_enabled: bool, allow_unauthenticated_network_access: bool
) -> None:
    """Refuse to bind a non-loopback address without inbound auth unless explicitly opted out."""
    if auth_enabled or is_loopback_host(host):
        return
    if allow_unauthenticated_network_access:
        logger.warning(
            "SECURITY WARNING: serving on %s without inbound authentication. Anyone who can "
            "reach this address can call every tool with your kfinance credentials.",
            host,
        )
        return
    raise click.UsageError(
        f"Refusing to bind to non-loopback host {host!r} without inbound authentication. "
        f"Set {INBOUND_AUTH_TOKEN_ENV_VAR}, bind to 127.0.0.1, or pass "
        f"{ALLOW_UNAUTHENTICATED_NETWORK_ACCESS_FLAG} if network-level controls restrict access."
    )


def build_host_origin_guard(
    allowed_hosts: Sequence[str] = (), allowed_origins: Sequence[str] = ()
) -> Middleware:
    """Build middleware that rejects unexpected Host and Origin headers (DNS rebinding).

    Loopback hosts and the bind address are always allowed as Host values. Browser origins
    other than loopback and same-origin are rejected unless listed in allowed_origins.
    """
    return Middleware(
        HostOriginGuardMiddleware,
        allowed_hosts=list(allowed_hosts),
        allowed_origins=list(allowed_origins),
        mode="strict",
    )
