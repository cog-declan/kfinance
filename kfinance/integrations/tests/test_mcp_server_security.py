import click
import pytest

from kfinance.integrations.mcp_server_security import (
    StaticBearerTokenVerifier,
    build_inbound_auth,
    check_network_exposure,
    is_loopback_host,
)


DUMMY_TOKEN = "dummy-inbound-token-0123456789abcdef"


@pytest.mark.parametrize(
    "host, expected",
    [
        pytest.param("127.0.0.1", True),
        pytest.param("127.0.0.2", True),
        pytest.param("localhost", True),
        pytest.param("::1", True),
        pytest.param("[::1]", True),
        pytest.param("0.0.0.0", False),
        pytest.param("::", False),
        pytest.param("10.0.0.5", False),
        pytest.param("mcp.example.com", False),
    ],
)
def test_is_loopback_host(host: str, expected: bool) -> None:
    assert is_loopback_host(host) is expected


class TestCheckNetworkExposure:
    def test_non_loopback_without_auth_raises(self) -> None:
        """
        GIVEN a non-loopback bind host
        WHEN no inbound auth is configured and there is no explicit opt-out
        THEN the server refuses to start.
        """
        with pytest.raises(click.UsageError, match="without inbound authentication"):
            check_network_exposure(
                host="0.0.0.0", auth_enabled=False, allow_unauthenticated_network_access=False
            )

    @pytest.mark.parametrize(
        "host, auth_enabled, opt_out",
        [
            pytest.param("127.0.0.1", False, False, id="loopback without auth"),
            pytest.param("0.0.0.0", True, False, id="non-loopback with auth"),
            pytest.param("0.0.0.0", False, True, id="non-loopback with explicit opt-out"),
        ],
    )
    def test_allowed(self, host: str, auth_enabled: bool, opt_out: bool) -> None:
        check_network_exposure(
            host=host, auth_enabled=auth_enabled, allow_unauthenticated_network_access=opt_out
        )


class TestStaticBearerTokenVerifier:
    def test_short_token_rejected(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            StaticBearerTokenVerifier("too-short")

    @pytest.mark.asyncio
    async def test_verify_token(self) -> None:
        verifier = StaticBearerTokenVerifier(DUMMY_TOKEN)
        assert await verifier.verify_token(DUMMY_TOKEN) is not None
        assert await verifier.verify_token(DUMMY_TOKEN + "x") is None
        assert await verifier.verify_token("") is None

    def test_build_inbound_auth_without_token(self) -> None:
        assert build_inbound_auth(None) is None
        assert build_inbound_auth("") is None
