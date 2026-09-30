import pytest
from respx import Router

from kfinance.client.kfinance import Client


BASE_URL = "https://kfinance.kensho.com/api/v1"


class TestKfinanceHttpxClientUrls:
    @pytest.mark.asyncio
    async def test_relative_url_is_sent_to_base_host(
        self, mock_client: Client, httpx2_mock: Router
    ) -> None:
        route = httpx2_mock.get(f"{BASE_URL}/info/21719").respond(json={})
        await mock_client.httpx_client.get("/info/21719")
        assert route.call_count == 1
        assert route.calls.last.request.headers["Authorization"] == "Bearer foo"

    @pytest.mark.asyncio
    async def test_same_host_absolute_url_is_allowed(
        self, mock_client: Client, httpx2_mock: Router
    ) -> None:
        route = httpx2_mock.get(f"{BASE_URL}/info/21719").respond(json={})
        await mock_client.httpx_client.get(f"{BASE_URL}/info/21719")
        assert route.call_count == 1

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/steal",
            "//evil.example/steal",
            "http://kfinance.kensho.com/api/v1/info/1",
            "https://kfinance.kensho.com.evil.example/api/v1/info/1",
            "https://kfinance.kensho.com:8443/api/v1/info/1",
        ],
    )
    @pytest.mark.asyncio
    async def test_foreign_absolute_url_is_rejected(
        self, url: str, mock_client: Client, httpx2_mock: Router
    ) -> None:
        """httpx2_mock fails the test if any request (and so the bearer token) is sent."""
        with pytest.raises(ValueError, match="outside the configured kfinance host"):
            await mock_client.httpx_client.get(url)

    @pytest.mark.parametrize("url", ["/info/../admin", "/info/./1", "../admin"])
    @pytest.mark.asyncio
    async def test_dot_segments_are_rejected(
        self, url: str, mock_client: Client, httpx2_mock: Router
    ) -> None:
        with pytest.raises(ValueError, match="Dot segments"):
            await mock_client.httpx_client.get(url)

    @pytest.mark.parametrize(
        "tool_value, expected_path",
        [
            ("1?admin=true#frag", "/info/1%3Fadmin=true%23frag"),
            ("a b", "/info/a%20b"),
            ("%2e%2e", "/info/%252e%252e"),
        ],
    )
    @pytest.mark.asyncio
    async def test_tool_derived_segments_are_percent_encoded(
        self, tool_value: str, expected_path: str, mock_client: Client, httpx2_mock: Router
    ) -> None:
        route = httpx2_mock.get(f"{BASE_URL}{expected_path}").respond(json={})
        await mock_client.httpx_client.get(f"/info/{tool_value}")
        assert route.call_count == 1
        assert route.calls.last.request.url.query == b""
