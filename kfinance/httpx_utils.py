import asyncio
import atexit
from contextlib import contextmanager
from contextvars import ContextVar
from queue import Queue
from typing import Any, Generator
from urllib.parse import quote, urlsplit

import httpx2

from kfinance.client.fetch import KFinanceApiClient


# Context variable for tracking endpoint URLs across async contexts
# RFC 3986 pchar minus "%", so tool-derived values cannot smuggle pre-encoded
# separators or dot segments into the request path.
_SAFE_PATH_SEGMENT_CHARS = "-._~!$&'()*+,;=:@"

_endpoint_tracker_queue: ContextVar[Queue[str] | None] = ContextVar(
    "endpoint_tracker_queue", default=None
)


class KfinanceBearerAuth(httpx2.Auth):
    def __init__(self, api_client: KFinanceApiClient) -> None:
        """"""
        self._api_client = api_client

    def auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response, None]:
        """Inject access token into auth header"""
        request.headers["Authorization"] = f"Bearer {self._api_client.access_token}"
        yield request


class KfinanceHttpxClient(httpx2.AsyncClient):
    """httpx2.AsyncClient subclass that automatically prefixes URLs with a base URL and includes endpoint tracking."""

    def __init__(self, api_client: KFinanceApiClient) -> None:
        """"""
        self._kfinance_base_url: str = f"{api_client.api_host}/api/v1"

        super().__init__(auth=KfinanceBearerAuth(api_client=api_client))

        # Auto-register cleanup on exit
        atexit.register(self._cleanup_on_exit)

    @contextmanager
    def endpoint_tracker(self) -> Generator[Queue[str], None, None]:
        """Context manager to track endpoint URLs accessed during execution.

        This is safe for concurrent async operations as it uses contextvars
        to ensure each async context gets its own tracking queue.

        Usage:
            with httpx_client.endpoint_tracker() as queue:
                # Make requests
                await httpx_client.get("some/endpoint")
                # After requests, dequeue URLs
                endpoint_urls = []
                while not queue.empty():
                    endpoint_urls.append(queue.get())
        """
        queue = Queue[str]()
        token = _endpoint_tracker_queue.set(queue)
        try:
            yield queue
        finally:
            _endpoint_tracker_queue.reset(token)

    def _cleanup_on_exit(self) -> None:
        """Clean up the httpx client on process exit."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.aclose())
            else:
                asyncio.run(self.aclose())
        except:  # noqa:E722
            pass  # Process is shutting down

    def _build_url(self, url: str) -> str:
        """Build the full URL by prepending base_url to relative URLs.

        Absolute URLs must point at the configured kfinance host. Each segment of a
        relative path is percent-encoded and dot segments are rejected so that
        tool-derived values cannot change the host, path, or query of the request.
        """
        parsed = urlsplit(url)
        if parsed.scheme or parsed.netloc:
            base = urlsplit(self._kfinance_base_url)
            if (
                parsed.scheme.lower() != base.scheme.lower()
                or parsed.hostname != base.hostname
                or parsed.port != base.port
            ):
                raise ValueError("Refusing to send a request outside the configured kfinance host.")
            return url
        segments = url.lstrip("/").split("/")
        if any(segment in (".", "..") for segment in segments):
            raise ValueError("Dot segments are not allowed in kfinance request paths.")
        path = "/".join(quote(segment, safe=_SAFE_PATH_SEGMENT_CHARS) for segment in segments)
        return f"{self._kfinance_base_url}/{path}"

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx2.Response:  # type: ignore[override]
        """Override request to prepend base_url to relative URLs and track endpoints."""
        full_url = self._build_url(url)

        # Track endpoint if tracking is active in the current async context
        queue = _endpoint_tracker_queue.get(None)
        if queue is not None:
            queue.put(full_url)

        return await super().request(method=method, url=full_url, **kwargs)
