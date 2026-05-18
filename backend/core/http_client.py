from __future__ import annotations

from typing import Any

import httpx

from .proxy import ProxyConnectionError, proxy_config
from .rate_limiter import rate_limiter


async def _before_request(request: httpx.Request) -> None:
    """Event hook: enforce per-domain rate limit and rotate UA for Tor."""
    await rate_limiter.acquire(request.url.host)
    if proxy_config.is_tor:
        request.headers["user-agent"] = proxy_config.random_ua()


def build_client(**kwargs: Any) -> "_MailAccessClient":
    """
    Return a configured AsyncClient with rate limiting and optional proxy.

    All keyword arguments are forwarded to httpx.AsyncClient.
    Default timeout is 10 s when not specified by the caller.

    When PROXY_ENABLED=true, the proxy URL is applied to all requests.
    When the proxy is unreachable a ProxyConnectionError is raised with a hint
    to check PROXY_URL in .env.
    """
    kwargs.setdefault("timeout", 10.0)
    event_hooks: dict[str, list[Any]] = {"request": [_before_request]}

    proxy_url = proxy_config.proxy_url()
    if proxy_url:
        kwargs["proxy"] = proxy_url

    return _MailAccessClient(event_hooks=event_hooks, **kwargs)


class _MailAccessClient(httpx.AsyncClient):
    """AsyncClient subclass that converts proxy errors into ProxyConnectionError."""

    async def send(self, request: httpx.Request, **kwargs: Any) -> httpx.Response:
        try:
            return await super().send(request, **kwargs)
        except (httpx.ProxyError, httpx.ConnectError) as exc:
            if proxy_config.is_enabled:
                from ..config import settings

                raise ProxyConnectionError(
                    f"Proxy connection failed ({settings.proxy_url!r}). "
                    "Check PROXY_URL in your .env file."
                ) from exc
            raise
