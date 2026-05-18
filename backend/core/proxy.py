from __future__ import annotations

import random
from urllib.parse import urlparse

from ..config import settings

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

_TOR_URL = "socks5://127.0.0.1:9050"

_VALID_SCHEMES = {"socks5", "socks4", "http", "https"}


class ProxyConnectionError(Exception):
    pass


class ProxyConfig:
    def __init__(self) -> None:
        self._enabled: bool = settings.proxy_enabled
        self._url: str | None = settings.proxy_url
        if self._enabled and self._url:
            scheme = urlparse(self._url).scheme
            if scheme not in _VALID_SCHEMES:
                raise ValueError(
                    f"Unsupported proxy scheme {scheme!r} in PROXY_URL. "
                    f"Supported schemes: {', '.join(sorted(_VALID_SCHEMES))}"
                )

    @property
    def is_enabled(self) -> bool:
        return self._enabled and bool(self._url)

    @property
    def is_tor(self) -> bool:
        return self.is_enabled and self._url == _TOR_URL

    def proxy_url(self) -> str | None:
        return self._url if self.is_enabled else None

    def random_ua(self) -> str:
        return random.choice(_UA_POOL)  # noqa: S311


proxy_config = ProxyConfig()
