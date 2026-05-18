from __future__ import annotations

import asyncio
import time
from collections import defaultdict

from ..config import settings


class DomainRateLimiter:
    """
    Async per-domain token-bucket rate limiter (one token per window, no burst).

    acquire(domain) blocks until the configured window has elapsed since the last
    call for that domain, then returns.  Zero overhead when RATE_LIMIT_ENABLED=false.

    Usage::

        await rate_limiter.acquire("haveibeenpwned.com")
        response = await client.get(url)
    """

    def __init__(self) -> None:
        self._enabled: bool = settings.rate_limit_enabled
        default_s = settings.request_delay_ms / 1000.0
        self._default: float = default_s
        # Per-domain overrides: RATE_LIMIT_OVERRIDES (ms→s) wins over legacy
        # RATE_LIMIT_DELAYS (already in seconds).
        overrides_s = {d: ms / 1000.0 for d, ms in settings.rate_limit_overrides.items()}
        self._delays: dict[str, float] = {**settings.rate_limit_delays, **overrides_s}
        self._last_call: dict[str, float] = defaultdict(float)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def acquire(self, domain: str) -> None:
        """Block until the rate-limit window for *domain* has elapsed."""
        if not self._enabled:
            return
        delay = self._delays.get(domain, self._default)
        if delay <= 0:
            return
        async with self._locks[domain]:
            elapsed = time.monotonic() - self._last_call[domain]
            wait = delay - elapsed
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call[domain] = time.monotonic()

    def set_delay(self, domain: str, seconds: float) -> None:
        """Override the configured delay for a domain at runtime."""
        self._delays[domain] = seconds

    def get_delay(self, domain: str) -> float:
        """Return the effective delay for a domain (falls back to global default)."""
        return self._delays.get(domain, self._default)


# Backward-compat alias used by core/__init__.py and any external imports
RateLimiter = DomainRateLimiter

# Module-level singleton shared across all modules via http_client
rate_limiter = DomainRateLimiter()
