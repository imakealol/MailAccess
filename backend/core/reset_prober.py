from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

_ENDPOINT_PATTERNS = (
    "https://{domain}/forgot-password",
    "https://{domain}/account/forgot",
    "https://{domain}/users/password/new",
    "https://{domain}/auth/forgot-password",
    "https://{domain}/reset-password",
    "https://{domain}/account/reset",
    "https://{domain}/api/auth/forgot-password",
    "https://{domain}/api/v1/auth/forgot-password",
    "https://accounts.{domain}/forgot-password",
)

_SUCCESS_SIGNALS = (
    "check your email",
    "reset link sent",
    "if an account exists",
    "email has been sent",
    "password reset",
    "we sent",
)

_FAILURE_SIGNALS = (
    "not found",
    "no account",
    "doesn't exist",
    "does not exist",
    "not registered",
    "invalid email",
    "no user found",
    "account not found",
)

_BLOCKED_STATUSES = {403, 429}
_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


@dataclass(frozen=True)
class _ProbeResult:
    value: bool | None
    blocked: bool = False
    responded: bool = False


def _classify_text(text: str) -> bool | None:
    lowered = text.lower()
    if any(signal in lowered for signal in _SUCCESS_SIGNALS):
        return True
    if any(signal in lowered for signal in _FAILURE_SIGNALS):
        return False
    return None


async def _post_json(url: str, email: str, client: httpx.AsyncClient) -> _ProbeResult:
    try:
        resp = await client.post(
            url,
            json={"email": email},
            headers={**_DEFAULT_HEADERS, "Accept": "application/json"},
            timeout=6.0,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return _ProbeResult(None)
    if resp.status_code in _BLOCKED_STATUSES:
        return _ProbeResult(None, blocked=True, responded=True)
    return _ProbeResult(_classify_text(resp.text), responded=True)


async def _post_form(url: str, email: str, client: httpx.AsyncClient) -> _ProbeResult:
    try:
        resp = await client.post(
            url,
            data={"email": email},
            headers={
                **_DEFAULT_HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=6.0,
        )
    except (httpx.TimeoutException, httpx.RequestError):
        return _ProbeResult(None)
    if resp.status_code in _BLOCKED_STATUSES:
        return _ProbeResult(None, blocked=True, responded=True)
    return _ProbeResult(_classify_text(resp.text), responded=True)


async def _probe_endpoint(url: str, email: str, client: httpx.AsyncClient) -> _ProbeResult:
    async def _attempt() -> _ProbeResult:
        json_result = await _post_json(url, email, client)
        if json_result.value is not None or json_result.blocked:
            return json_result
        form_result = await _post_form(url, email, client)
        if form_result.value is not None or form_result.blocked:
            return form_result
        return _ProbeResult(
            None,
            blocked=json_result.blocked or form_result.blocked,
            responded=json_result.responded or form_result.responded,
        )

    try:
        return await asyncio.wait_for(_attempt(), timeout=6.0)
    except asyncio.TimeoutError:
        return _ProbeResult(None)


async def probe(domain: str, email: str, client: httpx.AsyncClient) -> bool | None:
    """
    Return True when reset flow implies an account, False when it denies one,
    or None when the domain is blocked, absent, or inconclusive.
    """
    clean_domain = domain.strip().lower().removeprefix("www.")
    urls = [pattern.format(domain=clean_domain) for pattern in _ENDPOINT_PATTERNS[:3]]
    tasks = [asyncio.create_task(_probe_endpoint(url, email, client)) for url in urls]
    blocked = 0
    responded = 0
    try:
        for task in asyncio.as_completed(tasks):
            result = await task
            if result.responded:
                responded += 1
            if result.blocked:
                blocked += 1
            if result.value is not None:
                for pending in tasks:
                    if not pending.done():
                        pending.cancel()
                return result.value
            if result.responded and not result.blocked:
                for pending in tasks:
                    if not pending.done():
                        pending.cancel()
                return None
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
    if responded and blocked == responded:
        return None
    return None
