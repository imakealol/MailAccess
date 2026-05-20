from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)

_WMN_DATA_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)
_CACHE_PATH = Path("data/cache/wmn-data.json")
_CACHE_TTL = 86_400  # 24 hours
_CONCURRENCY = 50
_TIMEOUT = 6.0


async def _load_wmn_data() -> dict[str, Any]:
    """Return parsed wmn-data.json, refreshing the local cache when stale.

    Cache check runs before any network call. Debug log line records which
    branch was taken so back-to-back runs are easy to verify.
    """
    if _CACHE_PATH.exists():
        age = time.time() - _CACHE_PATH.stat().st_mtime
        if age < _CACHE_TTL:
            _LOG.debug("WMN: using cache (age=%.1fs, ttl=%ds)", age, _CACHE_TTL)
            return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
        _LOG.debug("WMN: cache stale (age=%.1fs >= ttl=%ds) — fetching fresh data", age, _CACHE_TTL)
    else:
        _LOG.debug("WMN: no cache present — fetching fresh data")

    _LOG.info("Fetching fresh wmn-data.json from GitHub")
    async with build_client(timeout=30.0) as client:
        resp = await client.get(_WMN_DATA_URL)
        resp.raise_for_status()
        data = resp.json()

    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_PATH.write_text(json.dumps(data), encoding="utf-8")
    return data


async def _check_site(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    entry: dict[str, Any],
    username: str,
) -> tuple[str, str | None]:
    """
    Returns ("found", profile_url), ("not_found", None), or ("error", reason).
    Semaphore caps simultaneous in-flight requests.
    """
    uri = entry["uri_check"].replace("{account}", username)
    e_code: int = entry.get("e_code", 200)
    e_string: str = entry.get("e_string", "")
    m_code: int = entry.get("m_code", 404)
    m_string: str = entry.get("m_string", "")

    async with sem:
        try:
            resp = await client.get(uri, timeout=_TIMEOUT, follow_redirects=True)
            body = resp.text

            if resp.status_code == e_code and (not e_string or e_string in body):
                return ("found", uri)

            if resp.status_code == m_code or (m_string and m_string in body):
                return ("not_found", None)

            return ("not_found", None)

        except httpx.TimeoutException:
            return ("error", "timeout")
        except Exception as exc:
            return ("error", str(exc))


class WhatsMyNameModule(BaseModule):
    name = "whatsmyname"
    description = (
        "Username enumeration across 700+ platforms via the WhatsMyName dataset. "
        "Enable via ENABLE_WHATSMYNAME=true. Sweep takes 60–90 seconds."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        if not settings.enable_whatsmyname:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_WHATSMYNAME=true to run this module"],
            )

        username = email.split("@")[0]

        try:
            wmn = await _load_wmn_data()
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load wmn-data.json: {exc}"],
            )

        sites: list[dict[str, Any]] = wmn.get("sites", [])
        wmn_version: str = wmn.get("version", "unknown")

        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        not_found_count = 0
        error_count = 0

        sem = asyncio.Semaphore(_CONCURRENCY)

        async with build_client(timeout=_TIMEOUT, follow_redirects=True) as client:
            tasks = [_check_site(client, sem, entry, username) for entry in sites]
            results = await asyncio.gather(*tasks)

        for entry, (outcome, detail) in zip(sites, results):
            if outcome == "found":
                findings.append({
                    "platform": entry["name"],
                    "profile_url": detail,
                    "metadata": {"category": entry.get("category", "")},
                    "confidence": "high",
                })
            elif outcome == "not_found":
                not_found_count += 1
            else:
                error_count += 1
                if detail != "timeout":
                    errors.append(f"{entry['name']}: {detail}")

        status = ModuleStatus.SUCCESS
        if error_count > 0 and not findings:
            status = ModuleStatus.PARTIAL if not_found_count > 0 else ModuleStatus.FAILED
        elif error_count > 0:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "total_platforms_checked": len(sites),
                "platforms_confirmed": len(findings),
                "platforms_not_found": not_found_count,
                "platforms_errored": error_count,
                "wmn_version": wmn_version,
            },
            errors=errors,
        )
