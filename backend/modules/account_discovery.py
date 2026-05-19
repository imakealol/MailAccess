from __future__ import annotations

import asyncio
import logging
from typing import Any

from holehe.core import __version__ as _HOLEHE_VERSION
from holehe.core import get_functions, import_submodules

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

_LOG = logging.getLogger(__name__)
_BATCH_SIZE = 20


def _make_finding(result: dict[str, Any]) -> dict[str, Any]:
    domain = result.get("domain") or ""
    profile_url = f"https://{domain}" if domain else None

    meta: dict[str, Any] = {}
    if result.get("emailrecovery"):
        meta["email_recovery"] = result["emailrecovery"]
    if result.get("phoneNumber"):
        meta["phone_hint"] = result["phoneNumber"]
    if result.get("others"):
        meta["extras"] = result["others"]
    if result.get("emailrecovery") or result.get("phoneNumber"):
        meta["high_value"] = True

    return {
        "platform": result.get("name", "unknown"),
        "profile_url": profile_url,
        "metadata": meta,
        "confidence": "high",
        "source": "account_discovery",
    }


class AccountDiscoveryModule(BaseModule):
    name = "account_discovery"
    description = (
        "Probe 120+ platforms via Holehe to detect account existence. "
        "Enable via ENABLE_ACCOUNT_DISCOVERY=true."
    )
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        if not settings.enable_account_discovery:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_ACCOUNT_DISCOVERY=true to run this module"],
            )

        funcs = get_functions(import_submodules("holehe"))
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        rate_limited: list[str] = []
        not_found_count = 0

        batches = [
            funcs[i : i + _BATCH_SIZE]
            for i in range(0, len(funcs), _BATCH_SIZE)
        ]

        async with build_client(timeout=15.0, follow_redirects=True) as client:
            for idx, batch in enumerate(batches):
                out_lists: list[list[dict[str, Any]]] = [[] for _ in batch]
                coros = [fn(email, client, out) for fn, out in zip(batch, out_lists)]
                gathered = await asyncio.gather(*coros, return_exceptions=True)

                for exc_or_none, out in zip(gathered, out_lists):
                    if isinstance(exc_or_none, Exception):
                        errors.append(str(exc_or_none))
                        continue
                    for r in out:
                        if r.get("rateLimit"):
                            rate_limited.append(r.get("name", "unknown"))
                        elif r.get("exists") is True:
                            findings.append(_make_finding(r))
                        elif r.get("exists") is False:
                            not_found_count += 1

                if idx < len(batches) - 1 and settings.request_delay_ms > 0:
                    await asyncio.sleep(settings.request_delay_ms / 1000.0)

        if rate_limited:
            errors.append(
                f"Rate-limited by {len(rate_limited)} platform(s): "
                + ", ".join(rate_limited)
            )

        hard_errors = [e for e in errors if not e.startswith("Rate-limited")]
        status = ModuleStatus.SUCCESS
        if hard_errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "platforms_checked": len(funcs),
                "platforms_confirmed": len(findings),
                "platforms_rate_limited": len(rate_limited),
                "platforms_not_found": not_found_count,
                "holehe_version": _HOLEHE_VERSION,
            },
            errors=errors,
        )
