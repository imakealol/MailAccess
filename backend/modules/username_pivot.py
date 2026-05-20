from __future__ import annotations

import asyncio
import re
from typing import Any

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus
from .whatsmyname import _check_site, _load_wmn_data

_MAX_USERNAMES = 5
_USERNAME_KEYS = frozenset({"username", "login", "user", "handle"})
_DISPLAY_NAME_KEYS = frozenset({"display_name", "name", "full_name", "real_name"})


def _slug_variants(display_name: str) -> list[str]:
    s = display_name.strip().lower()
    if not s or "@" in s:
        return []
    variants = [
        re.sub(r"\s+", "_", s),
        re.sub(r"\s+", "", s),
        re.sub(r"\s+", ".", s),
    ]
    out: list[str] = []
    seen: set[str] = set()
    for v in variants:
        v = re.sub(r"[^a-z0-9._-]", "", v)
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _collect_usernames(email: str, collected: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        u = value.strip().lower()
        if not u or "@" in u or len(u) < 2:
            return
        if u not in seen:
            seen.add(u)
            candidates.append(u)

    if "@" in email:
        _add(email.split("@", 1)[0])

    for result in collected.values():
        if not hasattr(result, "findings"):
            continue
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            payloads: list[dict[str, Any]] = [finding]
            meta = finding.get("metadata")
            if isinstance(meta, dict):
                payloads.append(meta)
            for payload in payloads:
                for key in _USERNAME_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str):
                        _add(val)
                for key in _DISPLAY_NAME_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str):
                        for variant in _slug_variants(val):
                            _add(variant)

    return candidates[:_MAX_USERNAMES]


def _confirmed_platforms(collected: dict[str, Any]) -> set[str]:
    platforms: set[str] = set()
    wmn = collected.get("whatsmyname")
    if wmn and hasattr(wmn, "findings"):
        for f in wmn.findings:
            if isinstance(f, dict) and f.get("platform"):
                platforms.add(str(f["platform"]).lower())
    return platforms


class UsernamePivotModule(BaseModule):
    name = "username_pivot"
    description = (
        "Pivot recovered usernames across WhatsMyName platforms after primary modules. "
        "Enable via ENABLE_USERNAME_PIVOT=true."
    )
    requires_key = False

    async def run(
        self, email: str, collected: dict[str, Any] | None = None
    ) -> ModuleResult:
        if collected is None:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Runs in post-primary phase only"],
            )

        if not settings.enable_username_pivot:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["Set ENABLE_USERNAME_PIVOT=true to run this module"],
            )

        usernames = _collect_usernames(email, collected)
        if not usernames:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["No usernames recovered from primary findings"],
            )

        try:
            wmn = await _load_wmn_data()
        except Exception as exc:
            return ModuleResult(
                status=ModuleStatus.FAILED,
                errors=[f"Failed to load wmn-data.json: {exc}"],
            )

        sites: list[dict[str, Any]] = wmn.get("sites", [])
        already_found = _confirmed_platforms(collected)
        sem = asyncio.Semaphore(50)
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        checked = 0
        confirmed = 0

        async with build_client(timeout=6.0, follow_redirects=True) as client:
            for username in usernames:
                tasks = [_check_site(client, sem, entry, username) for entry in sites]
                results = await asyncio.gather(*tasks)
                checked += len(sites)

                for entry, (outcome, profile_url, is_search) in zip(sites, results):
                    platform = entry.get("name", "")
                    if outcome != "found" or not platform:
                        continue
                    if platform.lower() in already_found:
                        continue
                    already_found.add(platform.lower())
                    confirmed += 1
                    findings.append({
                        "platform": platform,
                        "profile_url": profile_url,
                        "metadata": {
                            "matched_username": username,
                            "category": entry.get("category", ""),
                            "source": "username_pivot",
                            **({"search_result": True} if is_search else {}),
                        },
                        "confidence": "low" if is_search else "medium",
                    })

        status = ModuleStatus.SUCCESS
        if errors and not findings:
            status = ModuleStatus.FAILED
        elif errors:
            status = ModuleStatus.PARTIAL

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "usernames_pivoted": usernames,
                "platforms_checked": checked,
                "platforms_confirmed": confirmed,
                "wmn_version": wmn.get("version", "unknown"),
            },
            errors=errors,
        )
