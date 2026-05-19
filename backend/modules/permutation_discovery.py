from __future__ import annotations

import asyncio
import re

from ..config import settings
from ..core.permutator import _DEFAULT_DOMAINS, generate_permutations
from .base import ModuleResult, ModuleStatus

_NAME_KEYS = frozenset({"name", "display_name", "full_name", "real_name"})
_FULL_NAME_RE = re.compile(r"^([A-Za-z'\-]+)\s+([A-Za-z'\-]+)")


def _extract_names(collected: dict) -> list[tuple[str, str]]:
    """Return (first, last) pairs recovered from any primary-module finding."""
    candidates: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(fn: str, ln: str) -> None:
        fn, ln = fn.strip(), ln.strip()
        if not fn or not ln:
            return
        key = (fn.lower(), ln.lower())
        if key not in seen:
            seen.add(key)
            candidates.append((fn, ln))

    for result in collected.values():
        if not hasattr(result, "findings"):
            continue
        for finding in result.findings:
            if not isinstance(finding, dict):
                continue
            # Check both the top-level payload and its metadata sub-dict
            for payload in (finding, finding.get("metadata") or {}):
                if not isinstance(payload, dict):
                    continue

                # Explicit split fields (Hudson Rock, some breach datasets)
                _add(
                    str(payload.get("first_name", "")),
                    str(payload.get("last_name", "")),
                )

                # Full-name fields — split on first whitespace boundary
                for key in _NAME_KEYS:
                    val = payload.get(key, "")
                    if not isinstance(val, str) or not val.strip():
                        continue
                    m = _FULL_NAME_RE.match(val.strip())
                    if m:
                        _add(m.group(1), m.group(2))

    return candidates


class PermutationDiscovery:
    """
    Post-primary-phase orchestrator.

    Not a BaseModule subclass — invoked explicitly by the engine after the
    primary gather completes.  If any module recovered a real name, generates
    up to 60 email permutations and probes each with HIBP and Hudson Rock.
    """

    name = "permutation_discovery"

    async def run(self, email: str, collected: dict) -> ModuleResult:
        if not settings.enable_permutation_discovery:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["ENABLE_PERMUTATION_DISCOVERY is not set"],
            )

        names = _extract_names(collected)
        if not names:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["No real name found in primary module results"],
            )

        target_domain = email.split("@")[1] if "@" in email else None

        # Build permutation list: prioritise target domain (if non-default),
        # then all default providers.
        all_permutations: list[str] = []
        seen_perms: set[str] = set()
        target_email_lower = email.lower()

        def _add_perms(perms: list[str]) -> None:
            for p in perms:
                if p not in seen_perms and p.lower() != target_email_lower:
                    seen_perms.add(p)
                    all_permutations.append(p)

        for first, last in names:
            if target_domain and target_domain not in _DEFAULT_DOMAINS:
                _add_perms(generate_permutations(first, last, domain=target_domain))
            _add_perms(generate_permutations(first, last))

        all_permutations = all_permutations[:60]
        if not all_permutations:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["No permutations generated after deduplication"],
            )

        findings: list[dict] = []
        errors: list[str] = []

        semaphore = asyncio.Semaphore(10)
        await asyncio.gather(
            *[
                self._check_permutation(perm, semaphore, findings, errors)
                for perm in all_permutations
            ],
            return_exceptions=True,
        )

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            findings=findings,
            errors=errors,
            metadata={
                "names_found": [f"{f} {l}" for f, l in names],
                "permutations_checked": len(all_permutations),
                "related_emails_found": len(findings) > 0,
                "matched_emails": list({f["metadata"]["matched_email"] for f in findings}),
            },
        )

    async def _check_permutation(
        self,
        perm_email: str,
        semaphore: asyncio.Semaphore,
        findings: list[dict],
        errors: list[str],
    ) -> None:
        async with semaphore:
            await asyncio.gather(
                self._check_hibp(perm_email, findings, errors),
                self._check_hudson_rock(perm_email, findings, errors),
            )

    async def _check_hibp(
        self, email: str, findings: list[dict], errors: list[str]
    ) -> None:
        if not settings.hibp_api_key:
            return
        try:
            from .hibp import HIBPModule

            result = await HIBPModule().run(email)
            if result.status in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL) and result.findings:
                breach_count = sum(
                    1 for f in result.findings if f.get("platform") == "HaveIBeenPwned"
                )
                findings.append(
                    {
                        "platform": "permutation_match",
                        "metadata": {
                            "matched_email": email,
                            "source_module": "hibp",
                            "match_type": "breach",
                            "breach_count": breach_count,
                        },
                        "confidence": "medium",
                    }
                )
        except Exception as exc:
            errors.append(f"HIBP check for {email}: {exc}")

    async def _check_hudson_rock(
        self, email: str, findings: list[dict], errors: list[str]
    ) -> None:
        try:
            from .hudson_rock import HudsonRockModule

            result = await HudsonRockModule().run(email)
            if result.status == ModuleStatus.SUCCESS and result.findings:
                findings.append(
                    {
                        "platform": "permutation_match",
                        "metadata": {
                            "matched_email": email,
                            "source_module": "hudson_rock",
                            "match_type": "infostealer",
                            "infection_count": result.metadata.get("total_infections", 0),
                        },
                        "confidence": "medium",
                    }
                )
        except Exception as exc:
            errors.append(f"Hudson Rock check for {email}: {exc}")
