from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import update

from ..db.database import AsyncSessionLocal
from ..db.models import Finding, Investigation, InvestigationStatus, ModuleRun
from ..modules import get_all_modules
from ..modules.base import ModuleResult, ModuleStatus

# Module categories for exposure scoring
_INFOSTEALER_MODULES = frozenset({"hudson_rock"})
_BREACH_MODULES = frozenset({"hibp", "breachdirectory"})
_SOCIAL_MODULES = frozenset({
    "gravatar",
    "social_links",
    "google_search",
    "ghunt",
    "whatsmyname",
    "account_discovery",
    "user_scanner",
    "username_pivot",
    "social",
})
_POST_PRIMARY_ONLY = frozenset({"username_pivot", "phone_intel"})

_WEIGHT_INFOSTEALER = 20  # critical: active malware compromise
_WEIGHT_BREACH = 15       # high: credential exposure
_WEIGHT_SOCIAL = 5        # medium: identity surface
_WEIGHT_META = 2          # low: infrastructure / info

# Confidence multipliers applied per finding before summing.
# Low-confidence findings (search-result WMN hits, experimental hints) contribute
# fractionally so volume alone can't inflate the score.
_CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "high":   1.0,
    "medium": 0.5,
    "low":    0.2,
    "none":   0.0,
}

# Per-module score caps prevent a single module with many hits (e.g. WMN matching
# a common first-name username across 700 sites) from dominating the total.
# Breach/infostealer modules have higher caps because each hit is genuinely alarming.
_MODULE_CAP: dict[str, int] = {
    "whatsmyname":      20,
    "account_discovery": 15,
    "user_scanner":     15,
    "username_pivot":   10,
    "social":           10,
    "social_links":      5,
    "hudson_rock":      40,
    "hibp":             45,
    "breachdirectory":  40,
}


def _module_weight(module_name: str) -> int:
    if module_name in _INFOSTEALER_MODULES:
        return _WEIGHT_INFOSTEALER
    if module_name in _BREACH_MODULES:
        return _WEIGHT_BREACH
    if module_name in _SOCIAL_MODULES:
        return _WEIGHT_SOCIAL
    return _WEIGHT_META


def _finding_sort_key(finding) -> tuple[str, str, str]:
    if not isinstance(finding, dict):
        return ("", "", str(finding))
    platform = str(finding.get("platform", ""))
    profile_url = str(finding.get("profile_url", ""))
    source = str(finding.get("source", ""))
    return (platform, profile_url, source)


def _sort_collected(results: dict[str, ModuleResult]) -> dict[str, ModuleResult]:
    """Return a new dict with module keys sorted and findings within each module sorted.

    Determinism guard: async completion order varies between runs, which made the
    insertion order of `results` (and finding lists inside each module) depend on
    network race conditions. Sorting both gives identical inputs → identical score.
    """
    ordered: dict[str, ModuleResult] = {}
    for name in sorted(results.keys()):
        result = results[name]
        result.findings = sorted(result.findings, key=_finding_sort_key)
        ordered[name] = result
    return ordered


def _compute_exposure_score(results: dict[str, ModuleResult]) -> int:
    """
    Confidence-weighted, per-module-capped exposure score, clamped to [0, 100].

    Each finding contributes: base_weight × confidence_multiplier.
    The sum per module is then capped to prevent high-volume enumeration modules
    (WMN, account_discovery) from drowning out genuine breach/infostealer signals.
    """
    total: float = 0.0
    base_weight = _module_weight  # local alias

    for name in sorted(results.keys()):
        result = results[name]
        if result.status not in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
            continue

        weight = base_weight(name)
        module_score: float = 0.0
        for finding in result.findings:
            confidence = "high"
            if isinstance(finding, dict):
                confidence = finding.get("confidence", "high")
            multiplier = _CONFIDENCE_MULTIPLIER.get(confidence, 1.0)
            module_score += weight * multiplier

        cap = _MODULE_CAP.get(name)
        if cap is not None:
            module_score = min(module_score, cap)

        total += module_score

    return min(int(total), 100)


@dataclass
class QueueEvent:
    type: str  # "module_start" | "module_result" | "module_error"
    module_name: str
    result: ModuleResult | None = None


class InvestigationEngine:
    """
    Runs selected OSINT modules concurrently and streams results via asyncio.Queue.

    Usage::

        queue = await engine.investigate(email, investigation_id)
        while True:
            item = await queue.get()
            if item is None:              # sentinel — all modules done, DB persisted
                break
            # item is a QueueEvent

    The engine persists ModuleRun records, Finding records, the final exposure
    score, and the COMPLETE status to the DB before sending the sentinel.
    """

    def __init__(self, timeout: int = 30, max_concurrency: int = 10) -> None:
        self._timeout = timeout
        self._max_concurrency = max_concurrency
        self.status = InvestigationStatus.PENDING

    async def investigate(
        self,
        email: str,
        investigation_id: str,
        module_names: list[str] | None = None,
    ) -> asyncio.Queue[QueueEvent | None]:
        """
        Start investigation and return the result queue immediately.

        The background task writes a None sentinel to the queue after all modules
        complete and DB persistence finishes. Pass module_names to run a subset;
        None (default) runs all registered modules.
        """
        if module_names is not None:
            classes = [c for c in get_all_modules() if c.name in module_names]
        else:
            classes = get_all_modules()
        classes = [c for c in classes if c.name not in _POST_PRIMARY_ONLY]

        queue: asyncio.Queue[QueueEvent | None] = asyncio.Queue()
        semaphore = asyncio.Semaphore(self._max_concurrency)
        collected: dict[str, ModuleResult] = {}
        started_at = datetime.now(timezone.utc)

        async def _run_one(cls) -> None:
            mod = cls()
            from ..config import settings
            timeout = settings.module_timeout_overrides.get(mod.name, settings.module_timeout_seconds)
            async with semaphore:
                await queue.put(QueueEvent(type="module_start", module_name=mod.name))
                try:
                    result = await asyncio.wait_for(
                        mod.run(email), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    result = ModuleResult(
                        status=ModuleStatus.FAILED,
                        errors=[f"timed out after {timeout}s"],
                    )
                except Exception as exc:
                    result = ModuleResult(
                        status=ModuleStatus.FAILED,
                        errors=[str(exc)],
                    )
            collected[mod.name] = result
            event_type = (
                "module_error" if result.status == ModuleStatus.FAILED else "module_result"
            )
            await queue.put(QueueEvent(type=event_type, module_name=mod.name, result=result))

        async def _run_and_persist() -> None:
            self.status = InvestigationStatus.RUNNING
            await self._set_status(investigation_id, InvestigationStatus.RUNNING)

            await asyncio.gather(
                *[_run_one(cls) for cls in classes],
                return_exceptions=True,
            )

            from ..config import settings as _cfg

            if _cfg.enable_username_pivot:
                from ..modules.username_pivot import UsernamePivotModule

                _pivot = UsernamePivotModule()
                _pivot_timeout = _cfg.module_timeout_overrides.get(
                    _pivot.name, _cfg.module_timeout_seconds
                )
                await queue.put(QueueEvent(type="module_start", module_name=_pivot.name))
                try:
                    _pivot_result = await asyncio.wait_for(
                        _pivot.run(email, collected), timeout=_pivot_timeout
                    )
                except asyncio.TimeoutError:
                    _pivot_result = ModuleResult(
                        status=ModuleStatus.FAILED,
                        errors=[f"timed out after {_pivot_timeout}s"],
                    )
                except Exception as _exc:
                    _pivot_result = ModuleResult(
                        status=ModuleStatus.FAILED, errors=[str(_exc)]
                    )
                collected[_pivot.name] = _pivot_result
                _pivot_evt = (
                    "module_error"
                    if _pivot_result.status == ModuleStatus.FAILED
                    else "module_result"
                )
                await queue.put(
                    QueueEvent(
                        type=_pivot_evt, module_name=_pivot.name, result=_pivot_result
                    )
                )

            # Permutation discovery phase — runs after primary modules so it can
            # read their findings to extract a real name.
            if _cfg.enable_permutation_discovery:
                from ..modules.permutation_discovery import PermutationDiscovery
                _perm = PermutationDiscovery()
                await queue.put(QueueEvent(type="module_start", module_name=_perm.name))
                try:
                    _perm_result = await _perm.run(email, collected)
                except Exception as _exc:
                    _perm_result = ModuleResult(
                        status=ModuleStatus.FAILED, errors=[str(_exc)]
                    )
                collected[_perm.name] = _perm_result
                _evt = (
                    "module_error"
                    if _perm_result.status == ModuleStatus.FAILED
                    else "module_result"
                )
                await queue.put(
                    QueueEvent(type=_evt, module_name=_perm.name, result=_perm_result)
                )

            if _cfg.enable_phone_intel:
                from ..core.phone_extractor import extract_phones
                from ..modules.phone_intel import PhoneIntelModule

                _phone = PhoneIntelModule()
                _phone_timeout = _cfg.module_timeout_overrides.get(
                    _phone.name, _cfg.module_timeout_seconds
                )
                await queue.put(QueueEvent(type="module_start", module_name=_phone.name))
                try:
                    _phone_result = await asyncio.wait_for(
                        _phone.run(email, collected), timeout=_phone_timeout
                    )
                except asyncio.TimeoutError:
                    _phone_result = ModuleResult(
                        status=ModuleStatus.FAILED,
                        errors=[f"timed out after {_phone_timeout}s"],
                    )
                except Exception as _exc:
                    _phone_result = ModuleResult(
                        status=ModuleStatus.FAILED, errors=[str(_exc)]
                    )
                collected[_phone.name] = _phone_result
                _phone_evt = (
                    "module_error"
                    if _phone_result.status == ModuleStatus.FAILED
                    else "module_result"
                )
                await queue.put(
                    QueueEvent(
                        type=_phone_evt, module_name=_phone.name, result=_phone_result
                    )
                )

                # Re-run messaging hints with recovered phones (WhatsApp path)
                if _cfg.enable_messaging_hints:
                    from ..modules.messaging_hints import MessagingHintsModule

                    _all_findings: list = []
                    for _r in collected.values():
                        if hasattr(_r, "findings"):
                            _all_findings.extend(_r.findings)
                    _phones = extract_phones(_all_findings)
                    if _phones:
                        _msg = MessagingHintsModule()
                        try:
                            _msg_extra = await asyncio.wait_for(
                                _msg.run(email, phone_hints=_phones, collected=collected),
                                timeout=_cfg.module_timeout_seconds,
                            )
                            if _msg_extra.findings:
                                prev = collected.get(_msg.name)
                                if prev and hasattr(prev, "findings"):
                                    existing_urls = {
                                        f.get("profile_url") for f in prev.findings
                                    }
                                    new_only = [
                                        f for f in _msg_extra.findings
                                        if f.get("profile_url") not in existing_urls
                                    ]
                                    prev.findings = list(prev.findings) + new_only
                                    if prev.metadata and _msg_extra.metadata:
                                        prev.metadata["whatsapp_followup"] = True
                                else:
                                    collected[_msg.name] = _msg_extra
                        except Exception:
                            pass

            graph_data: dict | None = None
            try:
                from .identity_graph import IdentityGraph

                _findings_flat = []
                for _mod, _res in collected.items():
                    if hasattr(_res, "findings"):
                        for _f in _res.findings:
                            _findings_flat.append({"module_name": _mod, "data": _f})
                graph_data = IdentityGraph.build(
                    {"email": email, "findings": _findings_flat}
                ).to_d3()
            except Exception:
                graph_data = None

            # Sort collected once, after every module has reported, so the
            # exposure score and persisted finding order are independent of
            # async completion order.
            # NOTE: use a separate variable to avoid shadowing the closed-over
            # `collected` in _run_and_persist — assigning to `collected` here
            # would make Python treat it as a local throughout the function,
            # causing UnboundLocalError on every earlier reference.
            _final = _sort_collected(collected)

            # Persist before sentinel so consumers see the final score in the DB.
            self.status = InvestigationStatus.COMPLETE
            try:
                await self._persist(investigation_id, _final, started_at, graph_data)

                # Dispatch webhooks if configured
                try:
                    from ..integrations.webhooks import WebhookDispatcher
                    score = _compute_exposure_score(_final)
                    await WebhookDispatcher().dispatch(email, score, _final)

                    from ..config import settings
                    if settings.integration_webhook_url:
                        from ..core.service import InvestigationService, enrich_report
                        from ..integrations.integration_webhook import IntegrationWebhookDispatcher
                        
                        async with AsyncSessionLocal() as session:
                            svc = InvestigationService(session)
                            data = await svc.get_investigation(investigation_id)
                        
                        if data:
                            payload = enrich_report(data)
                            await IntegrationWebhookDispatcher().dispatch(payload)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).error(f"Webhook dispatch failed: {e}")
            except Exception:
                self.status = InvestigationStatus.FAILED
                await self._set_status(investigation_id, InvestigationStatus.FAILED)
            finally:
                await queue.put(None)

        asyncio.create_task(_run_and_persist())
        return queue

    # ------------------------------------------------------------------
    # DB helpers (each opens its own session — runs outside request scope)
    # ------------------------------------------------------------------

    async def _set_status(
        self, investigation_id: str, status: InvestigationStatus
    ) -> None:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(status=status)
                )

    async def _persist(
        self,
        investigation_id: str,
        collected: dict[str, ModuleResult],
        started_at: datetime,
        graph_data: dict | None = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        score = _compute_exposure_score(collected)

        async with AsyncSessionLocal() as session:
            async with session.begin():
                values: dict = {
                    "status": InvestigationStatus.COMPLETE,
                    "completed_at": now,
                    "exposure_score": score,
                }
                if graph_data is not None:
                    values["graph_data"] = graph_data
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(**values)
                )
                for module_name, result in collected.items():
                    session.add(
                        ModuleRun(
                            investigation_id=investigation_id,
                            module_name=module_name,
                            status=result.status.value,
                            run_metadata=result.metadata or None,
                            errors=result.errors or None,
                            started_at=started_at,
                            finished_at=now,
                        )
                    )
                    for finding_data in result.findings:
                        session.add(
                            Finding(
                                investigation_id=investigation_id,
                                module_name=module_name,
                                data=finding_data,
                            )
                        )
