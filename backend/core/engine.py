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
_BREACH_MODULES = frozenset({"hibp"})
_SOCIAL_MODULES = frozenset({"gravatar", "social_links", "google_search", "ghunt", "whatsmyname", "account_discovery", "social"})

_WEIGHT_INFOSTEALER = 20  # critical: active malware compromise
_WEIGHT_BREACH = 15       # high: credential exposure
_WEIGHT_SOCIAL = 5        # medium: identity surface
_WEIGHT_META = 2          # low: infrastructure / info


def _module_weight(module_name: str) -> int:
    if module_name in _INFOSTEALER_MODULES:
        return _WEIGHT_INFOSTEALER
    if module_name in _BREACH_MODULES:
        return _WEIGHT_BREACH
    if module_name in _SOCIAL_MODULES:
        return _WEIGHT_SOCIAL
    return _WEIGHT_META


def _compute_exposure_score(results: dict[str, ModuleResult]) -> int:
    """Sum weighted finding counts across all successful modules, clamped to [0, 100]."""
    total = 0
    for name, result in results.items():
        if result.status in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
            total += len(result.findings) * _module_weight(name)
    return min(total, 100)


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

            # Permutation discovery phase — runs after primary modules so it can
            # read their findings to extract a real name.
            from ..config import settings as _cfg
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

            # Persist before sentinel so consumers see the final score in the DB.
            self.status = InvestigationStatus.COMPLETE
            try:
                await self._persist(investigation_id, collected, started_at)
                
                # Dispatch webhooks if configured
                try:
                    from ..integrations.webhooks import WebhookDispatcher
                    score = _compute_exposure_score(collected)
                    await WebhookDispatcher().dispatch(email, score, collected)

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
    ) -> None:
        now = datetime.now(timezone.utc)
        score = _compute_exposure_score(collected)

        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(
                        status=InvestigationStatus.COMPLETE,
                        completed_at=now,
                        exposure_score=score,
                    )
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
