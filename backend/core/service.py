from __future__ import annotations

import asyncio
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..config import settings
from ..db.models import Finding, Investigation, InvestigationStatus, ModuleRun
from .engine import InvestigationEngine


def _risk_level(score: int | None) -> str:
    if score is None:
        return "unknown"
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


def _build_summary(data: dict) -> str:
    runs = data.get("module_runs", [])
    findings = data.get("findings", [])
    success = sum(1 for r in runs if r["status"] == "success")
    failed = sum(1 for r in runs if r["status"] == "failed")
    detail = f"{success} successful" + (f", {failed} failed" if failed else "")
    return f"Ran {len(runs)} modules ({detail}). Found {len(findings)} data points."


def enrich_report(data: dict) -> dict:
    score = data.get("exposure_score")
    data["risk_level"] = _risk_level(score)
    data["summary"] = _build_summary(data)

    data["metadata_table"] = {
        r["module_name"]: r.get("run_metadata") or {}
        for r in data.get("module_runs", [])
    }

    findings_by_module: dict[str, list] = {}
    for f in data.get("findings", []):
        findings_by_module.setdefault(f["module_name"], []).append(f["data"])
    data["findings_by_module"] = findings_by_module

    return data

class InvestigationService:
    """
    Application-layer facade over the DB and InvestigationEngine.

    Intended to be instantiated per-request with an injected AsyncSession::

        service = InvestigationService(session)
        investigation_id, created_at, queue = await service.create_investigation("user@example.com")
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_investigation(
        self,
        email: str,
        module_names: list[str] | None = None,
    ) -> tuple[str, datetime, asyncio.Queue]:
        """
        Persist a new Investigation (PENDING), launch the engine in the
        background, and return (id, created_at, queue) immediately.

        The caller is responsible for storing the queue in the registry so
        WebSocket handlers can consume it.
        """
        inv = Investigation(email=email, status=InvestigationStatus.PENDING)
        self._session.add(inv)
        await self._session.flush()
        investigation_id = inv.id
        created_at = inv.created_at
        await self._session.commit()

        engine = InvestigationEngine(
            timeout=settings.module_timeout_seconds,
            max_concurrency=settings.max_concurrent_modules,
        )
        queue = await engine.investigate(email, investigation_id, module_names)
        return investigation_id, created_at, queue

    async def get_investigation(self, investigation_id: str) -> dict | None:
        """Return the full investigation with all findings and module runs."""
        result = await self._session.execute(
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(
                selectinload(Investigation.findings),
                selectinload(Investigation.module_runs),
            )
        )
        inv = result.scalar_one_or_none()
        if inv is None:
            return None

        return {
            "id": inv.id,
            "email": inv.email,
            "status": inv.status.value,
            "exposure_score": inv.exposure_score,
            "created_at": inv.created_at.isoformat(),
            "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
            "findings": [
                {
                    "id": f.id,
                    "module_name": f.module_name,
                    "data": f.data,
                    "created_at": f.created_at.isoformat(),
                }
                for f in inv.findings
            ],
            "module_runs": [
                {
                    "id": r.id,
                    "module_name": r.module_name,
                    "status": r.status,
                    "run_metadata": r.run_metadata,
                    "errors": r.errors,
                    "started_at": r.started_at.isoformat(),
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                }
                for r in inv.module_runs
            ],
        }

    async def list_investigations(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """Return a paginated list of investigations, newest first."""
        total: int = (
            await self._session.execute(
                select(func.count()).select_from(Investigation)
            )
        ).scalar_one()

        rows = (
            await self._session.execute(
                select(Investigation)
                .order_by(Investigation.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        ).scalars().all()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, (total + page_size - 1) // page_size),
            "items": [
                {
                    "id": inv.id,
                    "email": inv.email,
                    "status": inv.status.value,
                    "exposure_score": inv.exposure_score,
                    "created_at": inv.created_at.isoformat(),
                    "completed_at": (
                        inv.completed_at.isoformat() if inv.completed_at else None
                    ),
                }
                for inv in rows
            ],
        }

    async def delete_investigation(self, investigation_id: str) -> bool:
        """Hard-delete an investigation and all its related records. Returns False if not found."""
        exists = (
            await self._session.execute(
                select(Investigation.id).where(Investigation.id == investigation_id)
            )
        ).scalar_one_or_none()
        if exists is None:
            return False

        await self._session.execute(
            delete(Finding).where(Finding.investigation_id == investigation_id)
        )
        await self._session.execute(
            delete(ModuleRun).where(ModuleRun.investigation_id == investigation_id)
        )
        await self._session.execute(
            delete(Investigation).where(Investigation.id == investigation_id)
        )
        await self._session.commit()
        return True
