from __future__ import annotations

from ..modules.base import ModuleResult, ModuleStatus


class ResultAggregator:
    """Collects per-module results and produces a unified investigation summary."""

    def __init__(self) -> None:
        self._results: dict[str, ModuleResult] = {}

    def add(self, module_name: str, result: ModuleResult) -> None:
        self._results[module_name] = result

    @property
    def all_findings(self) -> list[dict]:
        findings = []
        for module_name, result in self._results.items():
            for finding in result.findings:
                findings.append({"module": module_name, **finding})
        return findings

    @property
    def summary(self) -> dict:
        statuses = [r.status for r in self._results.values()]
        return {
            "total_modules": len(self._results),
            "success": statuses.count(ModuleStatus.SUCCESS),
            "partial": statuses.count(ModuleStatus.PARTIAL),
            "failed": statuses.count(ModuleStatus.FAILED),
            "skipped": statuses.count(ModuleStatus.SKIPPED),
            "total_findings": sum(len(r.findings) for r in self._results.values()),
        }

    @property
    def results(self) -> dict[str, ModuleResult]:
        return dict(self._results)
