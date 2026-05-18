from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ScheduledJob:
    email: str
    cron_expression: str
    next_run: datetime
    job_id: str
    investigation_ids: list[str] = field(default_factory=list)


class Scheduler:
    """Schedules recurring investigations. Not yet implemented."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScheduledJob] = {}

    def add(self, email: str, cron_expression: str) -> ScheduledJob:
        raise NotImplementedError

    def remove(self, job_id: str) -> None:
        raise NotImplementedError

    def list_jobs(self) -> list[ScheduledJob]:
        return list(self._jobs.values())
