from __future__ import annotations

import asyncio

_queues: dict[str, asyncio.Queue] = {}


def put(investigation_id: str, queue: asyncio.Queue) -> None:
    _queues[investigation_id] = queue


def pop(investigation_id: str) -> asyncio.Queue | None:
    return _queues.pop(investigation_id, None)
