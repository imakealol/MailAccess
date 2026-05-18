from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseExporter(ABC):
    format_name: str  # e.g. "json", "csv"
    content_type: str  # MIME type for HTTP responses

    @abstractmethod
    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        """Serialize *data* to the target format and return raw bytes."""
        ...
