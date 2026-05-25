from __future__ import annotations

import json
from datetime import date, datetime
from enum import Enum
from typing import Any

from .base import BaseExporter


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


class JsonExporter(BaseExporter):
    format_name = "json"
    content_type = "application/json"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        payload = {"investigation_id": investigation_id, **data}
        payload.pop("credential_risk", None)
        return json.dumps(payload, cls=CustomJSONEncoder, indent=2).encode("utf-8")
