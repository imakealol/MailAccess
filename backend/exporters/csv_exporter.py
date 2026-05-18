from __future__ import annotations

import csv
import io
import json
from typing import Any

from .base import BaseExporter


class CsvExporter(BaseExporter):
    format_name = "csv"
    content_type = "text/csv"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "investigation_id",
            "email",
            "timestamp",
            "module_name",
            "platform",
            "profile_url",
            "confidence",
            "severity",
            "metadata_json",
            "status",
        ])
        
        email = data.get("email", "")
        
        for f in data.get("findings", []):
            f_data = f.get("data", {})
            metadata = f_data.get("metadata", {})
            metadata_json = json.dumps(metadata) if metadata else "{}"
            
            writer.writerow([
                investigation_id,
                email,
                f.get("created_at", ""),
                f.get("module_name", ""),
                f_data.get("platform", ""),
                f_data.get("profile_url", ""),
                f_data.get("confidence", ""),
                f_data.get("severity", ""),
                metadata_json,
                f_data.get("status", ""),
            ])
            
        return buf.getvalue().encode("utf-8")
