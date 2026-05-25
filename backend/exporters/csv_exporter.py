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

        exposure_score = data.get("exposure_score")
        credential_score = data.get("credential_risk_score")
        credential_band = data.get("credential_risk_band", "")
        score_drivers = " | ".join(str(item) for item in data.get("score_drivers", []))
        recommended_actions = " | ".join(
            str(item) for item in data.get("recommended_actions", [])
        )
        email = data.get("email", "")

        writer.writerow(
            [
                "investigation_id",
                "email",
                "exposure_score",
                "credential_risk_score",
                "credential_risk_band",
                "score_drivers",
                "recommended_actions",
                "timestamp",
                "module_name",
                "platform",
                "profile_url",
                "confidence",
                "severity",
                "metadata_json",
                "status",
            ]
        )

        findings = data.get("findings", [])
        if not findings:
            writer.writerow(
                [
                    investigation_id,
                    email,
                    exposure_score if exposure_score is not None else "",
                    credential_score if credential_score is not None else "",
                    credential_band,
                    score_drivers,
                    recommended_actions,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "{}",
                    "",
                ]
            )
            return buf.getvalue().encode("utf-8")

        for finding in findings:
            f_data = finding.get("data", {})
            metadata = f_data.get("metadata", {})
            metadata_json = json.dumps(metadata) if metadata else "{}"
            writer.writerow(
                [
                    investigation_id,
                    email,
                    exposure_score if exposure_score is not None else "",
                    credential_score if credential_score is not None else "",
                    credential_band,
                    score_drivers,
                    recommended_actions,
                    finding.get("created_at", ""),
                    finding.get("module_name", ""),
                    f_data.get("platform", ""),
                    f_data.get("profile_url", ""),
                    f_data.get("confidence", ""),
                    f_data.get("severity", ""),
                    metadata_json,
                    f_data.get("status", ""),
                ]
            )

        return buf.getvalue().encode("utf-8")
