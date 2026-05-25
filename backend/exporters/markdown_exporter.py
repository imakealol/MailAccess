from __future__ import annotations

from typing import Any

from .base import BaseExporter


class MarkdownExporter(BaseExporter):
    format_name = "markdown"
    content_type = "text/markdown"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        lines: list[str] = []

        email = data.get("email", "unknown")
        timestamp = data.get("created_at", "unknown")

        lines.append("# MailAccess Investigation Report")
        lines.append(f"> {email} - {timestamp}")
        lines.append("")

        score = data.get("exposure_score")
        risk = data.get("risk_level", "unknown")
        credential_score = data.get("credential_risk_score")
        credential_band = data.get("credential_risk_band", "UNKNOWN")
        findings = data.get("findings", [])
        total_findings = len(findings)
        breach_count = sum(
            1
            for finding in findings
            if finding.get("module_name", "").lower()
            in ("hibp", "haveibeenpwned", "xposedornot")
        )

        runs = data.get("module_runs", [])
        modules_run = len(runs)
        modules_failed = sum(1 for run in runs if run.get("status") == "failed")

        lines.append("## Executive Summary")
        lines.append("| Field | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Exposure Score | {score if score is not None else 'N/A'} |")
        lines.append(f"| Risk Level | {risk} |")
        lines.append(
            f"| Credential Risk | {credential_score if credential_score is not None else 'N/A'} ({credential_band}) |"
        )
        lines.append(f"| Total Findings | {total_findings} |")
        lines.append(f"| Breach Count | {breach_count} |")
        lines.append(f"| Modules Run | {modules_run} |")
        lines.append(f"| Modules Failed | {modules_failed} |")
        lines.append("")

        lines.append("## Credential Risk Drivers")
        drivers = data.get("score_drivers", []) or ["No credential risk drivers recorded."]
        for driver in drivers:
            if driver == "No credential risk drivers recorded.":
                lines.append(driver)
            else:
                lines.append(f"- {driver}")
        lines.append("")

        lines.append("## Recommended Actions")
        actions = data.get("recommended_actions", []) or ["No follow-up actions recorded."]
        for action in actions:
            if action == "No follow-up actions recorded.":
                lines.append(action)
            else:
                lines.append(f"- {action}")
        lines.append("")

        lines.append("## Findings by Module")
        findings_by_module = data.get("findings_by_module", {})
        runs_by_module = {run.get("module_name"): run for run in runs}

        if not findings_by_module:
            lines.append("No findings.\n")

        for module_name, module_findings in findings_by_module.items():
            run_info = runs_by_module.get(module_name, {})
            status = run_info.get("status", "unknown")
            lines.append(f"### {module_name} - {status}")

            for f_data in module_findings:
                platform = f_data.get("platform", "Unknown Platform")
                lines.append(f"#### {platform}")

                metadata = f_data.get("metadata") or {}
                if metadata:
                    has_rows = False
                    for key, value in metadata.items():
                        if value is not None and value != "":
                            if not has_rows:
                                lines.append("| Key | Value |")
                                lines.append("| --- | --- |")
                                has_rows = True
                            lines.append(f"| {key} | {value} |")
                    if has_rows:
                        lines.append("")

                profile_url = f_data.get("profile_url")
                if profile_url:
                    lines.append(f"[Profile URL]({profile_url})")
                    lines.append("")

        lines.append("## Metadata Table")
        lines.append("| Data Type | Value | Source Module |")
        lines.append("| --- | --- | --- |")

        metadata_rows: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        for finding in findings:
            module_name = finding.get("module_name", "unknown")
            f_data = finding.get("data", {})
            meta = f_data.get("metadata", {})

            for key, value in meta.items():
                if not value:
                    continue
                key_lower = key.lower()
                data_type = None

                if "name" in key_lower and "username" not in key_lower:
                    data_type = "names"
                elif "username" in key_lower:
                    data_type = "usernames"
                elif any(token in key_lower for token in ("photo", "avatar", "image", "thumbnail")):
                    data_type = "photos"
                elif "phone" in key_lower:
                    data_type = "phones"
                elif "location" in key_lower:
                    data_type = "locations"

                if data_type:
                    values = value if isinstance(value, list) else [value]
                    for item in values:
                        value_str = str(item).strip()
                        if not value_str:
                            continue
                        sig = (data_type, value_str, module_name)
                        if sig not in seen:
                            seen.add(sig)
                            metadata_rows.append(sig)

        if metadata_rows:
            metadata_rows.sort(key=lambda item: (item[0], item[1]))
            for data_type, value, module_name in metadata_rows:
                lines.append(f"| {data_type} | {value} | {module_name} |")
        else:
            lines.append("| No recovered data points | - | - |")
        lines.append("")

        lines.append("## Module Run Log")
        lines.append("| Module | Status | Findings Count | Errors |")
        lines.append("| --- | --- | --- | --- |")

        for run in runs:
            module_name = run.get("module_name", "unknown")
            status = run.get("status", "unknown")
            error = run.get("error") or ""
            count = len(findings_by_module.get(module_name, []))
            lines.append(f"| {module_name} | {status} | {count} | {error} |")

        return "\n".join(lines).encode("utf-8")
