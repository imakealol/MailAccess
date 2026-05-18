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
        lines.append(f"> {email} — {timestamp}")
        lines.append("")
        
        # Executive Summary
        score = data.get("exposure_score")
        risk = data.get("risk_level", "unknown")
        findings = data.get("findings", [])
        total_findings = len(findings)
        breach_count = sum(1 for f in findings if f.get("module_name", "").lower() == "hibp")
        
        runs = data.get("module_runs", [])
        modules_run = len(runs)
        modules_failed = sum(1 for r in runs if r.get("status") == "failed")
        
        lines.append("## Executive Summary")
        lines.append("| Field | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Exposure Score | {score if score is not None else 'N/A'} |")
        lines.append(f"| Risk Level | {risk} |")
        lines.append(f"| Total Findings | {total_findings} |")
        lines.append(f"| Breach Count | {breach_count} |")
        lines.append(f"| Modules Run | {modules_run} |")
        lines.append(f"| Modules Failed | {modules_failed} |")
        lines.append("")
        
        # Findings by Module
        lines.append("## Findings by Module")
        findings_by_module = data.get("findings_by_module", {})
        runs_by_module = {r.get("module_name"): r for r in runs}
        
        if not findings_by_module:
            lines.append("No findings.\n")
            
        for module_name, module_findings in findings_by_module.items():
            run_info = runs_by_module.get(module_name, {})
            status = run_info.get("status", "unknown")
            lines.append(f"### {module_name} — {status}")
            
            for f_data in module_findings:
                platform = f_data.get("platform", "Unknown Platform")
                lines.append(f"#### {platform}")
                
                metadata = f_data.get("metadata") or {}
                if metadata:
                    has_rows = False
                    for k, v in metadata.items():
                        if v is not None and v != "":
                            if not has_rows:
                                lines.append("| Key | Value |")
                                lines.append("| --- | --- |")
                                has_rows = True
                            lines.append(f"| {k} | {v} |")
                    if has_rows:
                        lines.append("")
                
                profile_url = f_data.get("profile_url")
                if profile_url:
                    lines.append(f"[Profile URL]({profile_url})")
                    lines.append("")
        
        # Metadata Table
        lines.append("## Metadata Table")
        lines.append("| Data Type | Value | Source Module |")
        lines.append("| --- | --- | --- |")
        
        metadata_rows = []
        seen = set()
        
        for f in findings:
            mod = f.get("module_name", "unknown")
            f_data = f.get("data", {})
            meta = f_data.get("metadata", {})
            
            for k, v in meta.items():
                if not v:
                    continue
                k_lower = k.lower()
                data_type = None
                
                if "name" in k_lower and "username" not in k_lower:
                    data_type = "names"
                elif "username" in k_lower:
                    data_type = "usernames"
                elif "photo" in k_lower or "avatar" in k_lower or "image" in k_lower or "thumbnail" in k_lower:
                    data_type = "photos"
                elif "phone" in k_lower:
                    data_type = "phones"
                elif "location" in k_lower:
                    data_type = "locations"
                
                if data_type:
                    vals = v if isinstance(v, list) else [v]
                    for val in vals:
                        val_str = str(val).strip()
                        if not val_str:
                            continue
                        sig = (data_type, val_str, mod)
                        if sig not in seen:
                            seen.add(sig)
                            metadata_rows.append(sig)
                            
        if metadata_rows:
            metadata_rows.sort(key=lambda x: (x[0], x[1]))
            for dt, val, mod in metadata_rows:
                lines.append(f"| {dt} | {val} | {mod} |")
        else:
            lines.append("| No recovered data points | - | - |")
        lines.append("")
        
        # Module Run Log
        lines.append("## Module Run Log")
        lines.append("| Module | Status | Findings Count | Errors |")
        lines.append("| --- | --- | --- | --- |")
        
        for r in runs:
            mod = r.get("module_name", "unknown")
            status = r.get("status", "unknown")
            err = r.get("error") or ""
            count = len(findings_by_module.get(mod, []))
            lines.append(f"| {mod} | {status} | {count} | {err} |")
            
        return "\n".join(lines).encode("utf-8")
