from __future__ import annotations

import asyncio
import html as _html
from datetime import datetime, timezone
from typing import Any

from .base import BaseExporter

_RISK_CLASS = {
    "low": "risk-low",
    "medium": "risk-medium",
    "high": "risk-high",
    "critical": "risk-critical",
}

_STATUS_CLASS = {
    "success": "status-success",
    "failed": "status-failed",
    "skipped": "status-skipped",
}

_CONF_CLASS = {
    "high": "conf-high",
    "medium": "conf-medium",
    "low": "conf-low",
}


def _e(value: Any) -> str:
    if isinstance(value, list):
        return _html.escape(", ".join(str(v) for v in value))
    return _html.escape(str(value) if value is not None else "")


class PdfExporter(BaseExporter):
    format_name = "pdf"
    content_type = "application/pdf"

    def export(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        raise NotImplementedError("Use generate() for PDF export")

    async def generate(self, investigation_id: str, data: dict[str, Any]) -> bytes:
        html_content = self._build_html(investigation_id, data)
        return await asyncio.to_thread(self._render_pdf, html_content)

    # deferred import keeps WeasyPrint out of module-load path
    def _render_pdf(self, html_content: str) -> bytes:
        from weasyprint import HTML  # type: ignore[import-untyped]
        return HTML(string=html_content).write_pdf()  # type: ignore[no-any-return]

    # ── HTML assembly ────────────────────────────────────────────────────────

    def _build_html(self, investigation_id: str, data: dict[str, Any]) -> str:
        email = data.get("email", "unknown")
        score = data.get("exposure_score")
        risk = data.get("risk_level", "unknown")
        risk_class = _RISK_CLASS.get(risk, "risk-unknown")
        summary = data.get("summary", "")

        findings = data.get("findings", [])
        total_findings = len(findings)
        breach_count = sum(
            1 for f in findings
            if f.get("module_name", "").lower() in ("hibp", "haveibeenpwned")
        )

        runs = data.get("module_runs", [])
        modules_run = len(runs)
        modules_failed = sum(1 for r in runs if r.get("status") == "failed")
        findings_by_module = data.get("findings_by_module", {})

        score_display = str(score) if score is not None else "—"
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        findings_html = self._findings_html(findings_by_module, runs)
        metadata_html = self._metadata_table_html(findings)
        log_html = self._module_log_html(runs, findings_by_module)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>{self._css()}</style>
</head>
<body>

<header class="page-header">
  <div class="logo">Mail<span class="logo-access">Access</span></div>
  <div class="header-meta">
    <div class="header-email">{_e(email)}</div>
    <div>Generated {_e(generated_at)}</div>
    <div style="font-size:7pt">ID&nbsp;{_e(investigation_id)}</div>
  </div>
</header>

<section class="summary-card">
  <div class="score-row">
    <div class="score-number">{_e(score_display)}</div>
    <div>
      <div class="risk-badge {risk_class}">{_e(risk)}</div>
      <div style="font-size:7pt;color:#718096;margin-top:4px">exposure score / 100</div>
    </div>
  </div>
  <div class="stat-pills">
    <div class="pill"><strong>{_e(total_findings)}</strong>&nbsp;findings</div>
    <div class="pill"><strong>{_e(breach_count)}</strong>&nbsp;breaches</div>
    <div class="pill"><strong>{_e(modules_run)}</strong>&nbsp;modules run</div>
    <div class="pill"><strong>{_e(modules_failed)}</strong>&nbsp;failed</div>
  </div>
  <p class="summary-text">{_e(summary)}</p>
</section>

<h2>Findings by Module</h2>
{findings_html}

<h2>Recovered Data Points</h2>
{metadata_html}

<h2>Module Run Log</h2>
{log_html}

</body>
</html>"""

    def _findings_html(
        self, findings_by_module: dict[str, list], runs: list[dict]
    ) -> str:
        if not findings_by_module:
            return '<p class="empty">No findings recorded.</p>'

        runs_by_module = {r.get("module_name"): r for r in runs}
        parts: list[str] = []

        for module_name, module_findings in findings_by_module.items():
            run_info = runs_by_module.get(module_name, {})
            status = run_info.get("status", "unknown")
            status_class = _STATUS_CLASS.get(status, "status-unknown")
            cards = "".join(self._finding_card(f) for f in module_findings)

            parts.append(f"""
<div class="module-section">
  <div class="module-header">
    <span class="module-name">{_e(module_name)}</span>
    <span class="status-badge {status_class}">{_e(status)}</span>
  </div>
  {cards}
</div>""")

        return "\n".join(parts)

    def _finding_card(self, f_data: dict) -> str:
        platform = f_data.get("platform", "Unknown Platform")
        profile_url = f_data.get("profile_url") or ""
        confidence = str(f_data.get("confidence", "")).lower()
        conf_class = _CONF_CLASS.get(confidence, "conf-unknown")
        metadata = f_data.get("metadata") or {}

        url_html = (
            f'<div class="profile-url">{_e(profile_url)}</div>' if profile_url else ""
        )
        conf_html = (
            f'<span class="confidence-badge {conf_class}">{_e(confidence)}</span>'
            if confidence
            else ""
        )

        meta_rows = "".join(
            f'<tr><td class="meta-key">{_e(k)}</td>'
            f'<td class="meta-val">{_e(v)}</td></tr>'
            for k, v in metadata.items()
            if v is not None and v != ""
        )
        meta_html = (
            f'<table class="meta-table"><tbody>{meta_rows}</tbody></table>'
            if meta_rows
            else ""
        )

        return f"""
<div class="finding-card">
  <div class="finding-header">
    <span class="platform-name">{_e(platform)}</span>
    {conf_html}
  </div>
  {url_html}
  {meta_html}
</div>"""

    def _metadata_table_html(self, findings: list[dict]) -> str:
        rows: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()

        _type_map = {
            "name": lambda k: "name" in k and "username" not in k,
            "username": lambda k: "username" in k,
            "photo": lambda k: any(t in k for t in ("photo", "avatar", "image", "thumbnail")),
            "phone": lambda k: "phone" in k,
            "location": lambda k: "location" in k,
        }

        for f in findings:
            mod = f.get("module_name", "unknown")
            f_data = f.get("data", {})
            meta = f_data.get("metadata", {}) if isinstance(f_data, dict) else {}

            for k, v in meta.items():
                if not v:
                    continue
                k_lower = k.lower()
                data_type = next(
                    (dt for dt, test in _type_map.items() if test(k_lower)), None
                )
                if data_type is None:
                    continue
                for val in (v if isinstance(v, list) else [v]):
                    val_str = str(val).strip()
                    if not val_str:
                        continue
                    sig = (data_type, val_str, mod)
                    if sig not in seen:
                        seen.add(sig)
                        rows.append(sig)

        if not rows:
            return '<p class="empty">No structured data points recovered.</p>'

        rows.sort(key=lambda x: (x[0], x[1]))
        row_html = "".join(
            f"<tr><td>{_e(dt)}</td><td>{_e(val)}</td><td>{_e(src)}</td></tr>"
            for dt, val, src in rows
        )
        return (
            "<table>"
            "<thead><tr><th>Type</th><th>Value</th><th>Source</th></tr></thead>"
            f"<tbody>{row_html}</tbody>"
            "</table>"
        )

    def _module_log_html(
        self, runs: list[dict], findings_by_module: dict[str, list]
    ) -> str:
        if not runs:
            return '<p class="empty">No modules ran.</p>'

        row_html = ""
        for r in runs:
            mod = r.get("module_name", "unknown")
            status = r.get("status", "unknown")
            status_class = _STATUS_CLASS.get(status, "status-unknown")
            err = r.get("error") or "—"
            count = len(findings_by_module.get(mod, []))
            duration = r.get("duration_ms")
            dur_str = f"{duration}&nbsp;ms" if duration is not None else "—"
            row_html += (
                f"<tr>"
                f"<td>{_e(mod)}</td>"
                f'<td><span class="status-badge {status_class}">{_e(status)}</span></td>'
                f'<td style="text-align:center">{_e(count)}</td>'
                f'<td style="text-align:right">{dur_str}</td>'
                f"<td>{_e(err)}</td>"
                f"</tr>"
            )

        return (
            "<table>"
            "<thead><tr>"
            "<th>Module</th><th>Status</th>"
            '<th style="text-align:center">Findings</th>'
            '<th style="text-align:right">Duration</th>'
            "<th>Error</th>"
            "</tr></thead>"
            f"<tbody>{row_html}</tbody>"
            "</table>"
        )

    # ── CSS ─────────────────────────────────────────────────────────────────

    def _css(self) -> str:
        return """
* { box-sizing: border-box; margin: 0; padding: 0; }

@page {
  size: A4;
  margin: 14mm 12mm 20mm 12mm;
  @bottom-right {
    content: "Page " counter(page) " of " counter(pages);
    font-family: system-ui, -apple-system, 'Segoe UI', Arial, sans-serif;
    font-size: 8pt;
    color: #4a5568;
  }
  @bottom-left {
    content: "MailAccess — Confidential";
    font-family: system-ui, -apple-system, 'Segoe UI', Arial, sans-serif;
    font-size: 8pt;
    color: #4a5568;
  }
}

body {
  background: #0f1117;
  color: #e2e8f0;
  font-family: system-ui, -apple-system, 'Segoe UI', Arial, sans-serif;
  font-size: 9.5pt;
  line-height: 1.55;
}

/* ── Page header ── */
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  border-bottom: 2px solid #22d3ee;
  padding-bottom: 8px;
  margin-bottom: 18px;
}

.logo {
  font-size: 20pt;
  font-weight: 900;
  color: #22d3ee;
  letter-spacing: -0.5px;
  line-height: 1;
}
.logo-access { color: #e2e8f0; }

.header-meta {
  text-align: right;
  font-size: 8pt;
  color: #718096;
  line-height: 1.7;
}
.header-email { color: #e2e8f0; font-weight: 600; font-size: 9pt; }

/* ── Executive summary ── */
.summary-card {
  background: #1a1d27;
  border: 1px solid #2d3748;
  border-radius: 5px;
  padding: 14px 16px;
  margin-bottom: 22px;
}

.score-row {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  margin-bottom: 10px;
}

.score-number {
  font-size: 44pt;
  font-weight: 900;
  color: #22d3ee;
  line-height: 1;
  letter-spacing: -2px;
}

.risk-badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 3px;
  font-size: 10pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.risk-low      { background: #14532d; color: #22c55e; }
.risk-medium   { background: #713f12; color: #eab308; }
.risk-high     { background: #7c2d12; color: #f97316; }
.risk-critical { background: #7f1d1d; color: #ef4444; }
.risk-unknown  { background: #1f2937; color: #6b7280; }

.stat-pills { display: flex; gap: 6px; flex-wrap: wrap; }

.pill {
  background: #2d3748;
  border-radius: 20px;
  padding: 2px 9px;
  font-size: 8pt;
  color: #a0aec0;
}
.pill strong { color: #e2e8f0; }

.summary-text {
  font-size: 8.5pt;
  color: #718096;
  margin-top: 8px;
}

/* ── Section headings ── */
h2 {
  font-size: 12pt;
  color: #22d3ee;
  border-bottom: 1px solid #2d3748;
  padding-bottom: 3px;
  margin-top: 22px;
  margin-bottom: 10px;
  letter-spacing: 0.3px;
}

/* ── Module sections ── */
.module-section { margin-bottom: 18px; }

.module-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.module-name {
  font-size: 10.5pt;
  font-weight: 700;
  color: #e2e8f0;
}

.status-badge {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 3px;
  font-size: 7pt;
  font-weight: 700;
  text-transform: uppercase;
}

.status-success { background: #14532d; color: #22c55e; }
.status-failed  { background: #7f1d1d; color: #ef4444; }
.status-skipped { background: #1f2937; color: #6b7280; }
.status-unknown { background: #1f2937; color: #6b7280; }

/* ── Finding cards ── */
.finding-card {
  background: #1a1d27;
  border: 1px solid #2d3748;
  border-left: 3px solid #22d3ee;
  border-radius: 4px;
  padding: 8px 10px;
  margin-bottom: 6px;
  page-break-inside: avoid;
}

.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}

.platform-name {
  font-size: 9.5pt;
  font-weight: 700;
  color: #e2e8f0;
}

.confidence-badge {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 7pt;
  font-weight: 700;
  text-transform: uppercase;
}

.conf-high    { background: #14532d; color: #22c55e; }
.conf-medium  { background: #713f12; color: #eab308; }
.conf-low     { background: #7f1d1d; color: #ef4444; }
.conf-unknown { background: #1f2937; color: #6b7280; }

.profile-url {
  font-size: 7.5pt;
  color: #22d3ee;
  margin-bottom: 5px;
  word-break: break-all;
}

/* ── Metadata table inside finding card ── */
.meta-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 8pt;
  margin-top: 4px;
}
.meta-table td {
  padding: 2px 4px;
  vertical-align: top;
  border: none;
  background: transparent !important;
}
.meta-key { color: #718096; white-space: nowrap; width: 35%; }
.meta-val { color: #e2e8f0; }

/* ── Full-width tables (metadata + log) ── */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 8pt;
  margin-bottom: 14px;
}

th {
  background: #1e2130;
  color: #a0aec0;
  text-align: left;
  padding: 5px 8px;
  font-weight: 600;
  border-bottom: 1px solid #2d3748;
  white-space: nowrap;
}

td {
  padding: 4px 8px;
  border-bottom: 1px solid #1e2130;
  vertical-align: top;
}

tr:nth-child(odd)  td { background: #0f1117; }
tr:nth-child(even) td { background: #141720; }

.empty {
  color: #4a5568;
  font-style: italic;
  font-size: 8.5pt;
  padding: 6px 0;
}
"""
