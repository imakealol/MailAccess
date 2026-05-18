from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from backend.config import settings
from backend.core.engine import _BREACH_MODULES
from backend.modules.base import ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)


class WebhookDispatcher:
    def __init__(self) -> None:
        self.slack_url = settings.slack_webhook_url
        self.discord_url = settings.discord_webhook_url

    async def dispatch(
        self, email: str, score: int, collected: dict[str, ModuleResult]
    ) -> None:
        if not self.slack_url and not self.discord_url:
            return

        modules_run = [
            name for name, res in collected.items() if res.status != ModuleStatus.FAILED
        ]
        modules_run_str = ", ".join(modules_run) if modules_run else "None"

        breach_findings = []
        accounts_found = 0

        for name, res in collected.items():
            if res.status in (ModuleStatus.SUCCESS, ModuleStatus.PARTIAL):
                if name in _BREACH_MODULES:
                    for finding in res.findings:
                        breach_name = finding.get("Name", finding.get("name", finding.get("title", "Unknown Breach")))
                        breach_findings.append(breach_name)
                else:
                    accounts_found += len(res.findings)

        breaches_found = len(breach_findings)

        if score < 25:
            risk_level = "🟢 low"
            discord_color = 0x22D3EE
        elif score < 50:
            risk_level = "🟡 medium"
            discord_color = 0x22D3EE
        elif score < 75:
            risk_level = "🔴 high"
            discord_color = 0x22D3EE
        else:
            risk_level = "⛔ critical"
            discord_color = 0xFF4444

        timestamp_iso = datetime.now(timezone.utc).isoformat()

        tasks = []
        async with httpx.AsyncClient(timeout=10.0) as client:
            if self.slack_url:
                tasks.append(
                    self._send_slack(
                        client,
                        email,
                        score,
                        risk_level,
                        accounts_found,
                        breaches_found,
                        modules_run_str,
                        breach_findings,
                        timestamp_iso,
                    )
                )
            if self.discord_url:
                tasks.append(
                    self._send_discord(
                        client,
                        email,
                        score,
                        risk_level,
                        accounts_found,
                        breaches_found,
                        modules_run_str,
                        breach_findings,
                        discord_color,
                        timestamp_iso,
                    )
                )

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, Exception):
                        logger.error(f"Webhook dispatch failed: {res}")

    async def _send_slack(
        self,
        client: httpx.AsyncClient,
        email: str,
        score: int,
        risk_level: str,
        accounts_found: int,
        breaches_found: int,
        modules_run_str: str,
        breach_findings: list[str],
        timestamp_iso: str,
    ) -> None:
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "MailAccess Investigation Complete",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Email:* {email}\n*Timestamp:* {timestamp_iso}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Exposure Score:*\n{score}/100"},
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n{risk_level}"},
                    {"type": "mrkdwn", "text": f"*Accounts Found:*\n{accounts_found}"},
                    {"type": "mrkdwn", "text": f"*Breaches Found:*\n{breaches_found}"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Modules run: {modules_run_str}"}
                ],
            },
        ]

        if breaches_found > 0:
            blocks.append({"type": "divider"})
            breach_list_str = "\n".join(f"• {b}" for b in breach_findings)
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Identified Breaches:*\n{breach_list_str}",
                    },
                }
            )

        payload = {"blocks": blocks}
        resp = await client.post(self.slack_url, json=payload)
        resp.raise_for_status()

    async def _send_discord(
        self,
        client: httpx.AsyncClient,
        email: str,
        score: int,
        risk_level: str,
        accounts_found: int,
        breaches_found: int,
        modules_run_str: str,
        breach_findings: list[str],
        color: int,
        timestamp_iso: str,
    ) -> None:
        embed = {
            "title": f"MailAccess — {email}",
            "description": f"**Exposure Score:** {score}/100\n**Risk Level:** {risk_level}",
            "color": color,
            "timestamp": timestamp_iso,
            "footer": {"text": "MailAccess OSINT Tool"},
            "fields": [
                {
                    "name": "Accounts Found",
                    "value": str(accounts_found),
                    "inline": True,
                },
                {
                    "name": "Breaches Found",
                    "value": str(breaches_found),
                    "inline": True,
                },
                {"name": "Modules Run", "value": modules_run_str, "inline": False},
            ],
        }

        if breaches_found > 0:
            # Discord limit is 1024 characters per field value
            breach_list_str = "\n".join(f"• {b}" for b in breach_findings)[:1024]
            embed["fields"].append(
                {
                    "name": "Identified Breaches",
                    "value": breach_list_str,
                    "inline": False,
                }
            )

        payload = {"embeds": [embed]}
        resp = await client.post(self.discord_url, json=payload)
        resp.raise_for_status()
