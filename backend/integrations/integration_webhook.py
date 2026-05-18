import hashlib
import hmac
import json
import logging

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)


class IntegrationWebhookDispatcher:
    def __init__(self) -> None:
        self.url = settings.integration_webhook_url
        self.secret = settings.integration_webhook_secret

    async def dispatch(self, payload: dict) -> None:
        if not self.url:
            return

        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        if self.secret:
            signature = hmac.new(
                self.secret.encode("utf-8"),
                body,
                hashlib.sha256
            ).hexdigest()
            headers["X-MailAccess-Signature"] = signature

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self.url, content=body, headers=headers)
                resp.raise_for_status()
                logger.info(f"Integration webhook delivered successfully to {self.url}")
        except Exception as e:
            logger.error(f"Integration webhook failed to deliver to {self.url}: {e}")
