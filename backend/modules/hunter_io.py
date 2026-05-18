from ..config import settings
from .base import BaseModule, ModuleResult, ModuleStatus


class HunterIoModule(BaseModule):
    name = "hunter_io"
    description = "Verify email deliverability and find associated domain info via Hunter.io."
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        if not settings.hunter_io_api_key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["HUNTER_IO_API_KEY not set"],
            )
        # TODO: GET https://api.hunter.io/v2/email-verifier?email={email}&api_key=...
        return ModuleResult(status=ModuleStatus.SUCCESS)
