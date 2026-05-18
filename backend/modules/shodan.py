from ..config import settings
from .base import BaseModule, ModuleResult, ModuleStatus


class ShodanModule(BaseModule):
    name = "shodan"
    description = "Search Shodan for hosts and services associated with the email's domain."
    requires_key = True

    async def run(self, email: str) -> ModuleResult:
        if not settings.shodan_api_key:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                errors=["SHODAN_API_KEY not set"],
            )
        domain = email.split("@")[-1]
        # TODO: GET https://api.shodan.io/dns/domain/{domain}?key=...
        return ModuleResult(status=ModuleStatus.SUCCESS, metadata={"domain": domain})
