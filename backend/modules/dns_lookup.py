from .base import BaseModule, ModuleResult, ModuleStatus


class DnsLookupModule(BaseModule):
    name = "dns_lookup"
    description = "Resolve MX, SPF, DMARC, and DKIM DNS records for the email's domain. (domain_intel covers custom domains; this module handles free providers.)"
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@")[-1]
        return ModuleResult(
            status=ModuleStatus.SKIPPED,
            metadata={"domain": domain},
            errors=["Not yet implemented — DNS data is available via domain_intel for custom domains"],
        )
