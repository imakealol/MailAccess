from .base import BaseModule, ModuleResult, ModuleStatus


class WhoisLookupModule(BaseModule):
    name = "whois_lookup"
    description = "Retrieve WHOIS registration data for the email's domain."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@")[-1]
        return ModuleResult(
            status=ModuleStatus.SKIPPED,
            metadata={"domain": domain},
            errors=["Not yet implemented — WHOIS data is available via domain_intel for custom domains"],
        )
