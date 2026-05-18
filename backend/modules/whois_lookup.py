from .base import BaseModule, ModuleResult, ModuleStatus


class WhoisLookupModule(BaseModule):
    name = "whois_lookup"
    description = "Retrieve WHOIS registration data for the email's domain."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@")[-1]
        # TODO: implement using python-whois (run in executor to avoid blocking)
        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            metadata={"domain": domain},
        )
