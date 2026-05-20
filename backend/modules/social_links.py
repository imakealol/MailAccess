from .base import BaseModule, ModuleResult, ModuleStatus


class SocialLinksModule(BaseModule):
    name = "social_links"
    description = "Discover social media profiles plausibly linked to the email address."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        username = email.split("@")[0]
        return ModuleResult(
            status=ModuleStatus.SKIPPED,
            metadata={"derived_username": username},
            errors=["Not yet implemented — account_discovery and whatsmyname cover this"],
        )
