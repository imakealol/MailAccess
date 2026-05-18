import asyncio
import hashlib

from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus


class GravatarModule(BaseModule):
    name = "gravatar"
    description = "Look up Gravatar profile and avatar associated with the email address."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        email_clean = email.strip().lower()
        md5_hash = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
        sha256_hash = hashlib.sha256(email_clean.encode("utf-8")).hexdigest()

        findings = []
        errors = []

        async with build_client(timeout=8.0, follow_redirects=True) as client:
            gravatar_url = f"https://www.gravatar.com/{md5_hash}.json"
            libravatar_url = f"https://www.libravatar.org/avatar/{md5_hash}?d=404"
            
            grav_task = client.get(gravatar_url)
            librav_task = client.get(libravatar_url)
            
            grav_res, librav_res = await asyncio.gather(grav_task, librav_task, return_exceptions=True)

        # Process Gravatar
        if isinstance(grav_res, Exception):
            errors.append(f"Gravatar error: {str(grav_res)}")
        else:
            try:
                if grav_res.status_code == 200:
                    data = grav_res.json()
                    if data.get("entry"):
                        entry = data["entry"][0]
                        metadata = {
                            "display_name": entry.get("displayName"),
                            "thumbnail_url": entry.get("thumbnailUrl"),
                            "profile_url": entry.get("profileUrl"),
                            "accounts": entry.get("accounts", []),
                            "location": entry.get("currentLocation"),
                            "about_me": entry.get("aboutMe"),
                            "verified_accounts": entry.get("verifiedAccounts", [])
                        }
                        # Drop None values
                        metadata = {k: v for k, v in metadata.items() if v is not None}
                        
                        findings.append({
                            "platform": "Gravatar",
                            "url": entry.get("profileUrl", f"https://www.gravatar.com/{md5_hash}"),
                            "metadata": metadata,
                            "confidence": "high"
                        })
                elif grav_res.status_code != 404:
                    errors.append(f"Gravatar HTTP error: {grav_res.status_code}")
            except Exception as e:
                errors.append(f"Gravatar parsing error: {str(e)}")

        # Process Libravatar
        if isinstance(librav_res, Exception):
            errors.append(f"Libravatar error: {str(librav_res)}")
        else:
            if librav_res.status_code == 200:
                findings.append({
                    "platform": "Libravatar",
                    "url": f"https://www.libravatar.org/avatar/{md5_hash}",
                    "metadata": {},
                    "confidence": "low"
                })
            elif librav_res.status_code not in (404,):
                errors.append(f"Libravatar HTTP error: {librav_res.status_code}")

        status = ModuleStatus.SUCCESS
        if errors:
            status = ModuleStatus.PARTIAL if findings else ModuleStatus.FAILED

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "md5_hash": md5_hash,
                "sha256_hash": sha256_hash
            },
            errors=errors
        )
