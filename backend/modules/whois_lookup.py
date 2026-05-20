import asyncio
import whois
from datetime import datetime
from .base import BaseModule, ModuleResult, ModuleStatus
from .domain_intel import _FREE_PROVIDERS

class WhoisLookupModule(BaseModule):
    name = "whois_lookup"
    description = "Retrieve WHOIS registration data for the email's domain."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@")[-1].lower()

        if domain in _FREE_PROVIDERS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": domain},
                errors=["free provider"]
            )

        def do_whois():
            return whois.whois(domain)

        try:
            w = await asyncio.wait_for(asyncio.to_thread(do_whois), timeout=10.0)
        except Exception as e:
            return ModuleResult(
                status=ModuleStatus.ERROR,
                metadata={"domain": domain},
                errors=[f"WHOIS lookup failed: {str(e)}"]
            )

        def parse_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d
            return None

        creation_date = parse_date(w.creation_date)
        expiration_date = parse_date(w.expiration_date)
        updated_date = parse_date(w.updated_date)

        registrar = w.registrar
        registrant_name = w.name
        registrant_org = w.org
        registrant_email = w.emails
        registrant_country = w.country
        name_servers = w.name_servers
        status = w.status

        if isinstance(registrant_email, list):
            registrant_email = registrant_email[0]
        
        is_privacy_protected = False
        privacy_keywords = ["privacy", "redacted", "protected", "whoisguard"]
        check_fields = [
            str(registrant_name).lower(), str(registrant_org).lower(), 
            str(registrant_email).lower(), str(registrar).lower()
        ]
        
        for field in check_fields:
            if any(kw in field for kw in privacy_keywords):
                is_privacy_protected = True
                break

        domain_age_days = None
        if creation_date:
            domain_age_days = (datetime.now() - creation_date).days

        is_expired = False
        if expiration_date:
            is_expired = expiration_date < datetime.now()

        metadata_raw = {
            "registrant_name": registrant_name,
            "registrant_org": registrant_org,
            "registrant_email": registrant_email,
            "registrant_country": registrant_country,
            "registrar": registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
            "updated_date": updated_date.isoformat() if updated_date else None,
            "name_servers": name_servers,
            "status": status,
        }

        metadata_clean = {k: v for k, v in metadata_raw.items() if v is not None}
        confidence = "medium" if is_privacy_protected else "high"

        finding = {
            "platform": "whois",
            "metadata": metadata_clean,
            "confidence": confidence
        }

        module_metadata = {
            "domain": domain,
            "is_privacy_protected": is_privacy_protected,
            "registrar": registrar,
            "domain_age_days": domain_age_days,
            "is_expired": is_expired
        }
        module_metadata = {k: v for k, v in module_metadata.items() if v is not None}

        return ModuleResult(
            status=ModuleStatus.SUCCESS,
            metadata=module_metadata,
            findings=[finding]
        )
