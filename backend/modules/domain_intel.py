from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from ..config import settings
from ..core.http_client import build_client
from .base import BaseModule, ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)

_FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com",
    "icloud.com", "aol.com", "zoho.com", "gmx.com", "mail.com",
    "yandex.com", "tutanota.com", "fastmail.com", "msn.com", "live.com",
    "me.com", "pm.me", "hey.com", "duck.com", "guerrillamail.com",
}

_SHODAN_DNS_URL = "https://api.shodan.io/dns/domain/{domain}"


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _to_isoformat(value: Any) -> str | None:
    v = _first(value)
    if v is None:
        return None
    try:
        return v.isoformat()
    except AttributeError:
        return str(v)


def _sync_whois(domain: str) -> dict:
    import whois  # type: ignore[import]  # python-whois; not always installed

    data = whois.whois(domain)
    ns_raw = data.get("name_servers") or []
    name_servers = sorted({ns.lower().rstrip(".") for ns in ns_raw})[:6]
    return {
        "registrant_name": _first(data.get("name")),
        "registrant_org": _first(data.get("org")),
        "registrant_email": _first(data.get("emails")),
        "registrant_country": _first(data.get("country")),
        "creation_date": _to_isoformat(data.get("creation_date")),
        "expiration_date": _to_isoformat(data.get("expiration_date")),
        "registrar": _first(data.get("registrar")),
        "name_servers": name_servers,
    }


def _infer_mx_provider(mx_hostname: str) -> str:
    h = mx_hostname.lower()
    if "google" in h or "gmail" in h:
        return "google"
    if "microsoft" in h or "outlook" in h or "hotmail" in h:
        return "microsoft"
    if "protonmail" in h:
        return "protonmail"
    if "fastmail" in h:
        return "fastmail"
    return "other"


def _sync_dns(domain: str) -> dict:
    import dns.resolver  # type: ignore[import]  # dnspython

    result: dict[str, Any] = {
        "mx_records": [],
        "spf_record": None,
        "dmarc_record": None,
        "a_records": [],
        "ns_records": [],
        "has_spf": False,
        "has_dmarc": False,
        "mx_provider": "unknown",
    }

    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        mx_sorted = sorted(mx_answers, key=lambda r: r.preference)
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in mx_sorted]
        if result["mx_records"]:
            result["mx_provider"] = _infer_mx_provider(result["mx_records"][0])
    except Exception:
        pass

    try:
        for rdata in dns.resolver.resolve(domain, "TXT"):
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=spf1"):
                result["spf_record"] = txt
                result["has_spf"] = True
    except Exception:
        pass

    try:
        for rdata in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=DMARC1"):
                result["dmarc_record"] = txt
                result["has_dmarc"] = True
    except Exception:
        pass

    try:
        result["a_records"] = [str(r) for r in dns.resolver.resolve(domain, "A")]
    except Exception:
        pass

    try:
        result["ns_records"] = [str(r).rstrip(".") for r in dns.resolver.resolve(domain, "NS")]
    except Exception:
        pass

    return result


def _parse_head(html: str) -> tuple[str | None, str | None]:
    head_match = re.search(r"<head[^>]*>(.*?)</head>", html[:32_768], re.IGNORECASE | re.DOTALL)
    head = head_match.group(1) if head_match else html[:4_096]

    title_match = re.search(r"<title[^>]*>(.*?)</title>", head, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else None

    desc_match = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
        head,
        re.IGNORECASE | re.DOTALL,
    ) or re.search(
        r'<meta[^>]+content=["\'](.*?)["\'][^>]+name=["\']description["\']',
        head,
        re.IGNORECASE | re.DOTALL,
    )
    description = desc_match.group(1).strip() if desc_match else None

    return title, description


class DomainIntelModule(BaseModule):
    name = "domain_intel"
    description = "WHOIS registration data, DNS security signals (SPF/DMARC/MX), website presence, and optional Shodan lookup for the email's domain."
    requires_key = False

    async def run(self, email: str) -> ModuleResult:
        domain = email.split("@")[-1].lower()

        if domain in _FREE_PROVIDERS:
            return ModuleResult(
                status=ModuleStatus.SKIPPED,
                metadata={"domain": domain, "is_free_provider": True},
                errors=["free provider"],
            )

        tasks: list = [
            self._check_whois(domain),
            self._check_dns(domain),
            self._check_website(domain),
        ]
        task_names = ["whois", "dns", "website"]

        if settings.shodan_api_key:
            tasks.append(self._check_shodan(domain, settings.shodan_api_key))
            task_names.append("shodan")

        raw = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[dict] = []
        errors: list[str] = []
        checks_run: list[str] = []

        for check_name, result in zip(task_names, raw):
            checks_run.append(check_name)
            if isinstance(result, Exception):
                errors.append(f"{check_name}: unhandled exception: {result}")
                continue
            data, error = result
            if error:
                errors.append(error)
            if data is not None:
                findings.append({
                    "platform": check_name,
                    "confidence": "high" if check_name in ("whois", "dns") else "medium",
                    "metadata": data,
                })

        if not findings and errors:
            status = ModuleStatus.FAILED
        elif errors:
            status = ModuleStatus.PARTIAL
        else:
            status = ModuleStatus.SUCCESS

        return ModuleResult(
            status=status,
            findings=findings,
            metadata={
                "domain": domain,
                "is_free_provider": False,
                "checks_run": checks_run,
            },
            errors=errors,
        )

    async def _check_whois(self, domain: str) -> tuple[dict | None, str | None]:
        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(_sync_whois, domain),
                timeout=10.0,
            )
            _REGISTRANT_FIELDS = ("registrant_name", "registrant_org", "registrant_email", "registrant_country")
            if all(data.get(f) is None for f in _REGISTRANT_FIELDS):
                logger.debug("WHOIS %s: registrant data redacted or unavailable", domain)
                return data, f"whois/{domain}: registrant data redacted or unavailable (partial)"
            return data, None
        except asyncio.TimeoutError:
            return None, f"whois/{domain}: timed out after 10s"
        except Exception as exc:
            return None, f"whois/{domain}: {exc}"

    async def _check_dns(self, domain: str) -> tuple[dict | None, str | None]:
        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(_sync_dns, domain),
                timeout=6.0,
            )
            return data, None
        except asyncio.TimeoutError:
            return None, f"dns/{domain}: timed out after 6s"
        except Exception as exc:
            return None, f"dns/{domain}: {exc}"

    async def _check_website(self, domain: str) -> tuple[dict | None, str | None]:
        try:
            async with build_client(
                timeout=6.0,
                follow_redirects=True,
                max_redirects=2,
            ) as client:
                response = await client.get(f"https://{domain}")
                data: dict[str, Any] = {
                    "final_url": str(response.url),
                    "status_code": response.status_code,
                }
                if response.status_code == 200:
                    title, description = _parse_head(response.text)
                    data["title"] = title
                    data["meta_description"] = description
                return data, None
        except httpx.TimeoutException:
            return None, f"website/{domain}: timed out after 6s"
        except Exception as exc:
            return None, f"website/{domain}: {exc}"

    async def _check_shodan(self, domain: str, api_key: str) -> tuple[dict | None, str | None]:
        try:
            async with build_client(timeout=8.0) as client:
                response = await client.get(
                    _SHODAN_DNS_URL.format(domain=domain),
                    params={"key": api_key},
                )
                if response.status_code != 200:
                    return None, f"shodan/{domain}: HTTP {response.status_code}"
                body = response.json()
                subdomains = (body.get("subdomains") or [])[:10]
                ports: list[int] = []
                for entry in body.get("data") or []:
                    ports.extend(entry.get("ports") or [])
                return {
                    "subdomains": subdomains,
                    "open_ports": sorted(set(ports)),
                }, None
        except httpx.TimeoutException:
            return None, f"shodan/{domain}: timed out after 8s"
        except Exception as exc:
            return None, f"shodan/{domain}: {exc}"
