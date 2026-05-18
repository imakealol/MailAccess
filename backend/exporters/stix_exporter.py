from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import stix2

from .base import BaseExporter


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_date(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            dt = datetime.strptime(value[:26], fmt[:len(value[:26])])
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _account_type(platform: str) -> str:
    lower = platform.lower().strip()
    if lower.startswith("gravatar linked:"):
        lower = lower.replace("gravatar linked:", "").strip()
    return lower.replace(" ", "_")


class StixExporter(BaseExporter):
    format_name = "stix"
    content_type = "application/json"

    def export(self, _investigation_id: str, data: dict[str, Any]) -> bytes:
        email: str = data.get("email", "unknown@unknown.com")
        published: datetime = _parse_date(data.get("created_at")) or _utcnow()
        findings: list[dict] = data.get("findings", [])
        module_runs: list[dict] = data.get("module_runs", [])

        stix_objects: list[Any] = []
        all_ids: list[str] = []

        def register(obj: Any) -> Any:
            stix_objects.append(obj)
            all_ids.append(obj.id)
            return obj

        # EmailAddress SCO — anchor object for all relationships
        email_sco = register(stix2.EmailAddress(value=email))

        # Dedup helpers
        names_seen: set[str] = set()
        accounts_seen: set[tuple[str, str]] = set()
        domains_seen: set[str] = set()

        identities: list[Any] = []
        user_accounts: list[Any] = []
        breach_notes: list[Any] = []

        def add_identity(name: str) -> Any | None:
            n = (name or "").strip()
            if not n or n in names_seen:
                return None
            names_seen.add(n)
            obj = register(stix2.Identity(name=n, identity_class="individual"))
            identities.append(obj)
            return obj

        def add_user_account(
            platform: str,
            username: str,
            display_name: str | None = None,
        ) -> Any | None:
            u = (username or "").strip()
            p = (platform or "").strip()
            if not u or not p:
                return None
            key = (_account_type(p), u.lower())
            if key in accounts_seen:
                return None
            accounts_seen.add(key)
            kwargs: dict[str, Any] = {
                "user_id": u,
                "account_type": _account_type(p),
            }
            if display_name:
                kwargs["display_name"] = display_name
            obj = register(stix2.UserAccount(**kwargs))
            user_accounts.append(obj)
            return obj

        def add_domain(domain: str) -> Any | None:
            d = (domain or "").strip().lower()
            if not d or d in domains_seen:
                return None
            domains_seen.add(d)
            obj = register(stix2.DomainName(value=d))
            return obj

        # DomainName from domain_intel module run metadata
        for run in module_runs:
            if run.get("module_name") == "domain_intel":
                meta = run.get("run_metadata") or {}
                if not meta.get("is_free_provider"):
                    add_domain(meta.get("domain", ""))

        # Process findings
        for finding in findings:
            module_name: str = finding.get("module_name", "")
            fdata: dict = finding.get("data") or {}
            platform: str = fdata.get("platform", "")
            meta: dict = fdata.get("metadata") or {}

            if module_name in ("hibp", "haveibeenpwned"):
                breach_name = (meta.get("name") or "Unknown Breach").strip()
                data_classes: list[str] = meta.get("data_classes") or []
                content = (
                    f"{breach_name} — {', '.join(data_classes)}"
                    if data_classes
                    else breach_name
                )
                note_kwargs: dict[str, Any] = {
                    "content": content,
                    "abstract": "Data Breach Exposure",
                    "object_refs": [email_sco.id],
                }
                breach_dt = _parse_date(meta.get("breach_date"))
                if breach_dt:
                    note_kwargs["created"] = breach_dt
                breach_notes.append(register(stix2.Note(**note_kwargs)))

            elif module_name in ("social", "social_links", "gravatar"):
                display_name: str | None = meta.get("display_name")
                username: str | None = meta.get("username")

                if display_name:
                    add_identity(display_name)
                if username:
                    add_user_account(platform, username, display_name)

                # Gravatar profile links accounts on other platforms
                if module_name == "gravatar":
                    for acc in (meta.get("accounts") or []):
                        shortname = acc.get("shortname", "")
                        acc_display = (
                            acc.get("display")
                            or acc.get("username")
                            or acc.get("shortname", "")
                        )
                        if shortname and acc_display:
                            add_user_account(shortname, acc_display)

                # Social module emits "Gravatar Linked: <platform>" findings
                if "gravatar linked:" in platform.lower():
                    acc_display = meta.get("display") or meta.get("username") or meta.get("shortname")
                    if acc_display:
                        add_user_account(platform, acc_display)

            elif module_name == "domain_intel":
                # WHOIS registrant name → Identity
                registrant_name: str | None = meta.get("registrant_name")
                if registrant_name:
                    add_identity(registrant_name)

        # Relationships
        for ua in user_accounts:
            register(stix2.Relationship(
                relationship_type="related-to",
                source_ref=email_sco.id,
                target_ref=ua.id,
            ))
        for ident in identities:
            register(stix2.Relationship(
                relationship_type="attributed-to",
                source_ref=email_sco.id,
                target_ref=ident.id,
            ))
        for note in breach_notes:
            register(stix2.Relationship(
                relationship_type="related-to",
                source_ref=email_sco.id,
                target_ref=note.id,
            ))

        # Report SDO — references every object registered so far
        report = stix2.Report(
            name=f"MailAccess: {email}",
            published=published,
            object_refs=list(all_ids),
        )
        stix_objects.append(report)

        bundle = stix2.Bundle(objects=stix_objects)
        return bundle.serialize(pretty=False).encode("utf-8")
