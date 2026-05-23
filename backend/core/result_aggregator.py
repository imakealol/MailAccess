from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class UnifiedProfile:
    """Deduplicated identity signals extracted across all module findings."""

    names: list[str] = field(default_factory=list)
    photos: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    discovered_emails: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    # Confirmed or probed accounts: breach-confirmed domains + social/discovery hits
    accounts_found: list[dict] = field(default_factory=list)


class ProfileAggregator:
    """
    Merges a flat list of findings from multiple modules into a UnifiedProfile.

    Each finding may be either:
    - a raw module dict:   {"name": "Alice", "username": "alice42", ...}
    - a DB-loaded dict:    {"id": "...", "module_name": "...", "data": {...}, ...}

    Field aliases cover the naming conventions used across different OSINT APIs.
    """

    _NAME_KEYS = frozenset({"name", "display_name", "full_name", "real_name"})
    _PHOTO_KEYS = frozenset(
        {"photo", "photo_url", "avatar", "avatar_url", "image", "image_url", "thumbnail"}
    )
    _USERNAME_KEYS = frozenset(
        {"username", "handle", "login", "screen_name", "nickname", "user_name"}
    )
    _PHONE_KEYS = frozenset({"phone", "phone_number", "mobile", "telephone", "tel"})
    _EMAIL_KEYS = frozenset({"email", "email_address", "contact_email"})
    _LOCATION_KEYS = frozenset(
        {"location", "city", "country", "region", "address", "geo"}
    )

    # Platforms whose findings are breach-event records, not account-presence signals
    _BREACH_EVENT_PLATFORMS = frozenset({"HaveIBeenPwned"})

    def merge(self, findings: list[dict]) -> UnifiedProfile:
        """Extract and deduplicate identity fields from a list of findings."""
        names: set[str] = set()
        photos: set[str] = set()
        usernames: set[str] = set()
        phones: set[str] = set()
        emails: set[str] = set()
        discovered_emails: set[str] = set()
        locations: set[str] = set()
        accounts: dict[str, dict] = {}  # keyed by platform for dedup

        for finding in findings:
            # DB-loaded findings wrap the payload under "data"; raw findings are flat
            payload: dict = finding.get("data", finding)
            if not isinstance(payload, dict):
                continue

            module_name = str(finding.get("module_name", "")).lower()
            metadata = payload.get("metadata")
            if (
                (
                    module_name == "email_discovery"
                    or payload.get("platform") == "email_discovery"
                )
                and isinstance(metadata, dict)
                and isinstance(metadata.get("discovered_email"), str)
            ):
                discovered_emails.add(metadata["discovered_email"].strip().lower())

            # Collect account-presence signals
            platform = payload.get("platform")
            if platform and platform not in self._BREACH_EVENT_PLATFORMS:
                if platform not in accounts:
                    accounts[platform] = {
                        "platform": platform,
                        "source": payload.get("source") or "probed",
                        "confidence": payload.get("confidence"),
                        "url": payload.get("profile_url") or payload.get("url"),
                    }

            for key, value in payload.items():
                if not isinstance(value, str) or not value.strip():
                    continue
                val = value.strip()
                key_lower = key.lower()

                if key_lower in self._NAME_KEYS:
                    names.add(val)
                elif key_lower in self._PHOTO_KEYS:
                    photos.add(val)
                elif key_lower in self._USERNAME_KEYS:
                    usernames.add(val.lower())
                elif key_lower in self._PHONE_KEYS:
                    phones.add(val)
                elif key_lower in self._EMAIL_KEYS:
                    emails.add(val.lower())
                elif key_lower in self._LOCATION_KEYS:
                    locations.add(val)

        return UnifiedProfile(
            names=sorted(names),
            photos=sorted(photos),
            usernames=sorted(usernames),
            phones=sorted(phones),
            emails=sorted(emails),
            discovered_emails=sorted(discovered_emails),
            locations=sorted(locations),
            accounts_found=sorted(accounts.values(), key=lambda a: a["platform"]),
        )
