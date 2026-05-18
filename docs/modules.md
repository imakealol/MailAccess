# Module Reference

Modules are auto-discovered from `backend/modules/` at startup. Each module runs concurrently with all others, subject to `MAX_CONCURRENT_MODULES` and `MODULE_TIMEOUT_SECONDS`.

A module marked **key required** skips itself with `status: skipped` when its API key is absent — it does not cause the investigation to fail.

---

## `hibp`

Check if the email address appears in known data breaches via the HaveIBeenPwned v3 API.

| | |
|--|--|
| **Requires key** | Yes — `HIBP_API_KEY` |
| **Status** | Implemented |

**Findings schema (one per breach):**
```json
{
  "platform": "HaveIBeenPwned",
  "url": "https://haveibeenpwned.com/PwnedWebsites#Adobe",
  "metadata": {
    "name": "Adobe",
    "domain": "adobe.com",
    "breach_date": "2013-10-04",
    "description": "...",
    "data_classes": ["Email addresses", "Passwords"],
    "is_sensitive": false,
    "is_verified": true,
    "pwn_count": 152445165,
    "severity": "critical"
  },
  "confidence": "high"
}
```

Severity is derived from `data_classes`: `critical` if passwords or financial data are present, `high` if phone numbers or addresses, `medium` otherwise.

**Module metadata:**
```json
{
  "total_breaches": 3,
  "breach_dates": "2013-10-04 to 2023-01-01",
  "most_critical_breach": "Adobe",
  "all_data_classes": ["Email addresses", "Passwords"]
}
```

---

## `emailrep`

Query EmailRep.io for a reputation score, risk flags, and linked profiles.

| | |
|--|--|
| **Requires key** | No (a key raises the rate limit — set `EMAILREP_API_KEY` if querying at volume) |
| **Status** | Implemented |

**Findings schema (one finding per investigation):**
```json
{
  "platform": "emailrep",
  "confidence": "high",
  "severity": "high",
  "metadata": {
    "reputation": "high",
    "suspicious": false,
    "references": 12,
    "blacklisted": false,
    "malicious_activity": false,
    "credentials_leaked": true,
    "data_breach": true,
    "last_seen": "2024-01-15",
    "spam": false,
    "free_provider": true,
    "disposable": false,
    "profiles": ["twitter", "linkedin"]
  }
}
```

---

## `gravatar`

Look up Gravatar and Libravatar profiles linked to the email address.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

The email is hashed with MD5 (Gravatar standard). If a profile exists, the finding includes the display name, thumbnail URL, and any linked third-party accounts the user has added to their Gravatar profile.

**Findings schema:**
```json
{
  "platform": "Gravatar",
  "url": "https://www.gravatar.com/abc123",
  "metadata": {
    "display_name": "Jane Doe",
    "thumbnail_url": "https://www.gravatar.com/avatar/abc123",
    "profile_url": "https://www.gravatar.com/abc123",
    "accounts": [...],
    "location": "San Francisco",
    "verified_accounts": [...]
  },
  "confidence": "high"
}
```

A Libravatar finding (confidence `low`) is added if an avatar is hosted there.

---

## `google_dork`

Run Google dork queries via SerpAPI to surface public mentions of the email address.

| | |
|--|--|
| **Requires key** | Yes — `SERPAPI_KEY` |
| **Status** | Implemented |

Runs 5 dork templates concurrently:
- `site:linkedin.com "{email}"`
- `site:github.com "{email}"`
- `"{email}" site:pastebin.com`
- `"{email}" filetype:pdf OR filetype:csv OR filetype:xlsx`
- `intext:"{email}" -site:linkedin.com -site:github.com`

Up to 5 results per dork are returned as findings with platform inferred from the URL.

**Module metadata:**
```json
{
  "total_results_found": 8,
  "dorks_run": 5,
  "dorks_with_hits": 3
}
```

---

## `domain_intel`

WHOIS registration data, DNS security signals (SPF / DMARC / MX), website presence, and optionally Shodan host data for the email's domain.

| | |
|--|--|
| **Requires key** | No (Shodan lookup is added automatically when `SHODAN_API_KEY` is set) |
| **Status** | Implemented |

Skips free email providers (Gmail, Outlook, ProtonMail, etc.) — these are not worth querying for domain ownership.

Runs four checks concurrently: WHOIS, DNS, website HTTP fetch, and (if a Shodan key is present) Shodan subdomain and port data.

**Findings:** One finding per check (`whois`, `dns`, `website`, `shodan`), each with `platform` set to the check name.

**DNS finding example:**
```json
{
  "platform": "dns",
  "confidence": "high",
  "metadata": {
    "mx_records": ["aspmx.l.google.com"],
    "mx_provider": "google",
    "spf_record": "v=spf1 include:_spf.google.com ~all",
    "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "has_spf": true,
    "has_dmarc": true,
    "a_records": ["93.184.216.34"],
    "ns_records": ["ns1.example.com"]
  }
}
```

---

## `social`

Check account existence across 13 social and productivity platforms.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Platforms checked: GitHub, Duolingo, Spotify, Gravatar (linked accounts), Adobe, Patreon, Snapchat, Skype / Microsoft, Zoom, Dropbox, Apple ID, LinkedIn, Discord.

Detection methods vary by platform — some use public search APIs (GitHub), others infer existence from password-reset or registration flows. Confidence is `high` for direct API matches and `medium` / `low` for inferred results.

**Finding example:**
```json
{
  "platform": "GitHub",
  "profile_url": "https://github.com/janedoe",
  "metadata": {
    "login": "janedoe",
    "name": "Jane Doe",
    "bio": "...",
    "location": "San Francisco",
    "public_repos": 24,
    "followers": 180
  },
  "confidence": "high"
}
```

> LinkedIn, Snapchat, and several others aggressively block automated requests. These findings carry `medium` or `low` confidence and may be absent entirely when the platform changes its behavior.

---

## `hunter_io`

Verify email deliverability and retrieve associated domain information via the Hunter.io API.

| | |
|--|--|
| **Requires key** | Yes — `HUNTER_IO_API_KEY` |
| **Status** | Stub (returns empty success) |

---

## `dns_lookup`

Resolve MX, SPF, DMARC, and DKIM DNS records for the email's domain.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Stub — use `domain_intel` for a fully implemented DNS check |

---

## `whois_lookup`

Retrieve WHOIS registration data for the email's domain.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Stub — use `domain_intel` for a fully implemented WHOIS check |

---

## `shodan`

Search Shodan for hosts and services associated with the email's domain.

| | |
|--|--|
| **Requires key** | Yes — `SHODAN_API_KEY` |
| **Status** | Stub — `domain_intel` performs Shodan lookup automatically when the key is set |

---

## `social_links`

Discover social media profiles plausibly linked to the email address by deriving a username from the local part.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Stub |

---

## `google_search`

Perform Google search queries to surface public mentions of the email.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Stub — use `google_dork` (with `SERPAPI_KEY`) for implemented search |

---

## Adding a Module

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-module) for the full interface contract.
