# Module Reference

MailAccess ships 11 modules covering 800+ platforms. Modules are auto-discovered from `backend/modules/` at startup. Each module runs concurrently with all others, subject to `MAX_CONCURRENT_MODULES` and `MODULE_TIMEOUT_SECONDS`.

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

## `account_discovery`

Check account existence across 120+ platforms powered by [Holehe](https://github.com/megadose/holehe).

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Platform coverage is dynamic — as Holehe adds new platforms upstream, this module picks them up automatically on the next install. See the [Holehe repository](https://github.com/megadose/holehe) for the current full platform list.

Enable via `ENABLE_ACCOUNT_DISCOVERY=true` (opt-in — runs 120+ probes, expect 30–60 s per investigation).

**Finding example (account confirmed):**
```json
{
  "platform": "twitter",
  "profile_url": "https://twitter.com",
  "metadata": {
    "email_recovery": "j***@gmail.com",
    "high_value": true
  },
  "confidence": "high",
  "source": "account_discovery"
}
```

Findings with `email_recovery` or `phone_hint` in metadata are flagged `high_value: true` — these reveal partial contact details useful for cross-module correlation.

**Module metadata:**
```json
{
  "platforms_checked": 124,
  "platforms_confirmed": 3,
  "platforms_rate_limited": 2,
  "platforms_not_found": 119,
  "holehe_version": "1.61"
}
```

---

## `whatsmyname`

Username enumeration across 700+ platforms via the [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Opt-in (`ENABLE_WHATSMYNAME=true`) because the sweep fires one HTTP request per platform and takes 60–90 seconds. The dataset is fetched from GitHub on first run and cached locally at `data/cache/wmn-data.json` for 24 hours.

**Finding example (account confirmed):**
```json
{
  "platform": "HackerNews",
  "profile_url": "https://news.ycombinator.com/user?id=janedoe",
  "metadata": { "category": "tech" },
  "confidence": "high"
}
```

**Module metadata:**
```json
{
  "total_platforms_checked": 800,
  "platforms_confirmed": 4,
  "platforms_not_found": 705,
  "platforms_errored": 3,
  "wmn_version": "1.4.0"
}
```

---

## `hudson_rock`

Check if the email address appears in infostealer credential logs via the Hudson Rock Cavalier API.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Always-on (no opt-in). The API is free and returns a 404 when the email is clean. Rate limits return `status: partial`.

Returns one summary finding (infection counts, stealer families) and one finding per compromised domain credential.

**Finding example (clean):** empty findings list, `status: success`.

**Finding example (infected):**
```json
{
  "platform": "hudson_rock",
  "metadata": {
    "total_infections": 2,
    "stealer_families": ["RedLine", "Vidar"],
    "first_seen": "2023-04-10",
    "last_seen": "2024-01-22",
    "exposed_corporate_services": 1,
    "exposed_user_services": 4
  },
  "confidence": "high",
  "severity": "critical"
}
```

Per-domain findings (one per compromised service credential):
```json
{
  "platform": "github.com",
  "url": "https://github.com",
  "metadata": {
    "source": "infostealer_log",
    "stealer_family": "RedLine",
    "date_compromised": "2023-04-10",
    "high_value": true
  },
  "confidence": "high"
}
```

**Module metadata:**
```json
{
  "is_infostealer_victim": true,
  "total_infections": 2,
  "total_exposed_services": 5,
  "all_compromised_domains": ["github.com", "..."]
}
```

---

## `permutation_discovery`

Post-primary-phase orchestrator: if any upstream module recovered a real name (from Gravatar, HIBP breach data, GHunt, etc.), generates up to 60 email permutations and probes each with HIBP and Hudson Rock to find related accounts.

| | |
|--|--|
| **Requires key** | No (HIBP key enables breach-check sub-probes) |
| **Status** | Implemented |

Opt-in (`ENABLE_PERMUTATION_DISCOVERY=true`) because it adds 30–60 seconds and up to 120 extra API calls. Skips automatically if no name was recovered. The original email address is never re-checked.

**Finding example (match):**
```json
{
  "platform": "permutation_match",
  "metadata": {
    "matched_email": "jane.doe@outlook.com",
    "source_module": "hibp",
    "match_type": "breach",
    "breach_count": 2
  },
  "confidence": "medium"
}
```

**Module metadata:**
```json
{
  "names_found": ["Jane Doe"],
  "permutations_checked": 60,
  "related_emails_found": true,
  "matched_emails": ["jane.doe@outlook.com"]
}
```

---

## `ghunt`

Extract deep Google account intelligence via [GHunt](https://github.com/mxrch/GHunt): GAIA ID, display name, profile photo, YouTube channel, public Drive files, Maps review history, and active Google services.

| | |
|--|--|
| **Requires key** | Yes — `GHUNT_CREDS_PATH` (session credentials from `ghunt login`) |
| **Status** | Implemented |

Opt-in (`ENABLE_GHUNT=true`). Runs only against `@gmail.com`, `@googlemail.com`, and domains whose MX records route through Google (Google Workspace). All other domains are skipped immediately.

Requires the `ghunt` extra: `pip install "mailaccess[ghunt]"` and a one-time `ghunt login`. See [docs/ghunt-setup.md](ghunt-setup.md).

**Finding example:**
```json
{
  "platform": "google_account",
  "profile_url": "https://plus.google.com/123456789",
  "metadata": {
    "gaia_id": "123456789",
    "display_name": "Jane Doe",
    "account_creation_date": "2011-03-15",
    "profile_photo_url": "https://lh3.googleusercontent.com/...",
    "custom_profile_photo": true,
    "youtube_channel_url": "https://www.youtube.com/channel/...",
    "maps_reviews_count": 12,
    "public_drive_files": 3,
    "google_services_active": ["YouTube", "Maps", "Drive"],
    "possible_location_hint": "London, Shoreditch"
  },
  "confidence": "high"
}
```

---

## Adding a Module

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-module) for the full interface contract.
