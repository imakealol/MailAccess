# Module Reference

MailAccess ships 20 modules covering 800+ platforms. Modules are auto-discovered from `backend/modules/` at startup. Each module runs concurrently with all others, subject to `MAX_CONCURRENT_MODULES` and `MODULE_TIMEOUT_SECONDS`.

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

## `dns_lookup`

Real DNS resolution for the email's domain: MX, SPF, DMARC, DKIM, A, and NS records. Always runs — no API key required and no opt-in flag.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

**Findings schema:**
```json
{
  "platform": "dns_lookup",
  "confidence": "high",
  "metadata": {
    "mx_records": ["aspmx.l.google.com"],
    "mx_provider": "google",
    "spf_record": "v=spf1 include:_spf.google.com ~all",
    "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "dkim_record": "v=DKIM1; k=rsa; p=...",
    "has_spf": true,
    "has_dmarc": true,
    "has_dkim": true,
    "a_records": ["93.184.216.34"],
    "ns_records": ["ns1.example.com"]
  }
}
```

---

## `whois_lookup`

Full WHOIS registration data for the email's domain. Skips free email providers (Gmail, Outlook, ProtonMail, etc.) and detects privacy-shield registrations.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

**Findings schema:**
```json
{
  "platform": "whois_lookup",
  "confidence": "high",
  "metadata": {
    "registrar": "Namecheap, Inc.",
    "registered": "2015-03-12",
    "expires": "2027-03-12",
    "updated": "2024-01-05",
    "name_servers": ["ns1.example.com"],
    "privacy_protected": false,
    "registrant_org": "Acme Corp",
    "registrant_country": "US"
  }
}
```

When the domain uses a privacy shield, `privacy_protected` is `true` and registrant fields are omitted.

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

## `social_links`

Derives username variations from the target email (local part, display names from prior findings) and feeds them into `username_pivot`. Also probes links extracted from social profile bios and cross-references them across modules.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Runs in the primary phase alongside other modules. Findings are username candidates — they are not independent confirmations but signals passed to `username_pivot` for validation.

**Module metadata:**
```json
{
  "usernames_derived": ["janedoe", "jane.doe", "jdoe"],
  "source_modules": ["gravatar", "social"],
  "links_extracted": 3
}
```

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

## `user_scanner`

Email registration probes across 205+ platforms via the [user-scanner](https://pypi.org/project/user-scanner/) package.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Opt-in (`ENABLE_USER_SCANNER=true`) because a full sweep can take several minutes. Set `user_scanner` in `MODULE_TIMEOUT_OVERRIDES` (default 180s in `.env.example`).

**Finding example (account confirmed):**
```json
{
  "platform": "Instagram",
  "profile_url": "https://instagram.com",
  "metadata": {
    "category": "Social",
    "reason": "",
    "source": "user_scanner"
  },
  "confidence": "high"
}
```

**Module metadata:**
```json
{
  "platforms_checked": 205,
  "platforms_confirmed": 4,
  "platforms_not_registered": 198,
  "user_scanner_version": "1.3.6"
}
```

---

## `username_pivot`

Post-primary phase: collects up to five unique usernames from primary findings (email local-part, metadata usernames, slugified display names) and re-runs the WhatsMyName dataset for each. Skips platforms already confirmed by the `whatsmyname` module.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Opt-in (`ENABLE_USERNAME_PIVOT=true`). Runs after primary modules complete and before `permutation_discovery`. Reuses the cached WMN dataset at `data/cache/wmn-data.json`.

**Finding example:**
```json
{
  "platform": "GitHub",
  "profile_url": "https://github.com/katriel_moses",
  "metadata": {
    "matched_username": "katriel_moses",
    "category": "dev",
    "source": "username_pivot"
  },
  "confidence": "medium"
}
```

**Module metadata:**
```json
{
  "usernames_pivoted": ["katriel.moses", "katriel_moses"],
  "platforms_checked": 1600,
  "platforms_confirmed": 2,
  "wmn_version": "1.4.0"
}
```

---

## `breachdirectory`

Search breach records for the target email via the [BreachDirectory RapidAPI](https://rapidapi.com/rohan-patra/api/breachdirectory).

| | |
|--|--|
| **Requires key** | Yes — `BREACHDIRECTORY_API_KEY` |
| **Status** | Implemented |

One finding per unique breach source. Passwords and hashes are never stored in full — only a two-character hint (e.g. `pa***`) when a password field is present.

**Finding example:**
```json
{
  "platform": "Collection1",
  "metadata": {
    "breach_source": "Collection1",
    "has_password_hash": true,
    "password_hint": "pa***"
  },
  "confidence": "high",
  "severity": "critical"
}
```

**Module metadata:**
```json
{
  "total_records_found": 3,
  "sources_list": ["Collection1", "LinkedIn"],
  "has_plaintext_hashes": false
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

## `phone_intel`

Validates phone numbers recovered from primary module findings and probes WhatsApp/Telegram registration hints.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Runs in the **post-primary** phase when `ENABLE_PHONE_INTEL=true` (default) and at least one phone number was extracted from prior findings. Skips with `status: skipped` when no phones are found.

Phone numbers are never stored in full in findings — only masked values (e.g. `+1234***7890`).

**Findings schema (validation):**
```json
{
  "platform": "phone_validation",
  "metadata": {
    "phone_number": "+1234***7890",
    "valid": true,
    "country": "United States",
    "carrier": "Verizon",
    "line_type": "mobile",
    "platform_hint": "numverify"
  },
  "confidence": "high"
}
```

**Findings schema (WhatsApp / Telegram — experimental):**
```json
{
  "platform": "whatsapp",
  "profile_url": "https://wa.me/15551234567",
  "metadata": {
    "phone_number": "+1555***4567",
    "experimental": true,
    "platform_hint": "possible_registration"
  },
  "confidence": "low"
}
```

**Module metadata:**
```json
{
  "phones_processed": 2,
  "phones_found": 3
}
```

---

## `messaging_hints`

Best-effort Telegram username checks during the primary gather phase. Optional WhatsApp hints when phone numbers are available.

| | |
|--|--|
| **Requires key** | No |
| **Status** | Implemented |

Enabled by default (`ENABLE_MESSAGING_HINTS=true`). Rate-limited to **3 Telegram username checks** per investigation. Signal has no public lookup API — noted in module metadata as `signal_checkable: false`.

**Findings schema:**
```json
{
  "platform": "telegram",
  "profile_url": "https://t.me/username",
  "metadata": {
    "username": "jane.doe",
    "display_name": "Jane Doe",
    "photo_url": "https://...",
    "check_type": "username",
    "experimental": true
  },
  "confidence": "low"
}
```

**Module metadata:**
```json
{
  "telegram_checks": 3,
  "whatsapp_checks": 0,
  "signal_checkable": false
}
```

---

## `identity_graph` (built-in)

Not a standalone module — the identity graph is built automatically after all primary and post-primary modules complete. It cross-references findings by shared usernames, profile photos, display names, and breach data to produce confidence-scored identity clusters.

| | |
|--|--|
| **Requires key** | No |
| **Opt-in** | No — always runs |
| **Status** | Implemented |

The graph is available at:
- CLI: displayed automatically (use `--show-collisions` to expand low-confidence clusters)
- Web UI: `/investigation/:id/graph`
- API: `GET /api/report/{id}/clusters` (clusters) and `GET /api/report/{id}/graph` (D3 nodes/links)

**Cluster schema:**
```json
{
  "id": "cluster-1",
  "confidence": "high",
  "score": 0.91,
  "reasoning": "Shared username 'janedoe' across GitHub, HackerNews, and Twitter findings",
  "members": [
    {"module": "social", "platform": "GitHub", "username": "janedoe"},
    {"module": "whatsmyname", "platform": "HackerNews", "username": "janedoe"}
  ]
}
```

---

## Adding a Module

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-module) for the full interface contract.
