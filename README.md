<p align="center">
  <img src="frontend/public/ma_logo.png" width="120" alt="MailAccess Logo" />
</p>

<h1 align="center">MailAccess</h1>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](docker-compose.yml)
[![PyPI version](https://img.shields.io/static/v1?label=PyPI&message=0.3.0&color=3775A9&logo=pypi&logoColor=white)](https://pypi.org/project/mailaccess/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/mailaccess)](https://pypi.org/project/mailaccess/)

Self-hostable OSINT platform for investigating email addresses. Fan out across breach databases, social networks, DNS records, and the open web — get back a unified exposure score and structured findings you can export or pipe into Maltego.

Built for security researchers, OSINT analysts, and penetration testers operating under authorization. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

## Install

### Quickest — CLI only

```bash
pip install mailaccess
# or (recommended)
pipx install mailaccess
```

### Full stack (Web UI + API + CLI)

```bash
git clone https://github.com/YOUR_USERNAME/mailaccess
cd mailaccess
docker compose up -d
pip install mailaccess
mailaccess config set-url http://localhost:8000
```

## Quick Start

```bash
mailaccess investigate you@example.com
mailaccess investigate you@example.com -o report.pdf
mailaccess investigate you@example.com --format json
mailaccess keys list
mailaccess keys set HIBP_API_KEY your-key-here
mailaccess modules
```

<!-- screenshot -->

## What It Does

- **Identity graph** — cross-platform correlation of accounts, usernames, and signals from each investigation
- **Phone number recovery** — pipeline to surface and validate numbers tied to the target
- **Telegram / WhatsApp hints** — lightweight messaging-app footprint checks alongside other modules
- **YAML-driven platform system** — social-style checks defined in `backend/platforms/`; community extensible without new Python for each site
- Concurrent module execution — all modules run in parallel, results stream as they arrive
- WebSocket streaming — partial results arrive in real time without polling
- REST API + web UI + CLI — use whatever interface fits your workflow
- Plugin module system — drop a `.py` file in `backend/modules/` and it auto-registers; no wiring required
- 6 export formats: JSON, CSV, PDF, Markdown, STIX 2.1, Maltego XML
- Maltego local transform server — run investigations directly from the Maltego desktop app
- Webhook notifications — Slack, Discord, or any HTTP endpoint
- Exposure score (0–100) with risk label: low / medium / high / critical
- SQLite by default; PostgreSQL optional via Docker Compose profile

## Modules

| Module | Coverage | Key Required | Opt-in |
|--------|----------|--------------|--------|
| gravatar | Profile hash lookup | No | No |
| hibp | Breach check | Yes | No |
| emailrep | Reputation + blacklist | No | No |
| hudson_rock | Infostealer logs (free) | No | No |
| google_dork | 5 automated dorks | Yes (SerpAPI) | No |
| domain_intel | WHOIS + DNS + Shodan | No (Shodan optional) | No |
| social | 13 platforms via YAML | No | No |
| account_discovery | Holehe 120+ platforms | No | Yes |
| user_scanner | 205+ platform vectors | No | Yes |
| whatsmyname | 700+ platforms | No | Yes |
| breachdirectory | 2nd breach source | Yes | No |
| username_pivot | WMN via recovered usernames | No | Yes |
| permutation_discovery | 60 email variants | No | Yes |
| phone_intel | Phone validation + WA/TG hints | No | No |
| messaging_hints | Telegram/WhatsApp username check | No | No |
| ghunt | Gmail deep intel | No (setup required) | Yes |

> 800+ platforms checked when all opt-in modules enabled. YAML platform system — add new platforms via PR, no Python required.

## Identity Graph

Every investigation generates a cross-platform identity graph linking accounts by shared usernames, photos, display names, and breach data. View at:

`/investigation/:id/graph`

Export as Neo4j Cypher via `GET /api/report/{id}/graph`

## Adding a Platform

No Python required. Drop a YAML file in `backend/platforms/`:

```bash
cp backend/platforms/TEMPLATE.yaml backend/platforms/mysite.yaml
```

Edit fields, submit PR.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guide.

## Export Formats

| Format | `?format=` value | Use case |
|--------|-----------------|----------|
| JSON | `json` | Programmatic use, archiving |
| CSV | `csv` | Spreadsheet analysis |
| PDF | `pdf` | Human-readable reports |
| Markdown | `markdown` | Wikis, issue trackers |
| STIX 2.1 | `stix` | Threat intelligence platforms |
| Maltego XML | `maltego` | Maltego graph import |

## Integrations

| Integration | How |
|-------------|-----|
| Maltego | Local transform server at `POST /maltego/email_investigate` (no API key required) |
| Slack | Set `SLACK_WEBHOOK_URL` in `.env` |
| Discord | Set `DISCORD_WEBHOOK_URL` in `.env` |
| Generic webhook | `INTEGRATION_WEBHOOK_URL` + optional `INTEGRATION_WEBHOOK_SECRET` (HMAC) |

## Self-Hosting

```bash
cp .env.example .env      # all API keys are optional
docker compose up         # backend :8000  ·  frontend :3000
```

Open **http://localhost:3000** in your browser. Full setup guide: [docs/self-hosting.md](docs/self-hosting.md).

## CLI Reference

| Command | Description |
|---------|-------------|
| `mailaccess investigate <email>` | Run a full investigation against an email address |
| `mailaccess history` | List past investigations |
| `mailaccess keys list` | Show all configured API keys |
| `mailaccess keys set <KEY> <value>` | Set an API key |
| `mailaccess keys unset <KEY>` | Remove an API key |
| `mailaccess config set-url <url>` | Point the CLI at a MailAccess instance |
| `mailaccess modules` | List all available modules |
| `mailaccess commands` | List all CLI commands |

The `--output` / `-o` flag on `investigate` saves the report to a file. The extension determines the format: `.json`, `.csv`, `.pdf`, `.md`, `.stix.json`, `.maltego.csv`.

## API Keys

| Key | Module | Where to get it | Required? |
|-----|--------|-----------------|-----------|
| `HIBP_API_KEY` | `hibp` | https://haveibeenpwned.com/API/Key | Yes (module skips without it) |
| `SERPAPI_KEY` | `google_dork` | https://serpapi.com | Yes (module skips without it) |
| `SHODAN_API_KEY` | `domain_intel` | https://account.shodan.io | No |
| `EMAILREP_API_KEY` | `emailrep` | https://emailrep.io | No |
| `HUNTER_IO_API_KEY` | `hunter_io` | https://hunter.io | No |
| `SLACK_WEBHOOK_URL` | Webhooks | https://api.slack.com/messaging/webhooks | No |
| `DISCORD_WEBHOOK_URL` | Webhooks | Discord server settings | No |

## Links

| | |
|-|-|
| [Self-hosting guide](docs/self-hosting.md) | Docker Compose, `.env` reference, PostgreSQL, proxy/Tor, Maltego setup |
| [Module reference](docs/modules.md) | All modules, findings schema, adding new modules |
| [API reference](docs/api.md) | REST endpoints, WebSocket events, authentication |
| [Export formats](docs/exports.md) | Supported formats, MIME types, filename conventions |
| [Integrations](docs/integrations.md) | Maltego, Slack, Discord, generic webhooks |
| [Contributing](CONTRIBUTING.md) | Adding modules, adding exporters, code style, PR checklist |
| [PyPI](https://pypi.org/project/mailaccess/) | `pip install mailaccess` |
| [GitHub](https://github.com/YOUR_USERNAME/mailaccess) | Source code, issues, releases |

## Changelog

### 0.3.0

- Identity graph with D3 visualization
- Phone number recovery + WhatsApp/Telegram hints
- YAML-driven platform system (community extensible)
- user-scanner integration (205+ vectors)
- Username pivot via WhatsMyName
- BreachDirectory as second breach source
- Permutation discovery for related emails

### 0.2.0

- ASCII banner on CLI launch
- API key management (mailaccess keys list/set/unset)
- `--output` / `-o` flag for direct file export
- mailaccess modules and mailaccess commands
- pipx install support

### 0.1.0

- Initial release
- 800+ platform coverage (WMN + Holehe + hardcoded)
- 6 export formats (JSON CSV Markdown PDF STIX Maltego)
- Maltego local transform server
- Slack + Discord + webhook integrations
- Docker Compose self-hosting
- Full REST API + WebSocket streaming

## License

MIT. All data queried by MailAccess comes from public sources. See [DISCLAIMER.md](DISCLAIMER.md) for authorized use cases and legal responsibility.
