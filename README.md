# MailAccess

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](docker-compose.yml)

Self-hostable OSINT platform for investigating email addresses. Fan out across breach databases, social networks, DNS records, and the open web — get back a unified exposure score and structured findings you can export or pipe into Maltego.

Built for security researchers, OSINT analysts, and penetration testers operating under authorization. Read [DISCLAIMER.md](DISCLAIMER.md) before use.

<!-- screenshot -->

## Features

- Concurrent module execution — all modules run in parallel, results stream as they arrive
- WebSocket streaming — partial results arrive in real time without polling
- REST API + web UI + CLI — use whatever interface fits your workflow
- Plugin module system — drop a `.py` file in `backend/modules/` and it auto-registers; no wiring required
- 6 export formats: JSON, CSV, PDF, Markdown, STIX 2.1, Maltego XML
- Maltego local transform server — run investigations directly from the Maltego desktop app
- Webhook notifications — Slack, Discord, or any HTTP endpoint
- Exposure score (0–100) with risk label: low / medium / high / critical
- SQLite by default; PostgreSQL optional via Docker Compose profile

## Quick Start

```bash
cp .env.example .env      # all API keys are optional
docker compose up         # backend :8000  ·  frontend :3000
```

Open **http://localhost:3000** in your browser.

## Modules

| Module | What it checks | Requires key |
|--------|---------------|:------------:|
| `hibp` | Known data breaches via the HIBP v3 API | Yes — `HIBP_API_KEY` |
| `emailrep` | Reputation score, risk flags, linked profiles (EmailRep.io) | No (key optional) |
| `gravatar` | Gravatar and Libravatar profile, linked accounts | No |
| `google_dork` | Google dork queries via SerpAPI — LinkedIn, GitHub, Pastebin, open web | Yes — `SERPAPI_KEY` |
| `domain_intel` | WHOIS, SPF / DMARC / MX, website presence, Shodan subdomains | No (Shodan optional) |
| `social` | Account existence on 13 platforms (GitHub, Discord, Spotify, Skype, and more) | No |
| `hunter_io` | Email deliverability and domain info via Hunter.io | Yes — `HUNTER_IO_API_KEY` |
| `dns_lookup` | MX, SPF, DMARC, DKIM DNS records | No |
| `whois_lookup` | WHOIS registration data | No |
| `shodan` | Hosts and open services for the email's domain | Yes — `SHODAN_API_KEY` |
| `social_links` | Social profiles inferred from the email username | No |
| `google_search` | Google search mentions of the email | No |

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

## Documentation

| Page | Contents |
|------|----------|
| [Self-hosting](docs/self-hosting.md) | Docker Compose, `.env` reference, PostgreSQL, proxy/Tor, Maltego setup |
| [Module reference](docs/modules.md) | All modules, findings schema, adding new modules |
| [API reference](docs/api.md) | REST endpoints, WebSocket events, authentication |
| [Export formats](docs/exports.md) | Supported formats, MIME types, filename conventions |
| [Integrations](docs/integrations.md) | Maltego, Slack, Discord, generic webhooks |
| [Contributing](CONTRIBUTING.md) | Adding modules, adding exporters, code style, PR checklist |

## License

MIT. All data queried by MailAccess comes from public sources. See [DISCLAIMER.md](DISCLAIMER.md) for authorized use cases and legal responsibility.
