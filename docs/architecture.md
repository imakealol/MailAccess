# MailAccess Architecture

## Components

| Path | Role |
|------|------|
| `backend/` | FastAPI app — investigation engine, REST API, WebSocket |
| `frontend/` | Vite + React + TypeScript SPA |
| `cli/` | Typer CLI (`mailaccess investigate <email>`) |
| `docker/` | Dockerfiles for backend and frontend |
| `docker-compose.yml` | Orchestration (SQLite default; Postgres via `--profile postgres`) |

## Backend Layout

```
backend/
├── main.py          # FastAPI app + CORS + lifespan hook
├── config.py        # Pydantic-settings (loads .env)
├── core/
│   ├── engine.py    # InvestigationEngine — asyncio.gather + streaming queue
│   ├── aggregator.py# ResultAggregator — merges module results
│   └── scheduler.py # Scheduler stub — recurring investigations
├── modules/
│   ├── base.py      # BaseModule ABC + ModuleResult dataclass + ModuleStatus enum
│   ├── __init__.py  # Auto-discovery registry
│   └── *.py         # One file per OSINT module
├── api/
│   ├── router.py    # Mounts sub-routers
│   ├── routes/
│   │   ├── investigations.py  # CRUD for investigations
│   │   └── modules.py         # Module listing
│   └── websocket.py           # /ws/investigate streaming endpoint
├── db/
│   ├── database.py  # Engine, session factory, init_db()
│   └── models.py    # Investigation, ModuleRun, Finding (SQLAlchemy 2.0)
└── exporters/
    ├── base.py      # BaseExporter ABC
    └── *.py         # json, csv, pdf, markdown, stix, maltego
```

## Module Contract

All modules live in `backend/modules/` and inherit `BaseModule`:

```python
class MyModule(BaseModule):
    name = "my_module"           # unique slug
    description = "Does X."
    requires_key = True          # skips itself if API key missing

    async def run(self, email: str) -> ModuleResult:
        ...
```

`ModuleResult` carries:
- `status` — `success | partial | failed | skipped`
- `findings` — list of dicts (flexible schema per module)
- `metadata` — supplementary info (timing, API version, etc.)
- `errors` — human-readable error messages

**No registration step needed** — `modules/__init__.py` scans the package at
import time and registers every `BaseModule` subclass with a `name` attribute.

## Investigation Flow

```
POST /api/v1/investigations
  → create Investigation (status=pending) in DB
  → spawn background task: InvestigationEngine.investigate(email)
      → asyncio.Semaphore(max_concurrency) gates parallel module tasks
      → each module runs with asyncio.wait_for(timeout)
      → results pushed to asyncio.Queue as they complete
      → partial results streamed to client via /ws/investigate
      → ModuleRun + Finding records written to DB per result
  → Investigation status → complete (or failed)
```

## Database Models

```
Investigation
  ├── id, email, status, created_at, completed_at
  ├── ModuleRun[]  (one per module per investigation)
  │     id, module_name, status, run_metadata, errors, started_at, finished_at
  └── Finding[]   (one per data point)
        id, module_name, data (JSON), created_at
```

## Export Formats

| Format | Class | MIME |
|--------|-------|------|
| JSON | `JsonExporter` | `application/json` |
| CSV | `CsvExporter` | `text/csv` |
| PDF | `PdfExporter` | `application/pdf` |
| Markdown | `MarkdownExporter` | `text/markdown` |
| STIX 2.1 | `StixExporter` | `application/json` |
| Maltego | `MaltegoExporter` | `application/xml` |
