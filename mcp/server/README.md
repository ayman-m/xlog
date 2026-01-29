# XLog MCP Server

The MCP server exposes XLog capabilities (log generation and scenarios) plus CALDERA and XSIAM tooling through FastMCP so AI agents can orchestrate security simulations.

## What It Provides

- **XLog tooling**: create/list log streaming workers, generate scenarios, and inspect supported fields.
- **Simulation skills**: load and manage skill files (list/read/create/update/delete).
- **Observables tooling**: generate observables and derive a technology stack profile.
- **XSIAM integrations**: run XQL, manage datasets, lookups, assets, cases, issues, and send webhook logs.
- **CALDERA integrations**: query abilities, adversaries, agents, operations, payloads, planners, objectives, schedules, facts, and relationships.

## Configuration

Environment variables (defaults in `src/config/config.py`):

- `XLOG_URL` (default `http://localhost:8000`)
- `MCP_TRANSPORT` (`stdio` or `http`)
- `MCP_HOST` (default `0.0.0.0`)
- `MCP_PORT` (default `8080`)
- `MCP_PATH` (default `/api/v1/stream/mcp`)
- `CALDERA_URL`, `CALDERA_API_KEY`
- `CORTEX_MCP_PAPI_URL`, `CORTEX_MCP_PAPI_AUTH_HEADER`, `CORTEX_MCP_PAPI_AUTH_ID`, `PLAYGROUND_ID`
- `WEBHOOK_ENDPOINT`, `WEBHOOK_KEY`
- `TECHNOLOGY_STACK` (JSON string)

Optional TLS:
- `SSL_CERT_FILE`, `SSL_KEY_FILE`, `SSL_CERT_PEM`, `SSL_KEY_PEM`

## Run Locally

```bash
cd mcp/server
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m src.main
```

## Run with Docker

```bash
cd mcp/server
docker build -t xlog-mcp .
docker run --env-file .env -i --rm xlog-mcp
```

## HTTP Transport

When `MCP_TRANSPORT=http`, the server listens at:

```
http://<host>:<port>/api/v1/stream/mcp
```

A lightweight health check is available at `http://<host>:<port>/ping/`.
