[![made-with](https://img.shields.io/badge/Built%20with-grey)]()
[![made-with-Python](https://img.shields.io/badge/Python-blue)](https://www.python.org/)
[![made-with-FastAPI](https://img.shields.io/badge/FastAPI-green)](https://fastapi.tiangolo.com/)
[![made-with-GraphQL](https://img.shields.io/badge/GraphQL-red)](https://graphql.org/)
[![Docker Pulls](https://img.shields.io/docker/pulls/aymanam/rosetta)](https://hub.docker.com/repository/docker/aymanam/rosetta)
[![scanned-with](https://img.shields.io/badge/Scanned%20with-gree)]()
[![snyk](https://snyk.io/test/github/my-soc/Rosetta/badge.svg)](https://snyk.io/test/github/my-soc/Rosetta)
![codeql](https://github.com/my-soc/Rosetta/actions/workflows/github-code-scanning/codeql/badge.svg)
[![slack-community](https://img.shields.io/badge/Slack-4A154C?logo=slack&logoColor=white)](https://go-rosetta.slack.com)

<img align="left" src="img/logo.png" width="30%" alt="Xlog">

# XLog

XLog is a security testing and simulation platform that combines synthetic log generation, scenario-based attack telemetry, and AI-orchestrated workflows through MCP.

## Capabilities

- **Synthetic log generation** in SYSLOG, CEF, LEEF, WINEVENT, JSON, Incident, XSIAM Parsed, and XSIAM CEF formats.
- **Scenario-based telemetry** with multi-step MITRE ATT&CK tactics from JSON scenarios or on-the-fly scenario input.
- **Streaming workers** that continuously send logs to UDP, TCP, HTTP(S), XSIAM PAPI, or XSIAM webhook collectors.
- **Field catalog and observables tooling** to discover supported fields and generate realistic observables and technology stacks.
- **Simulation skills library** with CRUD tooling for skill files (foundation, scenarios, validation, workflows).
- **MCP integrations** for CALDERA (abilities, adversaries, operations, agents, payloads) and XSIAM (XQL, datasets, lookups, assets, cases, issues).
- **Web agent** for chat-based orchestration and skills management built in Next.js with Gemini/Vertex support.

## Project Structure

```
xlog/
├── app/                    # GraphQL API for log generation and workers
├── scenarios/              # Scenario definitions (ready and drafts)
├── mcp/
│   ├── server/             # MCP server exposing XLog, CALDERA, XSIAM tools
│   └── agent/              # Next.js MCP chat and skills UI
├── scripts/                # Utility scripts
├── examples/               # GraphQL request examples
└── img/                    # Documentation images
```

## Quick Start

1. Run the core GraphQL API:
   ```bash
   pip install -r requirements.txt
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```
2. Run example queries:
   ```bash
   python examples/graphql_generate_fake_data.py
   python examples/graphql_workers_and_scenarios.py
   ```
3. For MCP server and agent setup, follow their READMEs below.

## GraphQL API

The GraphQL endpoint is served at `http://localhost:8000/`.

### Queries and Mutations

- `getSupportedFields` -> returns the supported fields list used for observables and required fields.
- `generateFakeData(requestInput: DataFakerInput)` -> returns a batch of synthetic logs.
- `generateScenarioFakeData(requestInput: DetailedScenarioInput)` -> returns multi-step scenario logs without starting workers.
- `createDataWorker(requestInput: DataWorkerCreateInput)` -> starts a streaming worker.
- `createScenarioWorker(requestInput: ScenarioWorkerCreateInput)` -> starts workers from a `scenarios/ready/*.json` file.
- `createScenarioWorkerFromQuery(requestInput: ScenarioQueryWorkerCreateInput)` -> starts workers from inline scenario steps.
- `listWorkers` -> lists active workers.
- `actionWorker(requestInput: DataWorkerActionInput)` -> stops a worker or checks status.
- `generateObservables(requestInput: GenerateObservablesInput)` -> generates observables from threat intel feeds.

### Input Types

#### `DataFakerInput`

- `type` (required): `SYSLOG`, `CEF`, `LEEF`, `WINEVENT`, `JSON`, `Incident`, `XSIAM_Parsed`, `XSIAM_CEF`
- `count` (default `1`)
- `vendor`, `product`, `version`
- `datetimeIso` (`YYYY-MM-DD HH:MM:SS`)
- `fields` (comma-separated field list)
- `observablesDict` (object of supported fields)
- `requiredFields` (list of supported field enums)

#### `DetailedScenarioInput`

- `name` (required)
- `tags` (optional list)
- `steps` (list of `DetailedScenarioStep`)

`DetailedScenarioStep`:
- `tactic`, `tacticId`, `technique`, `techniqueId`, `procedure`, `type`
- `logs` (list of `DataFakerInput`)

#### `DataWorkerCreateInput`

- `type` (required): `SYSLOG`, `CEF`, `LEEF`, `WINEVENT`, `JSON`, `Incident`, `XSIAM_Parsed`, `XSIAM_CEF`
- `destination` (required): `udp:host:port`, `tcp:host:port`, `https://...`, `XSIAM`, or `XSIAM_WEBHOOK`
- `count` (default `1`), `interval` (default `2`)
- `vendor`, `product`, `version`
- `fields`, `observablesDict`, `requiredFields`, `datetimeIso`
- `verifySsl` (default `false`)

#### `ScenarioWorkerCreateInput`

- `scenario` (required): filename without `.json` in `scenarios/ready/`
- `destination` (required)
- `count`, `interval`, `vendor`, `datetimeIso`, `verifySsl`

#### `ScenarioQueryWorkerCreateInput`

- `name` (required)
- `destination` (required)
- `tags` (optional list)
- `steps` (list of `DetailedQueryScenarioStep`)

`DetailedQueryScenarioStep`:
- `tactic`, `tacticId`, `technique`, `techniqueId`, `procedure`, `type`
- `logs` (list of `WorkerFakerInput`)

`WorkerFakerInput`:
- `type` (required), `count`, `interval`
- `vendor`, `product`, `version`
- `datetimeIso`, `fields`, `observablesDict`, `requiredFields`, `verifySsl`

#### `DataWorkerActionInput`

- `worker` (required)
- `action` (required): `STOP` or `STATUS`

#### `GenerateObservablesInput`

- `count` (required)
- `observableType` (required): `IP`, `URL`, `SHA256`, `CVE`, `TERMS`
- `known` (default `BAD`): `BAD` or `GOOD`

### Example Queries

**Generate fake data (SYSLOG):**
```graphql
query Example($input: DataFakerInput!) {
  generateFakeData(requestInput: $input) {
    count
    type
    data
  }
}
```

**Generate fake data with observables (JSON):**
```graphql
query ExampleJson($input: DataFakerInput!) {
  generateFakeData(requestInput: $input) {
    count
    type
    data
  }
}
```
Example variables:
```json
{
  "input": {
    "type": "JSON",
    "count": 2,
    "datetimeIso": "2025-01-05 18:29:25",
    "observablesDict": {
      "remoteIp": "203.0.113.10",
      "localIp": "10.0.0.5",
      "user": "svc-backup",
      "url": "https://example.com/login"
    }
  }
}
```

**Create a worker:**
```graphql
query CreateWorker($input: DataWorkerCreateInput!) {
  createDataWorker(requestInput: $input) {
    worker
    status
    type
    destination
  }
}
```

**List workers:**
```graphql
query ListWorkers {
  listWorkers {
    worker
    status
    type
    interval
    destination
  }
}
```

**Stop a worker:**
```graphql
query StopWorker($input: DataWorkerActionInput!) {
  actionWorker(requestInput: $input) {
    worker
    status
  }
}
```

**Generate scenario fake data:**
```graphql
query Scenario($input: DetailedScenarioInput!) {
  generateScenarioFakeData(requestInput: $input) {
    name
    steps
  }
}
```

## Documentation

- `scenarios/README.md` - Scenario format and examples
- `mcp/server/README.md` - MCP server capabilities and setup
- `mcp/agent/README.md` - Next.js agent setup and usage
- `mcp/server/skills/README.md` - Skill library structure
