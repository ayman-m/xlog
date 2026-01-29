# XLog MCP Agent (Next.js)

A Next.js chat and skills UI that connects to the XLog MCP server. It supports Gemini (API key) or Vertex AI (service account) for tool-driven workflows.

## Features

- **Chat interface** that lists tools from the MCP server and executes tool calls.
- **Skills manager** for browsing, creating, editing, and deleting skill files.
- **Simple auth** gate via `UI_USER`/`UI_PASSWORD` with an HTTP-only cookie.
- **Gemini or Vertex AI** support for LLM responses.
- **MCP token support** for secured MCP servers.

## Configuration

Create `.env.local`:

```bash
cp .env.local.example .env.local
```

Key variables:

- `GEMINI_API_KEY` (or set `GOOGLE_APPLICATION_CREDENTIALS` for Vertex)
- `GEMINI_MODEL` (default `gemini-3-pro-preview`)
- `MCP_URL` (default `http://localhost:8080/api/v1/stream/mcp`)
- `MCP_TOKEN` (optional Authorization header)
- `UI_USER`, `UI_PASSWORD` (optional login guard)

## Run Locally

```bash
cd mcp/agent
npm install
npm run dev
```

Open `http://localhost:3000`.

## Docker

```bash
cd mcp/agent
docker build -t xlog-mcp-agent .
docker run -p 3000:3000 --env-file .env.local xlog-mcp-agent
```

## UI Routes

- `/` - Chat UI
- `/skills` - Skills manager
