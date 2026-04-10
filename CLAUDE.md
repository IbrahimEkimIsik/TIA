# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
pip install -r requirements.txt
```

Requires a `.env` file with:
```
ROSTI_API_KEY=...
ANTHROPIC_API_KEY=...
```

## Running

```bash
# Single query
python rosti.py "find reports about LummaC2"

# Interactive mode
python rosti.py
```

## Architecture

Single-file Python CLI (`rosti.py`) that acts as a natural language interface to the [rosti.dev](https://rosti.dev) threat intelligence API.

**Flow:** User prompt → Claude (`claude-opus-4-6`) with tools → Rosti REST API calls → formatted output

**Key components in `rosti.py`:**
- `rosti_get()` — thin wrapper around all Rosti API calls (`https://rosti.dev/api/v1`)
- Tool implementation functions (`search_reports`, `search_iocs`, `get_report`, `get_iocs`, etc.) — each returns a formatted string
- `TOOLS` / `TOOL_MAP` — Claude tool definitions and their dispatch table
- `run_query()` — agentic loop: sends query to Claude, executes tool calls, feeds results back until `end_turn`
- `main()` — entry point; single-shot or interactive REPL

**API endpoints used:**
- `GET /search/reports?q=` — full-text search over reports
- `GET /search/iocs?q=&pattern=` — IOC value search
- `GET /reports` — list/filter reports
- `GET /reports/{id}` — single report with IOCs and YARA rules
- `GET /iocs` — list/filter IOCs by type and category
- `GET /sources`, `/ioctypes`, `/categories` — reference data
