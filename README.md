# TIA — Threat Intelligence Assistant

A natural language CLI and native Claude Code MCP integration for querying the [rosti.dev](https://rosti.dev) threat intelligence platform. Search reports, extract IOCs, and export data for any threat actor or malware family.

## Features

- Search reports by threat actor, malware family, or keyword
- View results as a clean table with dates, report names, and direct URLs
- Extract IOCs from any report
- Export IOCs to **Excel (.xlsx)**, **CSV**, or **JSON** on demand
- Each Excel export creates one sheet per report, named after the report title
- **Native Claude Code integration via MCP** — no terminal needed

## Requirements

- Python 3.9+
- A [rosti.dev](https://rosti.dev) API key
- An [Anthropic](https://console.anthropic.com) API key

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/IbrahimEkimIsik/TIA.git
   cd TIA
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create your `.env` file from the example:
   ```bash
   cp .env.example .env
   ```
   Fill in your API keys in `.env`:
   ```
   ROSTI_API_KEY=your_rosti_api_key_here
   ANTHROPIC_API_KEY=your_anthropic_api_key_here
   ```

---

## Usage — CLI (Terminal)

**Single query:**
```bash
python rosti.py "find reports about Lazarus Group from 2026"
python rosti.py "get all reports about DPRK threat actors in 2026"
python rosti.py "find latest intel on Scattered Spider"
```

**Interactive mode:**
```bash
python rosti.py
```

**Export IOCs to file (just ask):**
```bash
python rosti.py "find DPRK reports from 2026 and export IOCs to Excel"
python rosti.py "get Lazarus IOCs and save as JSON"
python rosti.py "export Scattered Spider IOCs to CSV"
```

---

## Usage — Native Claude Code MCP Integration

This lets you query Rosti threat intelligence **directly inside Claude Code** without opening a terminal.

### 1. Register the MCP server

Add this to your `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "rosti": {
      "type": "stdio",
      "command": "python",
      "args": ["/absolute/path/to/rosti_mcp.py"],
      "env": {
        "ROSTI_API_KEY": "your_rosti_api_key_here",
        "ANTHROPIC_API_KEY": "your_anthropic_api_key_here"
      }
    }
  }
}
```

> Replace `/absolute/path/to/rosti_mcp.py` with the full path to the file on your machine.

### 2. Restart Claude Code

The `rosti` MCP server will load automatically on next launch.

### 3. Ask directly in the chat

No commands needed — just talk to Claude:

```
find all DPRK reports from 2026
show me Lazarus Group IOCs and export to Excel
what are the latest Scattered Spider reports?
search for reports about LummaC2
```

---

## Output Format

Reports are always displayed as a table:

| Date | Report Name | URL |
|------|-------------|-----|
| 2026-02-24 | North Korean Lazarus Group Now Working With Medusa Ransomware | https://www.security.com/... |

## Supported Export Formats

| Format | Example prompt |
|--------|---------------|
| Excel (.xlsx) | "export to Excel" / "save as xlsx" |
| CSV | "export to CSV" |
| JSON | "export to JSON" |

## Files

| File | Description |
|------|-------------|
| `rosti.py` | Standalone CLI script |
| `rosti_mcp.py` | Native MCP server for Claude Code |
| `requirements.txt` | Python dependencies |
| `.env.example` | API key template |
