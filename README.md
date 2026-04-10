# TIA — Threat Intelligence Assistant

A natural language CLI for querying the [rosti.dev](https://rosti.dev) threat intelligence platform, powered by Claude AI. Ask anything about threat actors, malware families, or IOCs — and get structured results with report links and optional file exports.

## Features

- Search reports by threat actor, malware family, or keyword
- View results as a clean table with dates, report names, and direct URLs
- Extract IOCs from any report
- Export IOCs to **Excel (.xlsx)**, **CSV**, or **JSON** on demand
- Each Excel export creates one sheet per report, named after the report title

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
   Then fill in your API keys in `.env`:
   ```
   ROSTI_API_KEY=your_rosti_api_key_here
   ANTHROPIC_API_KEY=your_anthropic_api_key_here
   ```

## Usage

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
