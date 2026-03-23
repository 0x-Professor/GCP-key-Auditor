# gcp-key-auditor

`gcp-key-auditor` is a Python CLI security tool that analyzes exposed Google API keys and estimates real-world impact.

When a key appears in source code, this tool helps answer:

- Is the key actually usable?
- Which Google services accept it?
- Is it likely unrestricted, partially restricted, or tightly restricted?
- What is the probable security severity?

## What It Does

- Scans code repositories for Google API key patterns (`AIza...`).
- Deduplicates keys and probes them against major Google APIs.
- Captures evidence from responses (HTTP code, service status, error messages).
- Computes a practical severity score with rationale.
- Produces machine-readable JSON and human-readable Markdown reports.

## Scope and Safety

This tool is intended for defensive security testing of assets you own or are authorized to test.

- It performs low-volume, minimal requests.
- It does not attempt quota exhaustion or destructive actions.
- It should be used in accordance with laws, contracts, and bug bounty program rules.

## Installation

### pip

```bash
pip install gcp-key-auditor
```

### uv

```bash
uv tool install gcp-key-auditor
```

For local development:

```bash
uv sync --dev
```

## Usage

### 1) Scan a repository and audit discovered keys

```bash
gcp-key-auditor scan --path . --output-json report.json --output-md report.md
```

### 2) Audit one key directly

```bash
gcp-key-auditor audit --key AIza... --output-json report.json
```

### 3) Add custom headers for restricted mobile-style keys

```bash
gcp-key-auditor audit \
  --key AIza... \
  --android-package com.example.app \
  --android-cert-sha1 DA:39:A3:EE:5E:6B:4B:0D:32:55:BF:EF:95:60:18:90:AF:D8:07:09 \
  --ios-bundle-id com.example.ios
```

## Output Severity Levels

- `critical`: Key is accepted on high-impact billable/location/content APIs.
- `high`: Key is accepted on at least one medium/high impact service.
- `medium`: Key appears valid but strongly constrained or mostly denied.
- `low`: No convincing evidence of usable access.
- `info`: No keys found or probing not possible.

## How Scoring Works

The score combines:

- Positive evidence that requests are accepted.
- Service impact weights (location, content, and billable APIs).
- Restriction indicators (`REQUEST_DENIED`, referrer/IP/app restriction patterns).
- Ambiguous outcomes (network failures or quota-only errors).

## Developer Quickstart

```bash
# pip workflow
python -m venv .venv
. .venv/Scripts/activate
pip install -e .[dev]
pytest

# uv workflow
uv sync --dev
uv run pytest
uv run gcp-key-auditor --help
```

## Research Notes

Probe design and interpretation are based on Google documentation for:

- API key management and restrictions.
- API key transmission best practices (`X-Goog-Api-Key` preferred over query parameter).
- Maps Web Service status/error semantics (`REQUEST_DENIED`, `OVER_QUERY_LIMIT`, etc.).

## Disclaimer

No automated probe can prove complete safety. A key that appears restricted today can become dangerous if project services or restrictions change. Always rotate exposed keys and apply both application and API restrictions.
