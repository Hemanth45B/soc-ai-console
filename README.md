# SOC AI Console

A self-hosted, AI-augmented log analysis console — a lightweight alternative
to a full SIEM for a portfolio-scale SOC pipeline. It ingests raw security
logs, runs rule-based detection to raise candidate alerts, then uses the
Google Gemini API to triage each alert with analyst-style reasoning, a
confidence score, and extracted IOCs — while keeping a **human-in-the-loop
gate** for every high/critical or low-confidence finding.

![status](https://img.shields.io/badge/status-active-2dd4bf) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![license](https://img.shields.io/badge/license-MIT-lightgrey)

## Why

Most "AI SOC" demos either auto-close everything (unsafe) or just summarize
logs (not very useful). This project is built around one rule: **the AI can
do first-pass triage, but it never gets to close a high-severity or
low-confidence alert by itself.** Those are always routed to a human analyst
for approval or override.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌────────────────────┐
│  Log ingest │ --> │  Detection rules  │ --> │   Alert queue (DB)  │
│  (/api/ingest)│   │  (detection.py)  │     └─────────┬───────────┘
└─────────────┘     └──────────────────┘               │
                                                          v
                                              ┌────────────────────────┐
                                              │   AI Triage Engine      │
                                              │   (Gemini API)          │
                                              │   — triage.py           │
                                              └───────────┬────────────┘
                                                           v
                                      ┌───────────────────────────────────┐
                                      │ Human-in-the-loop gate:            │
                                      │ high/critical severity OR          │
                                      │ confidence < threshold             │
                                      │  → pending_human_review            │
                                      │ else → triaged_auto                │
                                      └───────────────────────────────────┘
```

- **Backend:** FastAPI (`backend/`)
- **Storage:** SQLite, with an FTS5 virtual table for full-text log search
- **AI triage:** Google Gemini API (`triage.py`, free tier), structured JSON output (verdict,
  confidence, reasoning, recommended action, IOCs)
- **Frontend:** single-page dark-themed dashboard, vanilla JS (no build step)

## Features

- Full-text log search over ingested raw logs (SQLite FTS5)
- Rule-based detection engine that raises alerts (SSH brute-force, malware
  keyword match, port scan) — easy to extend with new rules
- AI triage on demand per alert: verdict, confidence score, plain-English
  reasoning, recommended action, extracted IOCs
- Hard-coded human-in-the-loop gate: severity + confidence thresholds decide
  whether an alert can auto-close or must wait for analyst approval/override
- Analyst actions: approve AI verdict, override to false positive, resolve
- Dashboard with live stats (logs ingested, open alerts, pending review count)

## Getting started

```bash
git clone <this-repo-url>
cd soc-ai-console
python -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements.txt

cp .env.example .env
# edit .env and set GEMINI_API_KEY (free key at https://aistudio.google.com/apikey)

uvicorn backend.main:app --reload
```

Open **http://127.0.0.1:8000**, click **"Ingest sample dataset"** to load the
bundled synthetic logs (`sample_data/sample_logs.jsonl`), then open any alert
in the queue and click **Run AI Triage**.

Alternatively, ingest via the API/CLI:

```bash
python scripts/load_sample_data.py
```

## API overview

| Method | Path | Description |
|---|---|---|
| POST | `/api/ingest` | Ingest raw log entries, runs detection rules |
| POST | `/api/load-sample` | Loads the bundled sample dataset |
| GET | `/api/logs/search?q=` | Full-text search over ingested logs |
| GET | `/api/alerts` | List alerts (filter by `status`, `severity`) |
| GET | `/api/alerts/{id}` | Alert detail + related log lines |
| POST | `/api/alerts/{id}/triage` | Run AI triage on an alert |
| POST | `/api/alerts/{id}/approve` | Human approves the AI verdict |
| POST | `/api/alerts/{id}/override` | Human overrides the AI verdict |
| POST | `/api/alerts/{id}/resolve` | Mark an alert resolved |
| GET | `/api/stats` | Dashboard summary counts |

## Extending

- **New detection rules:** add a function to `backend/detection.py` and wire
  it into `run_detections()`.
- **Different LLM prompt/behavior:** edit `SYSTEM_PROMPT` in
  `backend/triage.py`. The confidence/severity gate logic lives in the same
  file and is intentionally kept separate from the prompt.
- **Real log sources:** point a log shipper (syslog, Filebeat, etc.) at a
  small adapter that POSTs batches to `/api/ingest`.

## Project background

Built as a hands-on SOC/full-stack portfolio project, using the general
alert-triage workflow (clustering, confidence calibration, escalation
handoff) that a real SOC L1/L2 analyst follows, implemented as working
software rather than a slide deck.

## License

MIT
