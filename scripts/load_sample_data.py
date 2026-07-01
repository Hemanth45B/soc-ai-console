"""
Loads sample_data/sample_logs.jsonl into a running SOC AI Console instance
via its HTTP API. Useful for demoing ingestion from an external source
instead of the "Ingest sample dataset" button in the UI.

Usage:
    python scripts/load_sample_data.py [--base-url http://127.0.0.1:8000]
"""
import argparse
import json
from pathlib import Path
from urllib import request

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "sample_data" / "sample_logs.jsonl"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    logs = []
    with open(SAMPLE_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                logs.append(json.loads(line))

    payload = json.dumps({"logs": logs}).encode("utf-8")
    req = request.Request(
        f"{args.base_url}/api/ingest",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req) as resp:
        print(json.loads(resp.read()))


if __name__ == "__main__":
    main()
