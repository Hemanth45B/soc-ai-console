"""
AI triage engine.

Sends an alert plus its related raw log lines to Gemini and asks for a
structured SOC-analyst-style verdict. High/critical severity alerts, and any
alert the model is not confident about, are always routed to a human
(`requires_human_approval=True`, status='pending_human_review'). This gate is
intentionally never bypassable from this module.
"""
import json
import os
import re

from google import genai
from google.genai import types

TRIAGE_MODEL = os.environ.get("TRIAGE_MODEL", "gemini-2.5-flash")
AUTO_CLOSE_CONFIDENCE_THRESHOLD = int(os.environ.get("AUTO_CLOSE_CONFIDENCE_THRESHOLD", "85"))

SYSTEM_PROMPT = """You are a Tier-1 SOC analyst assistant. You will be given an
alert (raised by a detection rule) and the raw log lines that triggered it.

Respond with ONLY a JSON object (no markdown fences, no preamble) with exactly
these keys:
{
  "verdict": "true_positive" | "false_positive" | "needs_investigation",
  "confidence": <integer 0-100>,
  "reasoning": "<2-4 sentences of analyst-style reasoning>",
  "recommended_action": "<one short, concrete next step>",
  "iocs": ["<indicator strings extracted from the logs, e.g. IPs, hashes, domains>"]
}

Be conservative: if the evidence is ambiguous, use "needs_investigation" and a
lower confidence rather than guessing.
"""


def _client() -> genai.Client:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Copy .env.example to .env and add your key "
            "(free key at https://aistudio.google.com/apikey)."
        )
    return genai.Client(api_key=api_key)


def _build_user_prompt(alert: dict, logs: list) -> str:
    log_block = "\n".join(
        f"[{log['timestamp']}] host={log.get('host')} src_ip={log.get('source_ip')} "
        f"type={log.get('log_type')} :: {log['raw_log']}"
        for log in logs
    )
    return (
        f"ALERT TITLE: {alert['title']}\n"
        f"RULE: {alert.get('rule_name')}\n"
        f"SEVERITY (from detection rule): {alert['severity']}\n"
        f"DESCRIPTION: {alert.get('description')}\n\n"
        f"RELATED LOG LINES:\n{log_block or '(no related log lines found)'}\n"
    )


def _extract_json(text: str) -> dict:
    text = text.strip()
    # Strip accidental markdown fences if the model adds them anyway.
    text = re.sub(r"^```(json)?|```$", "", text, flags=re.MULTILINE).strip()
    return json.loads(text)


def triage_alert(alert: dict, logs: list) -> dict:
    """Calls Gemini to triage a single alert. Returns a dict ready to persist."""
    client = _client()
    response = client.models.generate_content(
        model=TRIAGE_MODEL,
        contents=_build_user_prompt(alert, logs),
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            max_output_tokens=600,
            temperature=0.2,
        ),
    )
    raw_text = response.text or ""

    try:
        parsed = _extract_json(raw_text)
        verdict = parsed.get("verdict", "needs_investigation")
        confidence = int(parsed.get("confidence", 0))
        reasoning = parsed.get("reasoning", "")
        recommended_action = parsed.get("recommended_action", "")
        iocs = parsed.get("iocs", [])
    except (json.JSONDecodeError, ValueError, TypeError):
        # Model output didn't parse cleanly — fail safe to human review.
        verdict = "needs_investigation"
        confidence = 0
        reasoning = f"AI response could not be parsed automatically. Raw output: {raw_text[:500]}"
        recommended_action = "Manual review required."
        iocs = []

    # --- Human-in-the-loop gate (non-negotiable) ---
    high_severity = alert["severity"] in ("high", "critical")
    low_confidence = confidence < AUTO_CLOSE_CONFIDENCE_THRESHOLD
    needs_investigation = verdict == "needs_investigation"

    requires_human_approval = high_severity or low_confidence or needs_investigation
    status = "pending_human_review" if requires_human_approval else "triaged_auto"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "recommended_action": recommended_action,
        "iocs": iocs,
        "requires_human_approval": requires_human_approval,
        "status": status,
    }
