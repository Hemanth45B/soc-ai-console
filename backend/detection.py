"""
Lightweight rule-based detection engine.

This is intentionally simple (keyword / threshold rules) rather than a full
correlation engine — its job is to turn raw ingested logs into candidate
alerts that the AI triage engine (triage.py) then reasons about. Swap or
extend RULES to add real detections.
"""
from collections import defaultdict

from . import database as db

MALWARE_KEYWORDS = ["malware", "trojan", "ransomware", "reverse shell", "cobalt strike"]


def run_detections(conn, log_ids):
    """Run all detection rules over the given newly-ingested log ids."""
    logs = db.get_logs_by_ids(conn, log_ids)
    created = []
    created += _rule_ssh_bruteforce(conn, logs)
    created += _rule_malware_keyword(conn, logs)
    created += _rule_port_scan(conn, logs)
    return created


def _rule_ssh_bruteforce(conn, logs, threshold=4):
    by_ip = defaultdict(list)
    for log in logs:
        if "failed password" in log["raw_log"].lower():
            by_ip[log.get("source_ip") or "unknown"].append(log["id"])

    created = []
    for ip, ids in by_ip.items():
        if len(ids) >= threshold:
            alert_id = db.insert_alert(
                conn,
                title=f"Possible SSH brute-force from {ip}",
                description=f"{len(ids)} failed password attempts detected from {ip} "
                             f"in the current ingestion batch.",
                severity="high",
                rule_name="ssh_bruteforce",
                related_log_ids=ids,
            )
            created.append(alert_id)
    return created


def _rule_malware_keyword(conn, logs):
    created = []
    for log in logs:
        text = log["raw_log"].lower()
        if any(k in text for k in MALWARE_KEYWORDS):
            alert_id = db.insert_alert(
                conn,
                title=f"Malware indicator on {log.get('host') or 'unknown host'}",
                description="Log line matched a known malware/adversary keyword.",
                severity="critical",
                rule_name="malware_keyword",
                related_log_ids=[log["id"]],
            )
            created.append(alert_id)
    return created


def _rule_port_scan(conn, logs, threshold=5):
    by_ip = defaultdict(set)
    ids_by_ip = defaultdict(list)
    for log in logs:
        text = log["raw_log"].lower()
        if "connection attempt" in text or "port scan" in text:
            ip = log.get("source_ip") or "unknown"
            by_ip[ip].add(log["id"])
            ids_by_ip[ip].append(log["id"])

    created = []
    for ip, ids in by_ip.items():
        if len(ids) >= threshold:
            alert_id = db.insert_alert(
                conn,
                title=f"Possible port scan from {ip}",
                description=f"{len(ids)} connection-attempt log lines from {ip} "
                             f"in the current ingestion batch.",
                severity="medium",
                rule_name="port_scan",
                related_log_ids=list(ids),
            )
            created.append(alert_id)
    return created
