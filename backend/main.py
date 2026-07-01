import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import database as db
from . import detection
from . import triage
from .models import IngestRequest, DecisionRequest, OverrideRequest

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="SOC AI Console", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    db.init_db()


# ---------- Frontend ----------

app.mount("/static", StaticFiles(directory=FRONTEND_DIR / "static"), name="static")


@app.get("/")
def serve_index():
    return FileResponse(FRONTEND_DIR / "index.html")


# ---------- Log ingestion & search ----------

@app.post("/api/ingest")
def ingest_logs(payload: IngestRequest):
    if not payload.logs:
        raise HTTPException(400, "No logs provided")

    with db.get_conn() as conn:
        inserted_ids = [
            db.insert_log(
                conn,
                timestamp=log.timestamp,
                source_ip=log.source_ip,
                host=log.host,
                log_type=log.log_type,
                raw_log=log.raw_log,
            )
            for log in payload.logs
        ]
        new_alert_ids = detection.run_detections(conn, inserted_ids)

    return {"ingested": len(inserted_ids), "alerts_created": len(new_alert_ids),
            "alert_ids": new_alert_ids}


@app.post("/api/load-sample")
def load_sample():
    """Loads the bundled sample_data/sample_logs.jsonl into the database and
    runs detection over it — a quick way to see the console working end-to-end."""
    import json as _json
    sample_path = BASE_DIR / "sample_data" / "sample_logs.jsonl"
    if not sample_path.exists():
        raise HTTPException(404, "sample_data/sample_logs.jsonl not found")

    entries = []
    with open(sample_path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(_json.loads(line))

    with db.get_conn() as conn:
        inserted_ids = [
            db.insert_log(
                conn,
                timestamp=e["timestamp"],
                source_ip=e.get("source_ip"),
                host=e.get("host"),
                log_type=e.get("log_type"),
                raw_log=e["raw_log"],
            )
            for e in entries
        ]
        new_alert_ids = detection.run_detections(conn, inserted_ids)

    return {"ingested": len(inserted_ids), "alerts_created": len(new_alert_ids)}


@app.get("/api/logs/search")
def search(q: str = "", limit: int = 50):
    with db.get_conn() as conn:
        if q.strip():
            return db.search_logs(conn, q, limit)
        return db.recent_logs(conn, limit)


# ---------- Alerts ----------

@app.get("/api/alerts")
def get_alerts(status: str = None, severity: str = None):
    with db.get_conn() as conn:
        return db.list_alerts(conn, status=status, severity=severity)


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    with db.get_conn() as conn:
        alert = db.get_alert(conn, alert_id)
        if not alert:
            raise HTTPException(404, "Alert not found")
        import json
        related_ids = json.loads(alert.get("related_log_ids") or "[]")
        alert["related_logs"] = db.get_logs_by_ids(conn, related_ids)
        return alert


@app.post("/api/alerts/{alert_id}/triage")
def triage_alert(alert_id: int):
    with db.get_conn() as conn:
        alert = db.get_alert(conn, alert_id)
        if not alert:
            raise HTTPException(404, "Alert not found")
        import json
        related_ids = json.loads(alert.get("related_log_ids") or "[]")
        logs = db.get_logs_by_ids(conn, related_ids)

        try:
            result = triage.triage_alert(alert, logs)
        except RuntimeError as e:
            raise HTTPException(400, str(e))

        db.update_alert_triage(
            conn, alert_id,
            verdict=result["verdict"],
            confidence=result["confidence"],
            reasoning=result["reasoning"],
            recommended_action=result["recommended_action"],
            iocs=result["iocs"],
            requires_human_approval=result["requires_human_approval"],
            status=result["status"],
        )
        return db.get_alert(conn, alert_id)


@app.post("/api/alerts/{alert_id}/approve")
def approve_alert(alert_id: int, payload: DecisionRequest = None):
    """Human analyst confirms the AI verdict for a high/critical or
    low-confidence alert and closes it out (or escalates it further)."""
    with db.get_conn() as conn:
        alert = db.get_alert(conn, alert_id)
        if not alert:
            raise HTTPException(404, "Alert not found")
        new_status = "escalated" if alert["ai_verdict"] == "true_positive" else "resolved"
        db.update_alert_human_decision(conn, alert_id, decision="approved", status=new_status)
        return db.get_alert(conn, alert_id)


@app.post("/api/alerts/{alert_id}/override")
def override_alert(alert_id: int, payload: OverrideRequest):
    """Human analyst disagrees with the AI verdict."""
    with db.get_conn() as conn:
        alert = db.get_alert(conn, alert_id)
        if not alert:
            raise HTTPException(404, "Alert not found")
        db.update_alert_triage(
            conn, alert_id,
            verdict=payload.verdict,
            confidence=alert.get("ai_confidence") or 0,
            reasoning=(alert.get("ai_reasoning") or "") + f"\n[Analyst override: {payload.note or ''}]",
            recommended_action=alert.get("ai_recommended_action") or "",
            iocs=[],
            requires_human_approval=False,
            status="resolved" if payload.verdict == "false_positive" else "escalated",
        )
        db.update_alert_human_decision(conn, alert_id, decision="overridden",
                                        status="resolved" if payload.verdict == "false_positive" else "escalated")
        return db.get_alert(conn, alert_id)


@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    with db.get_conn() as conn:
        alert = db.get_alert(conn, alert_id)
        if not alert:
            raise HTTPException(404, "Alert not found")
        db.update_alert_human_decision(conn, alert_id, decision="approved", status="resolved")
        return db.get_alert(conn, alert_id)


@app.get("/api/stats")
def stats():
    with db.get_conn() as conn:
        alerts = db.list_alerts(conn)
        logs = db.recent_logs(conn, limit=1)
        total_logs = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    by_status = {}
    by_severity = {}
    for a in alerts:
        by_status[a["status"]] = by_status.get(a["status"], 0) + 1
        by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
    return {"total_logs": total_logs, "total_alerts": len(alerts),
            "by_status": by_status, "by_severity": by_severity}
