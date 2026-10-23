from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime, timezone

app = FastAPI(
    title="Mini SIEM API",
    description="API de laboratório para eventos de segurança",
    version="1.0.0"
)

events = []


class SecurityEvent(BaseModel):
    event_type: str
    source_ip: str
    message: str
    severity: str = "INFO"


@app.get("/")
def home():
    return {
        "project": "Mini SIEM API",
        "status": "online"
    }


@app.post("/events")
def create_event(event: SecurityEvent):
    record = event.dict()
    record["id"] = len(events) + 1
    record["timestamp"] = datetime.now(timezone.utc).isoformat()
    events.append(record)

    return {
        "message": "Evento registrado",
        "event": record
    }


@app.get("/events")
def list_events():
    return {
        "total": len(events),
        "events": events
    }


@app.get("/alerts")
def list_alerts():
    alerts = [
        event for event in events
        if event["severity"].upper() in ("HIGH", "CRITICAL")
    ]

    return {
        "total": len(alerts),
        "alerts": alerts
    }


@app.get("/stats")
def statistics():
    return {
        "total_events": len(events),
        "total_alerts": sum(
            1 for event in events
            if event["severity"].upper() in ("HIGH", "CRITICAL")
        )
    }

from fastapi.responses import FileResponse
from pathlib import Path

@app.get("/dashboard", include_in_schema=False)
def dashboard():
    caminho = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"
    return FileResponse(caminho)
