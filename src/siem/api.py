from datetime import datetime, timezone
from pathlib import Path
import json

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(
    title="Mini SIEM API",
    version="1.0.0",
    description="API de laboratório para eventos de segurança"
)

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
EVENTS_FILE = DATA_DIR / "siem_events.jsonl"
DASHBOARD_FILE = BASE_DIR / "dashboard" / "index.html"

DATA_DIR.mkdir(parents=True, exist_ok=True)


class SecurityEvent(BaseModel):
    event_type: str
    source_ip: str
    message: str
    severity: str = "INFO"


def load_events():
    records = []
    if not EVENTS_FILE.exists():
        return records

    with EVENTS_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


events = load_events()


def save_event(event):
    with EVENTS_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")


@app.get("/")
def home():
    return {"project": "Mini SIEM API", "status": "online"}


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(DASHBOARD_FILE)


@app.post("/events")
def create_event(event: SecurityEvent):
    record = event.dict()
    record["id"] = max(
        (item.get("id", 0) for item in events),
        default=0
    ) + 1
    record["timestamp"] = datetime.now(timezone.utc).isoformat()

    events.append(record)
    save_event(record)

    return {"message": "Evento registrado", "event": record}


@app.get("/events")
def list_events():
    return {"total": len(events), "events": events}


@app.get("/alerts")
def list_alerts():
    alerts = [
        event for event in events
        if event.get("severity", "INFO").upper() in ("HIGH", "CRITICAL")
    ]
    return {"total": len(alerts), "alerts": alerts}


@app.get("/stats")
def statistics():
    return {
        "total_events": len(events),
        "total_alerts": sum(
            1 for event in events
            if event.get("severity", "INFO").upper() in ("HIGH", "CRITICAL")
        )
    }
