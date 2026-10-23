from datetime import datetime, timezone
from pathlib import Path
import json

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(
    title="Mini SIEM API",
    version="1.1.0",
    description="API de laboratório para eventos de segurança"
)

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
EVENTS_FILE = DATA_DIR / "siem_events.jsonl"
DASHBOARD_FILE = BASE_DIR / "dashboard" / "index.html"
BRUTE_FORCE_THRESHOLD = 5

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


def is_failed_login(event):
    return event.get("event_type", "").lower() in (
        "login_failed",
        "failed_login",
    )


def detect_brute_force(source_ip):
    failures = [
        event for event in events
        if event.get("source_ip") == source_ip
        and is_failed_login(event)
    ]

    if len(failures) < BRUTE_FORCE_THRESHOLD:
        return None

    existing_alert = any(
        event.get("event_type") == "brute_force_detected"
        and event.get("source_ip") == source_ip
        for event in events
    )

    if existing_alert:
        return None

    alert = {
        "event_type": "brute_force_detected",
        "source_ip": source_ip,
        "message": (
            f"Força bruta detectada: {len(failures)} "
            "falhas de login registradas para este IP"
        ),
        "severity": "CRITICAL",
        "id": max(
            (item.get("id", 0) for item in events),
            default=0
        ) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    events.append(alert)
    save_event(alert)
    return alert


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

    alert = None
    if is_failed_login(record):
        alert = detect_brute_force(record["source_ip"])

    return {
        "message": "Evento registrado",
        "event": record,
        "alert": alert,
    }


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
            if event.get("severity", "INFO").upper()
            in ("HIGH", "CRITICAL")
        )
    }
