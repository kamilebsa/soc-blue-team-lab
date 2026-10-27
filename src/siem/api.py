from datetime import datetime, timezone
from pathlib import Path
import json
import os
import secrets

from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel, validator

from src.siem import database
from src.detector.network_detector import analyze_network_event
from src.guardian.guardian import evaluate_event

app = FastAPI(
    title="Mini SIEM API",
    version="1.1.0",
    description="API de laboratório para eventos de segurança"
)

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
EVENTS_FILE = Path(
    os.getenv("SIEM_EVENTS_FILE", str(DATA_DIR / "siem_events.jsonl"))
)
DB_FILE = Path(os.getenv("SIEM_DB_FILE", str(database.DB_FILE)))
DASHBOARD_FILE = BASE_DIR / "dashboard" / "index.html"
BRUTE_FORCE_THRESHOLD = 5
API_KEY = os.getenv("SIEM_API_KEY")


def verify_api_key(x_api_key: str = Header(default=None, alias="X-API-Key")):
    if not API_KEY or not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Chave de API inválida ou ausente",
        )

DATA_DIR.mkdir(parents=True, exist_ok=True)


class SecurityEvent(BaseModel):
    event_type: str
    source_ip: str
    message: str
    severity: str = "INFO"
    destination_port: int | None = None

    @validator("event_type")
    def validate_event_type(cls, value):
        value = value.strip()
        if not value or len(value) > 100:
            raise ValueError("event_type deve ter entre 1 e 100 caracteres")
        return value

    @validator("source_ip")
    def validate_source_ip(cls, value):
        import ipaddress
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise ValueError("source_ip deve ser um endereço IP válido")

    @validator("message")
    def validate_message(cls, value):
        value = value.strip()
        if not value or len(value) > 2000:
            raise ValueError("message deve ter entre 1 e 2000 caracteres")
        return value

    @validator("severity")
    def validate_severity(cls, value):
        value = value.strip().upper()
        if value not in {"INFO", "LOW", "MEDIUM", "WARNING", "HIGH", "CRITICAL"}:
            raise ValueError("severity inválida")
        return value

    @validator("destination_port")
    def validate_destination_port(cls, value):
        if value is not None and not 1 <= value <= 65535:
            raise ValueError("destination_port deve estar entre 1 e 65535")
        return value


def load_events(events_file=None):
    records = []
    path = Path(events_file) if events_file else EVENTS_FILE
    if not path.exists():
        return records

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def initialize_storage(db_file=None, events_file=None):
    db_path = Path(db_file) if db_file else DB_FILE
    database.init_db(db_path)
    stored_events = database.get_events(db_path)

    if not stored_events:
        required = ("id", "timestamp", "event_type", "source_ip", "message")
        for legacy_event in load_events(events_file):
            if all(key in legacy_event for key in required):
                database.save_event(legacy_event, db_path)
        stored_events = database.get_events(db_path)

    return stored_events


events = initialize_storage()


def save_event(event):
    database.save_event(event, DB_FILE)
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
def create_event(event: SecurityEvent, _: None = Depends(verify_api_key)):
    record = event.dict(exclude_none=True)
    record["id"] = max(
        (item.get("id", 0) for item in events),
        default=0
    ) + 1
    record["timestamp"] = datetime.now(timezone.utc).isoformat()

    network_event_types = {
        "connection_blocked",
        "connection_allowed",
        "port_scan_detected",
        "malware_detected",
        "unauthorized_device",
        "repeated_connection_attempts",
        "suspicious_dns_query",
    }

    event_type = record["event_type"].strip().lower()
    if event_type in network_event_types:
        analysis = analyze_network_event(record)
        record["severity"] = analysis["severity"]
        record["message"] = analysis["message"]

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
def list_events(_: None = Depends(verify_api_key)):
    stored_events = database.get_events(DB_FILE)
    return {"total": len(stored_events), "events": stored_events}


@app.get("/alerts")
def list_alerts(_: None = Depends(verify_api_key)):
    stored_events = database.get_events(DB_FILE)
    alerts = [
        event for event in stored_events
        if event.get("severity", "INFO").upper() in ("HIGH", "CRITICAL")
    ]
    return {"total": len(alerts), "alerts": alerts}




@app.get("/guardian")
def guardian_report(_: None = Depends(verify_api_key)):
    stored_events = database.get_events(DB_FILE)
    decisions = [evaluate_event(event) for event in stored_events]
    return {
        "mode": "simulation",
        "executed_actions": 0,
        "total_events": len(decisions),
        "decisions": decisions,
    }

@app.get("/stats")
def statistics(_: None = Depends(verify_api_key)):
    stored_events = database.get_events(DB_FILE)
    return {
        "total_events": len(stored_events),
        "total_alerts": sum(
            1 for event in stored_events
            if event.get("severity", "INFO").upper()
            in ("HIGH", "CRITICAL")
        )
    }
