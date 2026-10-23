import json
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DB_FILE = BASE_DIR / "data" / "siem.db"


def get_connection(db_path=None):
    path = Path(db_path) if db_path else DB_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path=None):
    with get_connection(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )


def save_event(event, db_path=None):
    init_db(db_path)

    details = json.dumps(event, ensure_ascii=False)

    with get_connection(db_path) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO events (
                id, timestamp, event_type, source_ip,
                message, severity, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["id"],
                event["timestamp"],
                event["event_type"],
                event["source_ip"],
                event["message"],
                event.get("severity", "INFO"),
                details,
            ),
        )


def get_events(db_path=None):
    init_db(db_path)

    with get_connection(db_path) as connection:
        rows = connection.execute(
            "SELECT details_json FROM events ORDER BY id"
        ).fetchall()

    return [json.loads(row["details_json"]) for row in rows]
