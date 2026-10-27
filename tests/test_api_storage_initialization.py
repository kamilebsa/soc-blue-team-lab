import json

from src.siem import api, database


def test_initialize_storage_recovers_existing_events(tmp_path):
    db_file = tmp_path / "test_siem.db"
    events_file = tmp_path / "events.jsonl"

    event = {
        "id": 1,
        "timestamp": "2026-01-01T12:00:00+00:00",
        "event_type": "login_failed",
        "source_ip": "192.0.2.10",
        "message": "Falha de login simulada",
        "severity": "WARNING",
    }

    database.save_event(event, db_file)

    recovered = api.initialize_storage(db_file, events_file)

    assert recovered == [event]


def test_initialize_storage_imports_legacy_jsonl(tmp_path):
    db_file = tmp_path / "legacy_siem.db"
    events_file = tmp_path / "legacy_events.jsonl"

    event = {
        "id": 7,
        "timestamp": "2026-01-01T12:00:00+00:00",
        "event_type": "port_scan_detected",
        "source_ip": "192.0.2.20",
        "message": "Varredura simulada",
        "severity": "HIGH",
    }

    events_file.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    recovered = api.initialize_storage(db_file, events_file)

    assert recovered == [event]
    assert database.get_events(db_file) == [event]
