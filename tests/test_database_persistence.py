import json

from src.siem import database


def test_event_survives_database_reopen(tmp_path):
    db_path = tmp_path / "restart-test.db"

    event = {
        "id": 1,
        "timestamp": "2026-10-26T12:00:00+00:00",
        "event_type": "login_failed",
        "source_ip": "192.0.2.10",
        "message": "Evento fictício de teste",
        "severity": "WARNING",
        "custom_field": {"source": "pytest"},
    }

    database.init_db(db_path)
    database.save_event(event, db_path)

    # Simula o encerramento: a próxima leitura abre uma nova conexão.
    recovered = database.get_events(db_path)

    assert len(recovered) == 1
    assert recovered[0] == event
    assert recovered[0]["custom_field"] == {"source": "pytest"}


def test_multiple_events_keep_order_after_reopen(tmp_path):
    db_path = tmp_path / "multiple-events.db"
    database.init_db(db_path)

    for event_id in (1, 2, 3):
        database.save_event({
            "id": event_id,
            "timestamp": f"2026-10-26T12:00:0{event_id}+00:00",
            "event_type": "test_event",
            "source_ip": "192.0.2.10",
            "message": f"Evento {event_id}",
            "severity": "INFO",
        }, db_path)

    recovered = database.get_events(db_path)

    assert [event["id"] for event in recovered] == [1, 2, 3]
