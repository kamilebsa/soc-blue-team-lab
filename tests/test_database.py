from src.siem.database import init_db, save_event, get_events


def test_init_db_creates_database(tmp_path):
    db_path = tmp_path / "test.db"

    init_db(db_path)

    assert db_path.exists()


def test_save_and_get_event(tmp_path):
    db_path = tmp_path / "test.db"
    event = {
        "id": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "event_type": "login_failed",
        "source_ip": "192.0.2.10",
        "message": "Falha de login para teste",
        "severity": "WARNING",
    }

    save_event(event, db_path)

    assert get_events(db_path) == [event]


def test_get_events_returns_empty_list(tmp_path):
    db_path = tmp_path / "test.db"

    assert get_events(db_path) == []
