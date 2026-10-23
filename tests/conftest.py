import pytest

from src.siem import api


@pytest.fixture(autouse=True)
def isolate_api_data(tmp_path, monkeypatch):
    monkeypatch.setattr(
        api,
        "EVENTS_FILE",
        tmp_path / "siem_events.jsonl",
    )
    monkeypatch.setattr(api, "events", [])
    monkeypatch.setattr(api, "API_KEY", "chave-teste-local")
    test_db = tmp_path / "siem.db"
    monkeypatch.setattr(api, "DB_FILE", test_db)
    monkeypatch.setattr(api.database, "DB_FILE", test_db)
