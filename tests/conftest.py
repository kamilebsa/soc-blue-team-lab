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
