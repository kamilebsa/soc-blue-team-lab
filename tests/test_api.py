
from fastapi.testclient import TestClient

from src.siem import api


client = TestClient(api.app)


def test_home_returns_online_status():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_list_events_returns_expected_structure():
    response = client.get("/events")

    assert response.status_code == 200
    assert "total" in response.json()
    assert "events" in response.json()


def test_list_alerts_returns_expected_structure():
    response = client.get("/alerts")

    assert response.status_code == 200
    assert "total" in response.json()
    assert "alerts" in response.json()


def test_stats_returns_expected_structure():
    response = client.get("/stats")

    assert response.status_code == 200

    data = response.json()
    assert "total_events" in data
    assert "total_alerts" in data


def test_create_event():
    response = client.post(
        "/events",
        json={
            "event_type": "test_event",
            "source_ip": "192.0.2.10",
            "message": "Evento criado durante teste automatizado",
            "severity": "INFO",
        },
    )

    assert response.status_code == 200

    data = response.json()
    assert data["message"] == "Evento registrado"
    assert data["event"]["event_type"] == "test_event"
    assert data["event"]["source_ip"] == "192.0.2.10"
    assert "id" in data["event"]
    assert "timestamp" in data["event"]


def test_create_event_rejects_missing_fields():
    response = client.post(
        "/events",
        json={"event_type": "test_event"},
    )

    assert response.status_code == 422
