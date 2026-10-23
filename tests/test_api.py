

from fastapi.testclient import TestClient

from src.siem import api


client = TestClient(api.app, headers={"X-API-Key": "chave-teste-local"})


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
def test_brute_force_generates_alert_after_five_failures():
    source_ip = "198.51.100.25"

    api.events[:] = [
        event for event in api.events
        if event.get("source_ip") != source_ip
    ]

    for attempt in range(5):
        response = client.post(
            "/events",
            json={
                "event_type": "login_failed",
                "source_ip": source_ip,
                "message": f"Falha de login {attempt + 1}",
                "severity": "WARNING",
            },
        )
        assert response.status_code == 200

    data = response.json()

    assert data["alert"] is not None
    assert data["alert"]["event_type"] == "brute_force_detected"
    assert data["alert"]["severity"] == "CRITICAL"


def test_events_rejects_missing_api_key():
    client_without_key = TestClient(api.app)
    response = client_without_key.get("/events")
    assert response.status_code == 401


def test_events_rejects_invalid_api_key():
    client_with_wrong_key = TestClient(api.app)
    response = client_with_wrong_key.get(
        "/events",
        headers={"X-API-Key": "chave-errada"},
    )
    assert response.status_code == 401

def test_alerts_rejects_missing_api_key():
    response = TestClient(api.app).get("/alerts")
    assert response.status_code == 401


def test_stats_rejects_missing_api_key():
    response = TestClient(api.app).get("/stats")
    assert response.status_code == 401


def test_create_event_rejects_missing_api_key():
    response = TestClient(api.app).post(
        "/events",
        json={
            "event_type": "test_event",
            "source_ip": "192.0.2.10",
            "message": "Teste sem chave",
            "severity": "INFO",
        },
    )
    assert response.status_code == 401
