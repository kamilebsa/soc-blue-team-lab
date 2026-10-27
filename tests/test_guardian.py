from src.guardian.guardian import evaluate_event


def test_critical_event_recommends_isolation_candidate():
    result = evaluate_event({
        "id": 1,
        "event_type": "suspicious_activity",
        "source_ip": "192.0.2.10",
        "severity": "CRITICAL",
    })

    assert result["action"] == "isolate_candidate"
    assert result["mode"] == "simulation"
    assert result["executed"] is False


def test_high_event_recommends_investigation():
    result = evaluate_event({"severity": "HIGH"})

    assert result["action"] == "investigate_and_monitor"


def test_medium_event_recommends_monitoring():
    result = evaluate_event({"severity": "MEDIUM"})

    assert result["action"] == "monitor"


def test_warning_event_is_handled_explicitly():
    result = evaluate_event({"severity": "WARNING"})

    assert result["severity"] == "WARNING"
    assert result["action"] == "monitor"


def test_malware_event_recommends_isolation_candidate():
    result = evaluate_event({
        "event_type": "malware_detected",
        "severity": "LOW",
    })

    assert result["action"] == "isolate_candidate"
    assert result["executed"] is False


def test_invalid_event_returns_investigation():
    result = evaluate_event(None)

    assert result["action"] == "investigate"
    assert result["mode"] == "simulation"
