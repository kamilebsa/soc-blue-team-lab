
from src.detector.network_detector import analyze_network_event


def test_flags_telnet_connection():
    result = analyze_network_event({
        "event_type": "connection_allowed",
        "destination_port": 23,
    })
    assert result["severity"] == "HIGH"
    assert "Telnet" in result["message"]


def test_flags_port_scan():
    result = analyze_network_event({
        "event_type": "port_scan_detected"
    })
    assert result["severity"] == "HIGH"


def test_blocked_connection_is_info():
    result = analyze_network_event({
        "event_type": "connection_blocked"
    })
    assert result["severity"] == "INFO"


def test_unknown_event_is_low():
    result = analyze_network_event({
        "event_type": "unknown"
    })
    assert result["severity"] == "LOW"
