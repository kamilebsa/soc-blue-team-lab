from src.detector.network_detector import analyze_network_event


def test_flags_telnet_connection():
    result = analyze_network_event({
        "event_type": "connection_allowed",
        "destination_port": 23,
    })
    assert result["severity"] == "HIGH"
    assert "Telnet" in result["message"]


def test_flags_telnet_port_as_string():
    result = analyze_network_event({
        "event_type": "connection_allowed",
        "destination_port": "23",
    })
    assert result["severity"] == "HIGH"


def test_flags_port_scan():
    result = analyze_network_event({"event_type": "port_scan_detected"})
    assert result["severity"] == "HIGH"


def test_blocked_connection_is_info():
    result = analyze_network_event({"event_type": "connection_blocked"})
    assert result["severity"] == "INFO"


def test_flags_malware():
    result = analyze_network_event({"event_type": "malware_detected"})
    assert result["severity"] == "CRITICAL"


def test_flags_unauthorized_device():
    result = analyze_network_event({"event_type": "unauthorized_device"})
    assert result["severity"] == "HIGH"


def test_flags_repeated_connection_attempts():
    result = analyze_network_event({
        "event_type": "repeated_connection_attempts"
    })
    assert result["severity"] == "HIGH"


def test_flags_suspicious_dns_query():
    result = analyze_network_event({"event_type": "suspicious_dns_query"})
    assert result["severity"] == "HIGH"


def test_event_type_is_case_insensitive():
    result = analyze_network_event({"event_type": "PORT_SCAN_DETECTED"})
    assert result["severity"] == "HIGH"


def test_unknown_event_is_low():
    result = analyze_network_event({"event_type": "unknown"})
    assert result["severity"] == "LOW"


def test_invalid_event_is_handled():
    result = analyze_network_event(None)
    assert result["severity"] == "LOW"
    assert "inválido" in result["message"]
