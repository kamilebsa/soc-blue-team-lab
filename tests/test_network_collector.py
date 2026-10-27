import json
import urllib.error

from src.detector import network_collector as collector


def test_collect_saves_event_even_when_api_is_unavailable(
    tmp_path, monkeypatch
):
    output = tmp_path / "network_events.jsonl"
    monkeypatch.setattr(collector, "OUTPUT_FILE", output)
    monkeypatch.setattr(collector, "get_local_ip", lambda: "192.0.2.15")
    monkeypatch.setattr(
        collector, "send_event_to_api", lambda event: False
    )

    collector.collect_network_event()

    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    event = json.loads(lines[0])
    assert event["source_ip"] == "192.0.2.15"
    assert event["event_type"] == "network_observation"
    assert event["severity"] == "INFO"
    assert event["timestamp"]


def test_collect_handles_local_file_error(tmp_path, monkeypatch, capsys):
    output = tmp_path / "missing" / "events.jsonl"
    monkeypatch.setattr(collector, "OUTPUT_FILE", output)
    monkeypatch.setattr(collector, "get_local_ip", lambda: "127.0.0.1")

    def fail_to_save(event):
        raise OSError("simulated disk error")

    monkeypatch.setattr(collector, "save_event_locally", fail_to_save)
    sent = []
    monkeypatch.setattr(
        collector, "send_event_to_api", lambda event: sent.append(event)
    )

    collector.collect_network_event()

    assert sent == []
    assert "Falha ao salvar" in capsys.readouterr().out


def test_send_event_without_api_key_does_not_send(monkeypatch, capsys):
    monkeypatch.delenv("SIEM_API_KEY", raising=False)

    def unexpected_request(*args, **kwargs):
        raise AssertionError("Não deveria fazer requisição")

    monkeypatch.setattr(collector.urllib.request, "urlopen", unexpected_request)

    result = collector.send_event_to_api({
        "event_type": "network_observation",
        "source_ip": "192.0.2.15",
        "message": "Evento fictício",
        "severity": "INFO",
    })

    assert result is False
    assert "não está configurada" in capsys.readouterr().out


def test_send_event_returns_true_on_http_success(monkeypatch, capsys):
    monkeypatch.setenv("SIEM_API_KEY", "chave-ficticia-de-teste")

    class FakeResponse:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"message":"ok"}'

    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(collector.urllib.request, "urlopen", fake_urlopen)

    result = collector.send_event_to_api({
        "event_type": "network_observation",
        "source_ip": "192.0.2.15",
        "message": "Evento fictício",
        "severity": "INFO",
    })

    assert result is True
    assert captured["timeout"] == 5
    assert captured["request"].get_header("X-api-key") == (
        "chave-ficticia-de-teste"
    )
    assert "HTTP 201" in capsys.readouterr().out


def test_send_event_handles_http_401(monkeypatch, capsys):
    monkeypatch.setenv("SIEM_API_KEY", "chave-ficticia-de-teste")

    def unauthorized(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", {}, None
        )

    monkeypatch.setattr(collector.urllib.request, "urlopen", unauthorized)

    result = collector.send_event_to_api({
        "event_type": "network_observation",
        "source_ip": "192.0.2.15",
        "message": "Evento fictício",
        "severity": "INFO",
    })

    assert result is False
    assert "Autenticação recusada" in capsys.readouterr().out
