import json
import os
import subprocess
import sys


def run_isolated_process(db_file, events_file, code):
    env = os.environ.copy()
    env["SIEM_DB_FILE"] = str(db_file)
    env["SIEM_EVENTS_FILE"] = str(events_file)
    env["SIEM_API_KEY"] = "chave-teste-isolado"

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, (
        f"Processo falhou.\nSTDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )
    return result.stdout


def test_event_survives_api_module_process_restart(tmp_path):
    db_file = tmp_path / "restart_test.db"
    events_file = tmp_path / "restart_events.jsonl"

    event = {
        "id": 901,
        "timestamp": "2026-01-01T12:00:00+00:00",
        "event_type": "login_failed",
        "source_ip": "192.0.2.90",
        "message": "Evento de teste de reinicialização",
        "severity": "WARNING",
    }

    save_code = """
import json
from src.siem import api
event = json.loads(%r)
api.save_event(event)
print("EVENT_SAVED")
""" % json.dumps(event)

    load_code = """
import json
from src.siem import api, database
events = database.get_events(api.DB_FILE)
assert any(e.get("id") == 901 for e in events), events
print("EVENT_RECOVERED")
"""

    assert "EVENT_SAVED" in run_isolated_process(
        db_file, events_file, save_code
    )

    output = run_isolated_process(db_file, events_file, load_code)
    assert "EVENT_RECOVERED" in output

    lines = events_file.read_text(encoding="utf-8").splitlines()
    assert any(json.loads(line).get("id") == 901 for line in lines)
