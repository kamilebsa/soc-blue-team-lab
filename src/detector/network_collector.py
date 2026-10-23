
"""Coletor de rede integrado à Mini SIEM."""

import json
import socket
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_FILE = PROJECT_ROOT / "data" / "network_events.jsonl"
API_URL = "http://127.0.0.1:8000/events"


def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 443))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def collect_network_event():
    local_ip = get_local_ip()

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "network_observation",
        "source_ip": local_ip,
        "message": f"Observação de rede do Termux. IP local: {local_ip}",
        "severity": "INFO",
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")

    payload = json.dumps(event).encode("utf-8")
    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            print("Resposta da Mini SIEM:")
            print(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"Falha ao enviar à API: {error}")
        print("O evento continua salvo localmente.")

    print(f"Evento salvo em: {OUTPUT_FILE}")


if __name__ == "__main__":
    collect_network_event()


