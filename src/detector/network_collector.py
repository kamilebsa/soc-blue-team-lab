
"""Coletor de eventos de rede integrado à Mini SIEM.

Este módulo registra observações localmente e tenta enviá-las
à API autenticada. Ele não monitora todo o tráfego da rede.
"""

import json
import os
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_FILE = PROJECT_ROOT / "data" / "network_events.jsonl"
API_URL = "http://127.0.0.1:8000/events"


def get_local_ip():
    """Obtém o IP local usado para uma conexão de saída."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("1.1.1.1", 443))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def save_event_locally(event):
    """Acrescenta um evento ao arquivo JSONL local."""
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")


def send_event_to_api(event):
    """Envia um evento à API usando a chave de ambiente."""
    api_key = os.environ.get("SIEM_API_KEY")

    if not api_key:
        print("API não chamada: SIEM_API_KEY não está configurada.")
        return False

    payload = json.dumps(event, ensure_ascii=False).encode("utf-8")

    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            print(f"API respondeu com HTTP {response.status}.")
            print(response.read().decode("utf-8"))
            return True

    except urllib.error.HTTPError as error:
        if error.code == 401:
            print("Autenticação recusada: confira se API e coletor usam a mesma chave.")
        else:
            print(f"API respondeu com HTTP {error.code}.")
        return False

    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print(f"Não foi possível enviar à API: {error}")
        print("O evento continua salvo localmente.")
        return False


def collect_network_event():
    """Registra uma observação básica deste aparelho."""
    local_ip = get_local_ip()

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "network_observation",
        "source_ip": local_ip,
        "message": (
            f"Observação de rede do Termux. IP local: {local_ip}"
        ),
        "severity": "INFO",
    }

    try:
        save_event_locally(event)
        print(f"Evento salvo localmente em: {OUTPUT_FILE}")
    except OSError as error:
        print(f"Falha ao salvar o evento localmente: {error}")
        return

    send_event_to_api(event)


if __name__ == "__main__":
    collect_network_event()
0

