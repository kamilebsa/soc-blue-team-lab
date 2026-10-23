"""Detector simples de eventos de rede para laboratório SOC."""


def analyze_network_event(event):
    """Classifica um evento de rede fictício."""

    event_type = event.get("event_type", "").lower()
    destination_port = event.get("destination_port")

    if event_type == "connection_blocked":
        return {
            "severity": "INFO",
            "message": "Conexão bloqueada pelo controle de segurança",
        }

    if event_type == "connection_allowed" and destination_port == 23:
        return {
            "severity": "HIGH",
            "message": "Conexão permitida usando Telnet (porta 23)",
        }

    if event_type == "port_scan_detected":
        return {
            "severity": "HIGH",
            "message": "Possível varredura de portas detectada",
        }

    return {
        "severity": "LOW",
        "message": "Evento de rede sem regra específica",
    }
