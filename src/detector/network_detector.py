"""Detector de eventos de rede para laboratório SOC."""


def analyze_network_event(event):
    """Classifica eventos de rede recebidos, sem bloquear conexões."""

    if not isinstance(event, dict):
        return {
            "severity": "LOW",
            "message": "Evento inválido: esperado um objeto de dados",
        }

    event_type = str(event.get("event_type") or "").strip().lower()
    destination_port = event.get("destination_port")

    if event_type == "connection_blocked":
        return {
            "severity": "INFO",
            "message": "Conexão bloqueada pelo controle de segurança",
        }

    if event_type == "connection_allowed":
        try:
            port = int(destination_port) if destination_port is not None else None
        except (TypeError, ValueError):
            port = None

        if port == 23:
            return {
                "severity": "HIGH",
                "message": "Conexão permitida usando Telnet (porta 23)",
            }

    rules = {
        "port_scan_detected": (
            "HIGH",
            "Possível varredura de portas detectada",
        ),
        "malware_detected": (
            "CRITICAL",
            "Evento de possível malware detectado; investigar evidências",
        ),
        "unauthorized_device": (
            "HIGH",
            "Possível dispositivo não autorizado detectado",
        ),
        "repeated_connection_attempts": (
            "HIGH",
            "Tentativas repetidas de conexão detectadas",
        ),
        "suspicious_dns_query": (
            "HIGH",
            "Consulta DNS suspeita sinalizada para investigação",
        ),
    }

    if event_type in rules:
        severity, message = rules[event_type]
        return {"severity": severity, "message": message}

    return {
        "severity": "LOW",
        "message": "Evento de rede sem regra específica",
    }
