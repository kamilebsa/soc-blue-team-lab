"""Guardian: motor de decisões defensivas em modo de simulação."""

SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "WARNING": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def evaluate_event(event):
    """Avalia um evento e recomenda uma resposta, sem bloquear tráfego."""
    if not isinstance(event, dict):
        return {
            "severity": "LOW",
            "action": "investigate",
            "reason": "Evento inválido; revisar os dados recebidos.",
            "mode": "simulation",
            "executed": False,
        }

    severity = str(event.get("severity", "LOW")).strip().upper()
    if severity not in SEVERITY_ORDER:
        severity = "LOW"

    event_type = str(event.get("event_type", "")).strip().lower()

    if severity == "CRITICAL" or event_type == "malware_detected":
        action = "isolate_candidate"
        reason = (
            "Prioridade crítica: investigar e avaliar "
            "isolamento do dispositivo."
        )
    elif severity == "HIGH":
        action = "investigate_and_monitor"
        reason = "Alerta alto: investigar evidências e monitorar a origem."
    elif severity == "WARNING":
        action = "monitor"
        reason = (
            "Alerta de atenção: monitorar e investigar "
            "se houver recorrência."
        )
    elif severity == "MEDIUM":
        action = "monitor"
        reason = "Atividade suspeita: acompanhar novos eventos."
    else:
        action = "log_only"
        reason = "Sem indicação suficiente para uma resposta mais agressiva."

    return {
        "event_id": event.get("id"),
        "event_type": event_type or "unknown",
        "source_ip": event.get("source_ip", "unknown"),
        "severity": severity,
        "action": action,
        "reason": reason,
        "mode": "simulation",
        "executed": False,
    }
