import json
from pathlib import Path


def classify_event(event):
    message = str(event.get("message", "")).lower()
    event_type = str(event.get("event_type", "")).lower()

    if any(word in message for word in [
        "malware", "ransomware", "privilege escalation"
    ]):
        return "CRITICAL"

    if event_type in ("login_failed", "failed_login"):
        return "WARNING"

    if any(word in message for word in [
        "unauthorized access", "suspicious activity", "brute force"
    ]):
        return "HIGH"

    if event_type == "login_success":
        return "INFO"

    return "LOW"


def analyze_file(input_file):
    results = []

    with open(input_file, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                results.append({
                    "line": line_number,
                    "severity": "ERROR",
                    "message": "Invalid JSON"
                })
                continue

            if not isinstance(event, dict):
                results.append({
                    "line": line_number,
                    "severity": "ERROR",
                    "message": "Event must be a JSON object"
                })
                continue

            results.append({
                "line": line_number,
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type", "unknown"),
                "source_ip": event.get("source_ip", "unknown"),
                "severity": classify_event(event),
                "message": event.get("message", "")
            })

    return results


def main():
    project_dir = Path(__file__).resolve().parents[2]
    input_file = project_dir / "data" / "security_events.jsonl"
    output_file = project_dir / "reports" / "analysis_report.json"

    results = analyze_file(input_file)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(f"Eventos analisados: {len(results)}")
    print(f"Relatório salvo em: {output_file}")

    for result in results:
        print(
            f"[{result['severity']}] "
            f"{result.get('event_type', 'unknown')} - "
            f"{result.get('message', '')}"
        )


if __name__ == "__main__":
    main()
