import json
from collections import Counter
from pathlib import Path


def detect_brute_force(events, threshold=5):
    failures = Counter()

    for event in events:
        event_type = str(event.get("event_type", "")).lower()

        if event_type in ("login_failed", "failed_login"):
            ip = event.get("source_ip")
            if ip:
                failures[ip] += 1

    return [
        {
            "alert": "POSSIBLE_BRUTE_FORCE",
            "source_ip": ip,
            "failed_attempts": count,
            "severity": "HIGH"
        }
        for ip, count in failures.items()
        if count >= threshold
    ]


def main():
    base = Path(__file__).resolve().parents[2]
    input_file = base / "data" / "security_events.jsonl"
    output_file = base / "reports" / "brute_force_report.json"

    events = []
    with input_file.open(encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
            except json.JSONDecodeError:
                continue

    alerts = detect_brute_force(events)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(alerts, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(f"Alertas de possível força bruta: {len(alerts)}")
    print(f"Relatório salvo em: {output_file}")


if __name__ == "__main__":
    main()
