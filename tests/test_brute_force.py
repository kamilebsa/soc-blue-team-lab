import unittest
from src.detector.brute_force import detect_brute_force

class TestBruteForce(unittest.TestCase):
    def test_detects_five_failed_logins(self):
        events = [
            {"event_type": "login_failed", "source_ip": "192.0.2.10"}
            for _ in range(5)
        ]
        alerts = detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 5)

    def test_no_alert_below_threshold(self):
        events = [
            {"event_type": "login_failed", "source_ip": "192.0.2.10"}
            for _ in range(4)
        ]
        self.assertEqual(detect_brute_force(events), [])

    def test_ignores_successful_logins(self):
        events = [
            {"event_type": "login_success", "source_ip": "192.0.2.10"}
            for _ in range(6)
        ]
        self.assertEqual(detect_brute_force(events), [])

if __name__ == "__main__":
    unittest.main()
