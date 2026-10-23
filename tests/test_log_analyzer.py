import unittest

from src.analyzer.log_analyzer import classify_event


class TestLogAnalyzer(unittest.TestCase):

    def test_malware_is_critical(self):
        event = {"message": "Malware detected"}
        self.assertEqual(classify_event(event), "CRITICAL")

    def test_failed_login_is_warning(self):
        event = {"event_type": "login_failed"}
        self.assertEqual(classify_event(event), "WARNING")

    def test_successful_login_is_info(self):
        event = {"event_type": "login_success"}
        self.assertEqual(classify_event(event), "INFO")

    def test_suspicious_activity_is_high(self):
        event = {"message": "Suspicious activity detected"}
        self.assertEqual(classify_event(event), "HIGH")

    def test_unknown_event_is_low(self):
        event = {"message": "Routine system check"}
        self.assertEqual(classify_event(event), "LOW")


if __name__ == "__main__":
    unittest.main()
