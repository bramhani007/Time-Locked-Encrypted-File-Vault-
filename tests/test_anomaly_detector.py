import unittest
from datetime import datetime, timedelta, timezone

from anomaly_detector import detect_anomalies


class IsolationForestDetectorTests(unittest.TestCase):
    def setUp(self):
        self.base = datetime(2026, 11, 21, 8, 0, tzinfo=timezone.utc)

    def event(self, event_id, actor, event, result, minute=0, second=0, file_id=None):
        created = self.base + timedelta(minutes=minute, seconds=second)
        return {
            "id": event_id,
            "file_id": file_id,
            "actor_user_id": None,
            "actor_key": actor,
            "ip_hash": actor.removeprefix("ip:"),
            "created_at": created.isoformat(),
            "event": event,
            "result": result,
        }

    def test_empty_logs_return_no_model(self):
        result = detect_anomalies([])
        self.assertFalse(result["model_trained"])
        self.assertEqual(result["windows"], 0)
        self.assertEqual(result["results"], [])

    def test_repeated_failed_logins_are_flagged(self):
        rows = [
            self.event(i, "ip:failed-source", "LOGIN_FAILED", "DENIED", minute=2, second=i * 20)
            for i in range(5)
        ]
        result = detect_anomalies(rows)
        self.assertFalse(result["model_trained"])
        self.assertTrue(any("failed login" in item["summary"].lower() for item in result["results"]))

    def test_excessive_downloads_are_flagged(self):
        rows = [
            self.event(i, "ip:download-source", "DOWNLOAD", "SUCCESS", minute=3, second=i * 15, file_id=f"file-{i}")
            for i in range(9)
        ]
        result = detect_anomalies(rows)
        self.assertTrue(any("download" in item["summary"].lower() for item in result["results"]))

    def test_isolation_forest_trains_with_enough_windows(self):
        rows = []
        for i in range(8):
            rows.append(self.event(i, f"user:{i + 1}", "VIEW", "SUCCESS", minute=i * 15, file_id=f"file-{i % 3}"))
        for i in range(5):
            rows.append(self.event(100 + i, "ip:repeated-source", "LOGIN_FAILED", "DENIED", minute=7, second=i * 20))
        result = detect_anomalies(rows)
        self.assertTrue(result["model_trained"])
        self.assertGreaterEqual(result["windows"], 5)
        self.assertTrue(result["results"])
        for item in result["results"]:
            self.assertGreaterEqual(item["anomaly_score"], 0.0)
            self.assertLessEqual(item["anomaly_score"], 1.0)


if __name__ == "__main__":
    unittest.main()
