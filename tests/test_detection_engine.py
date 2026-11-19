from pathlib import Path
import unittest

from security_analyzer.detector import DetectionEngine
from security_analyzer.models import SecurityAlert, Severity
from security_analyzer.parser import parse_log_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestDetectionEngine(unittest.TestCase):
    """Verify Checkpoint 4.1–4.3: DetectionEngine orchestration and severity levels."""

    @classmethod
    def setUpClass(cls) -> None:
        """Parse sample_logs/auth_sample.log once for detection engine tests."""
        cls.sample_result = parse_log_file(SAMPLE_LOG, reference_year=2026)

    def test_evaluate_empty_events_returns_empty_list(self) -> None:
        """Verify evaluating an empty event sequence produces zero alerts."""
        engine = DetectionEngine()
        self.assertEqual(engine.evaluate([]), [])

    def test_evaluate_sample_log_triggers_all_four_rule_types(self) -> None:
        """Verify DetectionEngine detects all expected incidents in sample log."""
        engine = DetectionEngine()
        alerts = engine.evaluate(self.sample_result.events)

        self.assertEqual(len(alerts), 5)
        self.assertTrue(all(isinstance(alert, SecurityAlert) for alert in alerts))

        rule_ids = [alert.rule_id for alert in alerts]
        self.assertEqual(rule_ids.count("SSH_REPEATED_FAILURES"), 2)
        self.assertEqual(rule_ids.count("SSH_MULTI_USER_PROBE"), 1)
        self.assertEqual(rule_ids.count("SSH_SUCCESS_AFTER_FAILURES"), 1)
        self.assertEqual(rule_ids.count("SUDO_REPEATED_FAILURES"), 1)

    def test_alert_hashes_are_unique_and_deterministic(self) -> None:
        """Verify repeated runs produce identical alert hashes with no collisions."""
        engine = DetectionEngine()
        run_one = engine.evaluate(self.sample_result.events)
        run_two = engine.evaluate(self.sample_result.events)

        hashes_one = [alert.alert_hash for alert in run_one]
        hashes_two = [alert.alert_hash for alert in run_two]

        self.assertEqual(hashes_one, hashes_two)
        self.assertEqual(len(set(hashes_one)), len(hashes_one))

    def test_contextual_severity_and_priority_sorting(self) -> None:
        """Verify alerts are assigned contextual severities and sorted highest first."""
        engine = DetectionEngine()
        alerts = engine.evaluate(self.sample_result.events)

        # Highest priority first: critical -> high -> medium
        ranks = [alert.severity_rank for alert in alerts]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

        # 5 password failures + accepted password for deploy -> critical
        self.assertEqual(alerts[0].rule_id, "SSH_SUCCESS_AFTER_FAILURES")
        self.assertEqual(alerts[0].severity, Severity.CRITICAL.value)

        # Repeated sudo failures attempting /usr/sbin/visudo -> high
        self.assertEqual(alerts[1].rule_id, "SUDO_REPEATED_FAILURES")
        self.assertEqual(alerts[1].severity, Severity.HIGH.value)

        # Remaining brute-force and multi-user probes -> medium
        self.assertTrue(
            all(alert.severity == Severity.MEDIUM.value for alert in alerts[2:])
        )

    def test_invalid_severity_raises_value_error(self) -> None:
        """Verify SecurityAlert rejects unknown severity labels."""
        with self.assertRaises(ValueError):
            SecurityAlert(
                rule_id="TEST",
                rule_name="Test Rule",
                severity="urgent",
                title="Invalid severity test",
                description="Should fail validation",
                source_ip=None,
                username=None,
                first_seen="2026-11-18T08:00:00+05:30",
                last_seen="2026-11-18T08:01:00+05:30",
                event_count=1,
                alert_hash="a" * 64,
            )


if __name__ == "__main__":
    unittest.main()