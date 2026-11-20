import json
from pathlib import Path
import unittest

from security_analyzer.detector import DetectionEngine
from security_analyzer.models import SecurityAlert, Severity
from security_analyzer.parser import parse_log_file, parse_log_line
from security_analyzer.config import DetectionRulesConfig


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestDetectionEngine(unittest.TestCase):
    """Verify Checkpoint 4.1–4.4: orchestration, severity levels, and evidence."""

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

        ranks = [alert.severity_rank for alert in alerts]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

        self.assertEqual(alerts[0].rule_id, "SSH_SUCCESS_AFTER_FAILURES")
        self.assertEqual(alerts[0].severity, Severity.CRITICAL.value)

        self.assertEqual(alerts[1].rule_id, "SUDO_REPEATED_FAILURES")
        self.assertEqual(alerts[1].severity, Severity.HIGH.value)

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

    def test_all_generated_alerts_include_structured_json_serializable_evidence(
        self,
    ) -> None:
        """Verify every alert attaches evidence with line_number, timestamp, and hash."""
        engine = DetectionEngine()
        alerts = engine.evaluate(self.sample_result.events)

        for alert in alerts:
            self.assertGreater(len(alert.evidence), 0)
            for item in alert.evidence:
                self.assertIn("line_number", item)
                self.assertIn("timestamp", item)
                self.assertIn("event_hash", item)
                self.assertIn("message", item)
            # Confirm full alert + evidence serializes cleanly to JSON
            encoded = json.dumps(alert.to_dict())
            self.assertIn(alert.alert_hash, encoded)

        # Verify sudo alert evidence includes the attempted visudo command
        sudo_alert = next(
            a for a in alerts if a.rule_id == "SUDO_REPEATED_FAILURES"
        )
        commands = [ev.get("command") for ev in sudo_alert.evidence if ev.get("command")]
        self.assertIn("/usr/sbin/visudo", commands)

    def test_evidence_truncation_preserves_head_and_tail_of_large_burst(self) -> None:
        """Verify large event bursts cap evidence while keeping first and last events."""
        lines = [
            f"2026-11-18T08:00:{sec:02d}+05:30 host sshd[{sec}]: "
            f"Failed password for root from 203.0.113.99 port {40000 + sec} ssh2"
            for sec in range(1, 15)
        ]
        events = [
            ev
            for idx, line in enumerate(lines, start=1)
            if (ev := parse_log_line(line, line_number=idx)) is not None
        ]

        engine = DetectionEngine(brute_force_threshold=5, max_evidence_events=6)
        alerts = engine.evaluate(events)
        brute_alert = next(
            a for a in alerts if a.rule_id == "SSH_REPEATED_FAILURES"
        )

        self.assertEqual(brute_alert.event_count, 14)
        self.assertEqual(len(brute_alert.evidence), 6)
        # First 3 lines (1, 2, 3) and last 3 lines (12, 13, 14) preserved
        self.assertEqual(
            [item["line_number"] for item in brute_alert.evidence],
            [1, 2, 3, 12, 13, 14],
        )

    def test_sliding_window_exact_boundary_inclusive_vs_exclusive(self) -> None:
        """Verify failures spanning exactly window_seconds trigger, while +1s does not."""
        # 5 failures spanning exactly 300 seconds (08:00:00 -> 08:05:00)
        inclusive_lines = [
            "2026-11-18T08:00:00+05:30 host sshd[1]: Failed password for root from 203.0.113.10 port 41001 ssh2",
            "2026-11-18T08:01:00+05:30 host sshd[2]: Failed password for root from 203.0.113.10 port 41002 ssh2",
            "2026-11-18T08:02:00+05:30 host sshd[3]: Failed password for root from 203.0.113.10 port 41003 ssh2",
            "2026-11-18T08:03:00+05:30 host sshd[4]: Failed password for root from 203.0.113.10 port 41004 ssh2",
            "2026-11-18T08:05:00+05:30 host sshd[5]: Failed password for root from 203.0.113.10 port 41005 ssh2",
        ]
        # 5 failures spanning 301 seconds (08:00:00 -> 08:05:01)
        exclusive_lines = inclusive_lines[:-1] + [
            "2026-11-18T08:05:01+05:30 host sshd[5]: Failed password for root from 203.0.113.10 port 41005 ssh2",
        ]

        inclusive_events = [
            ev for i, line in enumerate(inclusive_lines, 1) if (ev := parse_log_line(line, i)) is not None
        ]
        exclusive_events = [
            ev for i, line in enumerate(exclusive_lines, 1) if (ev := parse_log_line(line, i)) is not None
        ]

        engine = DetectionEngine(brute_force_threshold=5, brute_force_window_seconds=300)
        self.assertEqual(len(engine.evaluate(inclusive_events)), 1)
        self.assertEqual(engine.evaluate(exclusive_events), [])

    def test_disabling_all_rules_returns_zero_alerts(self) -> None:
        """Verify disabling all four rules produces an empty alert list."""
        disabled_cfg = DetectionRulesConfig(
            enabled_rules={
                "SSH_REPEATED_FAILURES": False,
                "SSH_MULTI_USER_PROBE": False,
                "SSH_SUCCESS_AFTER_FAILURES": False,
                "SUDO_REPEATED_FAILURES": False,
            }
        )
        engine = DetectionEngine(rules_config=disabled_cfg)
        self.assertEqual(engine.evaluate(self.sample_result.events), [])


if __name__ == "__main__":
    unittest.main()