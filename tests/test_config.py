import json
from pathlib import Path
import tempfile
import unittest

from security_analyzer.config import AppConfig, DetectionRulesConfig, load_config
from security_analyzer.detector import DetectionEngine
from security_analyzer.parser import parse_log_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_CONFIG = PROJECT_ROOT / "config.example.json"
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "auth_sample.log"


class TestConfigurationAndRules(unittest.TestCase):
    """Verify Checkpoint 4.2: JSON config loading, validation, and rule toggles."""

    def test_load_default_and_example_config(self) -> None:
        """Verify defaults and config.example.json load cleanly into AppConfig."""
        default_cfg = load_config(None)
        example_cfg = load_config(EXAMPLE_CONFIG)

        self.assertIsInstance(default_cfg, AppConfig)
        self.assertEqual(example_cfg.detection_rules.brute_force_threshold, 5)
        self.assertEqual(example_cfg.detection_rules.multi_user_threshold, 3)
        self.assertTrue(
            example_cfg.detection_rules.is_rule_enabled("SSH_REPEATED_FAILURES")
        )

    def test_custom_json_override_changes_engine_behavior(self) -> None:
        """Verify raising thresholds and disabling a rule alters DetectionEngine output."""
        custom_payload = {
            "detection_rules": {
                "brute_force_threshold": 6,
                "enabled_rules": {
                    "SUDO_REPEATED_FAILURES": False,
                },
            }
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_path = Path(tmp_dir) / "custom_config.json"
            cfg_path.write_text(json.dumps(custom_payload), encoding="utf-8")

            app_cfg = load_config(cfg_path)
            engine = DetectionEngine.from_config(app_cfg)
            sample = parse_log_file(SAMPLE_LOG, reference_year=2026)
            alerts = engine.evaluate(sample.events)

            rule_ids = [alert.rule_id for alert in alerts]
            # Only 203.0.113.50 has >= 6 failures; SUDO_REPEATED_FAILURES is disabled
            self.assertEqual(rule_ids.count("SSH_REPEATED_FAILURES"), 1)
            self.assertEqual(rule_ids.count("SUDO_REPEATED_FAILURES"), 0)

    def test_invalid_threshold_or_malformed_json_raises_value_error(self) -> None:
        """Verify invalid thresholds, booleans, and broken JSON fail fast."""
        with self.assertRaises(ValueError):
            DetectionRulesConfig(brute_force_threshold=0)
        with self.assertRaises(ValueError):
            DetectionRulesConfig(brute_force_threshold=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            DetectionRulesConfig(brute_force_window_seconds=-5)

        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_json = Path(tmp_dir) / "broken.json"
            bad_json.write_text("{ invalid json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(bad_json)

    def test_missing_config_file_raises_file_not_found(self) -> None:
        """Verify passing a non-existent config path raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            load_config("/tmp/nonexistent_security_analyzer_config_999.json")


if __name__ == "__main__":
    unittest.main()