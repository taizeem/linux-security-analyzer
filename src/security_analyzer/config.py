from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, Optional, Union


DEFAULT_ENABLED_RULES: Dict[str, bool] = {
    "SSH_REPEATED_FAILURES": True,
    "SSH_MULTI_USER_PROBE": True,
    "SSH_SUCCESS_AFTER_FAILURES": True,
    "SUDO_REPEATED_FAILURES": True,
}


@dataclass(frozen=True)
class DetectionRulesConfig:
    """Validated thresholds, time windows, and toggle switches for detection rules."""

    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300
    multi_user_threshold: int = 3
    multi_user_window_seconds: int = 600
    success_after_failure_threshold: int = 3
    success_after_failure_window_seconds: int = 300
    sudo_failure_threshold: int = 3
    sudo_failure_window_seconds: int = 300
    enabled_rules: Dict[str, bool] = field(
        default_factory=lambda: dict(DEFAULT_ENABLED_RULES)
    )

    def __post_init__(self) -> None:
        thresholds = {
            "brute_force_threshold": self.brute_force_threshold,
            "multi_user_threshold": self.multi_user_threshold,
            "success_after_failure_threshold": self.success_after_failure_threshold,
            "sudo_failure_threshold": self.sudo_failure_threshold,
        }
        for name, value in thresholds.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be an integer >= 1 (got {value!r})")

        windows = {
            "brute_force_window_seconds": self.brute_force_window_seconds,
            "multi_user_window_seconds": self.multi_user_window_seconds,
            "success_after_failure_window_seconds": (
                self.success_after_failure_window_seconds
            ),
            "sudo_failure_window_seconds": self.sudo_failure_window_seconds,
        }
        for name, value in windows.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be an integer >= 0 (got {value!r})")

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Return True if a rule is enabled (defaults to True for known rules)."""
        return bool(self.enabled_rules.get(rule_id, True))


@dataclass(frozen=True)
class AppConfig:
    """Top-level application configuration."""

    default_log_path: str = "/var/log/auth.log"
    fallback_sample_path: str = "sample_logs/auth_sample.log"
    log_encoding: str = "utf-8"
    db_path: str = "data/security_events.db"
    report_output_dir: str = "reports"
    report_retention_days: int = 30
    app_log_path: str = "data/analyzer.log"
    log_level: str = "INFO"
    detection_rules: DetectionRulesConfig = field(
        default_factory=DetectionRulesConfig
    )


def _build_detection_rules_config(raw_rules: Dict[str, Any]) -> DetectionRulesConfig:
    merged_enabled = dict(DEFAULT_ENABLED_RULES)
    raw_enabled = raw_rules.get("enabled_rules")
    if isinstance(raw_enabled, dict):
        for rule_id, flag in raw_enabled.items():
            if not isinstance(flag, bool):
                raise ValueError(
                    f"enabled_rules['{rule_id}'] must be a boolean (got {flag!r})"
                )
            merged_enabled[str(rule_id)] = flag

    return DetectionRulesConfig(
        brute_force_threshold=raw_rules.get("brute_force_threshold", 5),
        brute_force_window_seconds=raw_rules.get("brute_force_window_seconds", 300),
        multi_user_threshold=raw_rules.get("multi_user_threshold", 3),
        multi_user_window_seconds=raw_rules.get("multi_user_window_seconds", 600),
        success_after_failure_threshold=raw_rules.get(
            "success_after_failure_threshold", 3
        ),
        success_after_failure_window_seconds=raw_rules.get(
            "success_after_failure_window_seconds", 300
        ),
        sudo_failure_threshold=raw_rules.get("sudo_failure_threshold", 3),
        sudo_failure_window_seconds=raw_rules.get(
            "sudo_failure_window_seconds", 300
        ),
        enabled_rules=merged_enabled,
    )


def load_config(config_path: Optional[Union[str, Path]] = None) -> AppConfig:
    """Load and validate application configuration from a JSON file.

    If `config_path` is None, returns default AppConfig values.
    """
    if config_path is None:
        return AppConfig()

    path = Path(config_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    try:
        with open(path, mode="r", encoding="utf-8") as handle:
            raw_data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in configuration file {path}: {exc}") from exc

    if not isinstance(raw_data, dict):
        raise ValueError("Configuration root must be a JSON object")

    log_source = raw_data.get("log_source", {})
    database = raw_data.get("database", {})
    reporting = raw_data.get("reporting", {})
    logging_cfg = raw_data.get("logging", {})
    raw_rules = raw_data.get("detection_rules", {})

    detection_rules = _build_detection_rules_config(
        raw_rules if isinstance(raw_rules, dict) else {}
    )

    return AppConfig(
        default_log_path=str(log_source.get("default_path", "/var/log/auth.log")),
        fallback_sample_path=str(
            log_source.get("fallback_sample_path", "sample_logs/auth_sample.log")
        ),
        log_encoding=str(log_source.get("encoding", "utf-8")),
        db_path=str(database.get("db_path", "data/security_events.db")),
        report_output_dir=str(reporting.get("output_dir", "reports")),
        report_retention_days=int(reporting.get("retention_days", 30)),
        app_log_path=str(logging_cfg.get("app_log_path", "data/analyzer.log")),
        log_level=str(logging_cfg.get("level", "INFO")).upper(),
        detection_rules=detection_rules,
    )