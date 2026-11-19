from collections import defaultdict
from typing import Any, Dict, List, Sequence, Set, Optional

from security_analyzer.models import AuthEvent, SecurityAlert, compute_alert_hash
from security_analyzer.config import AppConfig, DetectionRulesConfig


def _sort_chronologically(events: Sequence[AuthEvent]) -> List[AuthEvent]:
    """Return events sorted by timestamp (epoch_seconds) and line_number."""
    return sorted(events, key=lambda ev: (ev.epoch_seconds, ev.line_number))


def detect_failed_ssh_logins(events: Sequence[AuthEvent]) -> List[AuthEvent]:
    """Return all failed SSH login events in chronological order."""
    failed = [
        event
        for event in events
        if event.service == "sshd" and event.event_type == "ssh_failed_login"
    ]
    return _sort_chronologically(failed)


def group_failed_ssh_by_ip(
    events: Sequence[AuthEvent],
) -> Dict[str, List[AuthEvent]]:
    """Group failed SSH login events by source IP address in chronological order."""
    grouped: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in detect_failed_ssh_logins(events):
        if event.source_ip:
            grouped[event.source_ip].append(event)
    return dict(grouped)


def detect_successful_ssh_logins(events: Sequence[AuthEvent]) -> List[AuthEvent]:
    """Return all successful SSH login events in chronological order."""
    accepted = [
        event
        for event in events
        if event.service == "sshd" and event.event_type == "ssh_successful_login"
    ]
    return _sort_chronologically(accepted)


def group_successful_ssh_by_user(
    events: Sequence[AuthEvent],
) -> Dict[str, List[AuthEvent]]:
    """Group successful SSH login events by username in chronological order."""
    grouped: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in detect_successful_ssh_logins(events):
        if event.username:
            grouped[event.username].append(event)
    return dict(grouped)


def detect_invalid_user_events(events: Sequence[AuthEvent]) -> List[AuthEvent]:
    """Return all SSH events targeting non-existent usernames in chronological order."""
    invalid_events = [
        event
        for event in events
        if event.service == "sshd" and event.is_invalid_user
    ]
    return _sort_chronologically(invalid_events)


def detect_multi_username_probes(
    events: Sequence[AuthEvent],
    min_usernames: int = 3,
    window_seconds: int = 600,
) -> List[Dict[str, Any]]:
    """Detect source IPs attempting authentication against multiple usernames."""
    if min_usernames < 1:
        raise ValueError("min_usernames must be at least 1")
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")

    candidates_by_ip: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in _sort_chronologically(events):
        if (
            event.service == "sshd"
            and event.event_type in ("ssh_failed_login", "ssh_invalid_user")
            and event.source_ip
            and event.username
        ):
            candidates_by_ip[event.source_ip].append(event)

    findings: List[Dict[str, Any]] = []

    for source_ip, ip_events in candidates_by_ip.items():
        best_window: List[AuthEvent] = []
        best_users: Set[str] = set()

        left = 0
        for right in range(len(ip_events)):
            while (
                ip_events[right].epoch_seconds - ip_events[left].epoch_seconds
                > window_seconds
            ):
                left += 1

            window_slice = ip_events[left : right + 1]
            distinct_users = {
                ev.username for ev in window_slice if ev.username is not None
            }
            if len(distinct_users) >= min_usernames and len(
                distinct_users
            ) >= len(best_users):
                best_users = distinct_users
                best_window = window_slice

        if best_window:
            invalid_users = sorted(
                {
                    ev.username
                    for ev in best_window
                    if ev.is_invalid_user and ev.username is not None
                }
            )
            findings.append(
                {
                    "source_ip": source_ip,
                    "usernames": sorted(best_users),
                    "invalid_usernames": invalid_users,
                    "unique_username_count": len(best_users),
                    "attempt_count": len(best_window),
                    "first_seen": best_window[0].timestamp,
                    "last_seen": best_window[-1].timestamp,
                    "evidence_events": tuple(best_window),
                }
            )

    return findings


def detect_repeated_ssh_failures(
    events: Sequence[AuthEvent],
    min_failures: int = 5,
    window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    """Detect source IPs with repeated failed SSH logins within a time window."""
    if min_failures < 1:
        raise ValueError("min_failures must be at least 1")
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")

    grouped_failures = group_failed_ssh_by_ip(events)
    findings: List[Dict[str, Any]] = []

    for source_ip, ip_events in grouped_failures.items():
        best_window: List[AuthEvent] = []
        left = 0

        for right in range(len(ip_events)):
            while (
                ip_events[right].epoch_seconds - ip_events[left].epoch_seconds
                > window_seconds
            ):
                left += 1

            window_slice = ip_events[left : right + 1]
            if len(window_slice) >= min_failures and len(window_slice) >= len(
                best_window
            ):
                best_window = window_slice

        if best_window:
            targeted_users = sorted(
                {ev.username for ev in best_window if ev.username is not None}
            )
            findings.append(
                {
                    "source_ip": source_ip,
                    "failure_count": len(best_window),
                    "targeted_usernames": targeted_users,
                    "first_seen": best_window[0].timestamp,
                    "last_seen": best_window[-1].timestamp,
                    "window_seconds": window_seconds,
                    "evidence_events": tuple(best_window),
                }
            )

    return findings


def detect_success_after_failures(
    events: Sequence[AuthEvent],
    min_failures: int = 3,
    window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    """Detect successful SSH logins preceded by repeated failures from the same IP."""
    if min_failures < 1:
        raise ValueError("min_failures must be at least 1")
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")

    failures_by_ip = group_failed_ssh_by_ip(events)
    successful_logins = detect_successful_ssh_logins(events)
    findings: List[Dict[str, Any]] = []

    for success in successful_logins:
        if not success.source_ip:
            continue

        ip_failures = failures_by_ip.get(success.source_ip, [])
        if not ip_failures:
            continue

        preceding_failures = [
            fail
            for fail in ip_failures
            if (fail.epoch_seconds, fail.line_number)
            < (success.epoch_seconds, success.line_number)
            and (success.epoch_seconds - fail.epoch_seconds) <= window_seconds
        ]

        if len(preceding_failures) >= min_failures:
            evidence = tuple(preceding_failures) + (success,)
            findings.append(
                {
                    "source_ip": success.source_ip,
                    "username": success.username,
                    "auth_method": success.auth_method,
                    "preceding_failure_count": len(preceding_failures),
                    "first_failure_seen": preceding_failures[0].timestamp,
                    "success_timestamp": success.timestamp,
                    "window_seconds": window_seconds,
                    "evidence_events": evidence,
                }
            )

    return findings


def detect_sudo_events(events: Sequence[AuthEvent]) -> List[AuthEvent]:
    """Return all sudo command execution and sudo auth failure events in order."""
    sudo_events = [
        event
        for event in events
        if event.service == "sudo"
        and event.event_type in ("sudo_command", "sudo_auth_failure")
    ]
    return _sort_chronologically(sudo_events)


def detect_repeated_sudo_failures(
    events: Sequence[AuthEvent],
    min_failures: int = 3,
    window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    """Detect users with repeated failed sudo authentication attempts in a window."""
    if min_failures < 1:
        raise ValueError("min_failures must be at least 1")
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")

    failures_by_user: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in detect_sudo_events(events):
        if event.event_type == "sudo_auth_failure" and event.username:
            failures_by_user[event.username].append(event)

    findings: List[Dict[str, Any]] = []

    for username, user_events in failures_by_user.items():
        best_window: List[AuthEvent] = []
        left = 0

        for right in range(len(user_events)):
            while (
                user_events[right].epoch_seconds - user_events[left].epoch_seconds
                > window_seconds
            ):
                left += 1

            window_slice = user_events[left : right + 1]
            if len(window_slice) >= min_failures and len(window_slice) >= len(
                best_window
            ):
                best_window = window_slice

        if best_window:
            commands = sorted(
                {ev.command for ev in best_window if ev.command is not None}
            )
            target_users = sorted(
                {
                    ev.target_user
                    for ev in best_window
                    if ev.target_user is not None
                }
            )
            findings.append(
                {
                    "username": username,
                    "failure_count": len(best_window),
                    "target_users": target_users,
                    "attempted_commands": commands,
                    "first_seen": best_window[0].timestamp,
                    "last_seen": best_window[-1].timestamp,
                    "window_seconds": window_seconds,
                    "evidence_events": tuple(best_window),
                }
            )

    return findings


class DetectionEngine:
    """Orchestrates configurable authentication detection rules into SecurityAlerts."""

    def __init__(
        self,
        rules_config: Optional[DetectionRulesConfig] = None,
        brute_force_threshold: Optional[int] = None,
        brute_force_window_seconds: Optional[int] = None,
        multi_user_threshold: Optional[int] = None,
        multi_user_window_seconds: Optional[int] = None,
        success_after_failure_threshold: Optional[int] = None,
        success_after_failure_window_seconds: Optional[int] = None,
        sudo_failure_threshold: Optional[int] = None,
        sudo_failure_window_seconds: Optional[int] = None,
    ) -> None:
        base = rules_config or DetectionRulesConfig()
        self.rules_config = DetectionRulesConfig(
            brute_force_threshold=(
                brute_force_threshold
                if brute_force_threshold is not None
                else base.brute_force_threshold
            ),
            brute_force_window_seconds=(
                brute_force_window_seconds
                if brute_force_window_seconds is not None
                else base.brute_force_window_seconds
            ),
            multi_user_threshold=(
                multi_user_threshold
                if multi_user_threshold is not None
                else base.multi_user_threshold
            ),
            multi_user_window_seconds=(
                multi_user_window_seconds
                if multi_user_window_seconds is not None
                else base.multi_user_window_seconds
            ),
            success_after_failure_threshold=(
                success_after_failure_threshold
                if success_after_failure_threshold is not None
                else base.success_after_failure_threshold
            ),
            success_after_failure_window_seconds=(
                success_after_failure_window_seconds
                if success_after_failure_window_seconds is not None
                else base.success_after_failure_window_seconds
            ),
            sudo_failure_threshold=(
                sudo_failure_threshold
                if sudo_failure_threshold is not None
                else base.sudo_failure_threshold
            ),
            sudo_failure_window_seconds=(
                sudo_failure_window_seconds
                if sudo_failure_window_seconds is not None
                else base.sudo_failure_window_seconds
            ),
            enabled_rules=dict(base.enabled_rules),
        )

    @classmethod
    def from_config(cls, app_config: AppConfig) -> "DetectionEngine":
        """Construct a DetectionEngine from a validated AppConfig."""
        return cls(rules_config=app_config.detection_rules)

    def evaluate(self, events: Sequence[AuthEvent]) -> List[SecurityAlert]:
        """Run all enabled detection rules against parsed events and return alerts."""
        if not events:
            return []

        alerts: List[SecurityAlert] = []
        if self.rules_config.is_rule_enabled("SSH_REPEATED_FAILURES"):
            alerts.extend(self._run_repeated_ssh_failure_rule(events))
        if self.rules_config.is_rule_enabled("SSH_MULTI_USER_PROBE"):
            alerts.extend(self._run_multi_username_probe_rule(events))
        if self.rules_config.is_rule_enabled("SSH_SUCCESS_AFTER_FAILURES"):
            alerts.extend(self._run_success_after_failures_rule(events))
        if self.rules_config.is_rule_enabled("SUDO_REPEATED_FAILURES"):
            alerts.extend(self._run_repeated_sudo_failure_rule(events))
        return alerts

    def _run_repeated_ssh_failure_rule(
        self, events: Sequence[AuthEvent]
    ) -> List[SecurityAlert]:
        cfg = self.rules_config
        findings = detect_repeated_ssh_failures(
            events,
            min_failures=cfg.brute_force_threshold,
            window_seconds=cfg.brute_force_window_seconds,
        )
        alerts: List[SecurityAlert] = []
        for finding in findings:
            users_label = ", ".join(finding["targeted_usernames"]) or "unknown"
            alerts.append(
                SecurityAlert(
                    rule_id="SSH_REPEATED_FAILURES",
                    rule_name="Repeated SSH Authentication Failures",
                    severity="medium",
                    title=f"Repeated SSH failures from {finding['source_ip']}",
                    description=(
                        f"Observed {finding['failure_count']} failed SSH login "
                        f"attempts from {finding['source_ip']} within "
                        f"{cfg.brute_force_window_seconds}s targeting: {users_label}. "
                        "Evidence establishes repeated failed authentication; verify "
                        "whether this is automated password guessing or a misconfigured client."
                    ),
                    source_ip=finding["source_ip"],
                    username=None,
                    first_seen=finding["first_seen"],
                    last_seen=finding["last_seen"],
                    event_count=finding["failure_count"],
                    alert_hash=compute_alert_hash(
                        "SSH_REPEATED_FAILURES",
                        finding["source_ip"],
                        None,
                        finding["first_seen"],
                        finding["last_seen"],
                    ),
                )
            )
        return alerts

    def _run_multi_username_probe_rule(
        self, events: Sequence[AuthEvent]
    ) -> List[SecurityAlert]:
        cfg = self.rules_config
        findings = detect_multi_username_probes(
            events,
            min_usernames=cfg.multi_user_threshold,
            window_seconds=cfg.multi_user_window_seconds,
        )
        alerts: List[SecurityAlert] = []
        for finding in findings:
            users_label = ", ".join(finding["usernames"])
            alerts.append(
                SecurityAlert(
                    rule_id="SSH_MULTI_USER_PROBE",
                    rule_name="Multi-Username SSH Enumeration",
                    severity="medium",
                    title=f"Multi-username SSH probe from {finding['source_ip']}",
                    description=(
                        f"Observed {finding['source_ip']} attempting SSH logins "
                        f"across {finding['unique_username_count']} distinct usernames "
                        f"({users_label}) within {cfg.multi_user_window_seconds}s. "
                        "Evidence is consistent with username enumeration or scanning."
                    ),
                    source_ip=finding["source_ip"],
                    username=None,
                    first_seen=finding["first_seen"],
                    last_seen=finding["last_seen"],
                    event_count=finding["attempt_count"],
                    alert_hash=compute_alert_hash(
                        "SSH_MULTI_USER_PROBE",
                        finding["source_ip"],
                        None,
                        finding["first_seen"],
                        finding["last_seen"],
                    ),
                )
            )
        return alerts

    def _run_success_after_failures_rule(
        self, events: Sequence[AuthEvent]
    ) -> List[SecurityAlert]:
        cfg = self.rules_config
        findings = detect_success_after_failures(
            events,
            min_failures=cfg.success_after_failure_threshold,
            window_seconds=cfg.success_after_failure_window_seconds,
        )
        alerts: List[SecurityAlert] = []
        for finding in findings:
            alerts.append(
                SecurityAlert(
                    rule_id="SSH_SUCCESS_AFTER_FAILURES",
                    rule_name="Successful SSH Login After Repeated Failures",
                    severity="high",
                    title=(
                        f"SSH login for {finding['username']} after "
                        f"{finding['preceding_failure_count']} failures from "
                        f"{finding['source_ip']}"
                    ),
                    description=(
                        f"Account '{finding['username']}' authenticated via "
                        f"{finding['auth_method']} from {finding['source_ip']} after "
                        f"{finding['preceding_failure_count']} failed attempts within "
                        f"{cfg.success_after_failure_window_seconds}s. "
                        "Evidence warrants immediate review to distinguish legitimate "
                        "password typos from successful credential guessing."
                    ),
                    source_ip=finding["source_ip"],
                    username=finding["username"],
                    first_seen=finding["first_failure_seen"],
                    last_seen=finding["success_timestamp"],
                    event_count=finding["preceding_failure_count"] + 1,
                    alert_hash=compute_alert_hash(
                        "SSH_SUCCESS_AFTER_FAILURES",
                        finding["source_ip"],
                        finding["username"],
                        finding["first_failure_seen"],
                        finding["success_timestamp"],
                    ),
                )
            )
        return alerts

    def _run_repeated_sudo_failure_rule(
        self, events: Sequence[AuthEvent]
    ) -> List[SecurityAlert]:
        cfg = self.rules_config
        findings = detect_repeated_sudo_failures(
            events,
            min_failures=cfg.sudo_failure_threshold,
            window_seconds=cfg.sudo_failure_window_seconds,
        )
        alerts: List[SecurityAlert] = []
        for finding in findings:
            cmds = ", ".join(finding["attempted_commands"]) or "not recorded"
            alerts.append(
                SecurityAlert(
                    rule_id="SUDO_REPEATED_FAILURES",
                    rule_name="Repeated Sudo Authentication Failures",
                    severity="medium",
                    title=f"Repeated sudo failures for user {finding['username']}",
                    description=(
                        f"User '{finding['username']}' generated "
                        f"{finding['failure_count']} failed sudo authentication "
                        f"records within {cfg.sudo_failure_window_seconds}s "
                        f"(attempted commands: {cmds}). Evidence establishes repeated "
                        "failed privilege escalation checks."
                    ),
                    source_ip=None,
                    username=finding["username"],
                    first_seen=finding["first_seen"],
                    last_seen=finding["last_seen"],
                    event_count=finding["failure_count"],
                    alert_hash=compute_alert_hash(
                        "SUDO_REPEATED_FAILURES",
                        None,
                        finding["username"],
                        finding["first_seen"],
                        finding["last_seen"],
                    ),
                )
            )
        return alerts