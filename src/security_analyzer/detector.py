from collections import defaultdict
from typing import Any, Dict, List, Sequence, Set

from security_analyzer.models import AuthEvent


def _sort_chronologically(events: Sequence[AuthEvent]) -> List[AuthEvent]:
    """Return events sorted by timestamp (epoch_seconds) and line_number."""
    return sorted(events, key=lambda ev: (ev.epoch_seconds, ev.line_number))


def detect_failed_ssh_logins(events: Sequence[AuthEvent]) -> List[AuthEvent]:
    """Return all failed SSH login events in chronological order.

    Includes both valid-user failures ('Failed password for root...') and
    invalid-user password failures ('Failed password for invalid user admin...').
    """
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
    """Detect source IPs attempting authentication against multiple usernames.

    Uses a sliding window of `window_seconds` across failed/invalid SSH events
    grouped by source IP.
    """
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