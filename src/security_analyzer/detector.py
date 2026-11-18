from collections import defaultdict
from typing import Dict, List, Sequence

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