from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
from typing import Any, Dict, Optional, Tuple


def compute_event_hash(
    timestamp: str,
    hostname: str,
    service: str,
    pid: Optional[int],
    message: str,
) -> str:
    """Compute a deterministic SHA-256 fingerprint for deduplicating events."""
    pid_part = str(pid) if pid is not None else ""
    canonical = f"{timestamp}|{hostname}|{service}|{pid_part}|{message}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_alert_hash(
    rule_id: str,
    source_ip: Optional[str],
    username: Optional[str],
    first_seen: str,
    last_seen: str,
) -> str:
    """Compute a deterministic SHA-256 fingerprint for deduplicating alerts."""
    canonical = (
        f"{rule_id}|{source_ip or ''}|{username or ''}|{first_seen}|{last_seen}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthEvent:
    """Immutable representation of a single parsed Linux authentication event."""

    line_number: int
    timestamp: str
    timestamp_raw: str
    hostname: str
    service: str
    pid: Optional[int]
    event_type: str
    username: Optional[str]
    source_ip: Optional[str]
    port: Optional[int]
    auth_method: Optional[str]
    target_user: Optional[str]
    command: Optional[str]
    is_invalid_user: bool
    message: str
    raw_line: str
    event_hash: str

    @classmethod
    def from_parsed_dict(cls, data: Dict[str, Any]) -> "AuthEvent":
        """Construct an AuthEvent from a validated parser dictionary."""
        event_hash = data.get("event_hash") or compute_event_hash(
            timestamp=data["timestamp"],
            hostname=data["hostname"],
            service=data["service"],
            pid=data.get("pid"),
            message=data["message"],
        )
        return cls(
            line_number=int(data["line_number"]),
            timestamp=str(data["timestamp"]),
            timestamp_raw=str(data["timestamp_raw"]),
            hostname=str(data["hostname"]),
            service=str(data["service"]),
            pid=data.get("pid"),
            event_type=str(data["event_type"]),
            username=data.get("username"),
            source_ip=data.get("source_ip"),
            port=data.get("port"),
            auth_method=data.get("auth_method"),
            target_user=data.get("target_user"),
            command=data.get("command"),
            is_invalid_user=bool(data.get("is_invalid_user", False)),
            message=str(data["message"]),
            raw_line=str(data["raw_line"]),
            event_hash=event_hash,
        )

    @property
    def epoch_seconds(self) -> float:
        """Return the event timestamp as POSIX epoch seconds for window math."""
        dt = datetime.fromisoformat(self.timestamp)
        return dt.timestamp()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the event to a plain dictionary for JSON or SQLite."""
        return asdict(self)


@dataclass(frozen=True)
class SecurityAlert:
    """Immutable security alert produced by the DetectionEngine."""

    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    source_ip: Optional[str]
    username: Optional[str]
    first_seen: str
    last_seen: str
    event_count: int
    alert_hash: str
    evidence: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the alert to a plain dictionary for JSON or SQLite."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "username": self.username,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "alert_hash": self.alert_hash,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class ParseResult:
    """Summary and structured events produced by parsing a log file."""

    source_path: str
    events: Tuple[AuthEvent, ...]
    total_lines: int
    valid_events: int
    malformed_lines: int

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the parse summary and events to a plain dictionary."""
        return {
            "source_path": self.source_path,
            "total_lines": self.total_lines,
            "valid_events": self.valid_events,
            "malformed_lines": self.malformed_lines,
            "events": [event.to_dict() for event in self.events],
        }