from datetime import datetime
import ipaddress
import re
from typing import Any, Dict, Optional

from security_analyzer.logger import get_logger


logger = get_logger(__name__)

# Matches non-printable ASCII control characters except horizontal tab (\x09)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Stage 1: Syslog envelope regex (ISO-8601 or BSD RFC 3164)
SYSLOG_HEADER_RE = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
    r"|"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")\s+"
    r"(?P<hostname>[\w.\-]+)\s+"
    r"(?P<service>[\w.\-/]+?)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# Stage 2: Service message payload regexes
SSH_FAILED_RE = re.compile(
    r"^Failed\s+(?P<auth_method>\S+)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?"
    r"(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

SSH_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<auth_method>\S+)\s+for\s+"
    r"(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

SSH_INVALID_USER_RE = re.compile(
    r"^Invalid user\s+(?P<username>\S+)\s+from\s+(?P<ip>\S+)"
    r"(?:\s+port\s+(?P<port>\d+))?"
)

SUDO_COMMAND_RE = re.compile(
    r"^(?P<username>[\w.\-]+)\s*:\s*"
    r"(?:(?P<attempts>\d+)\s+incorrect password attempts\s*;\s*)?"
    r"TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>[^;]+?)\s*;\s*"
    r"USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)

SUDO_PAM_AUTH_FAIL_RE = re.compile(
    r"^pam_unix\(sudo:auth\):\s+authentication failure;.*?"
    r"\buser=(?P<username>\S+)"
)

PAM_SESSION_RE = re.compile(
    r"^pam_unix\((?P<pam_service>[^:]+):session\):\s+"
    r"session\s+(?P<state>opened|closed)\s+for\s+user\s+"
    r"(?P<target_user>[\w.\-]+)(?:\(uid=\d+\))?"
    r"(?:\s+by\s+(?P<username>[\w.\-]*)(?:\(uid=\d+\))?)?"
)


def sanitize_log_line(raw_line: str) -> str:
    """Remove null bytes, carriage returns, and terminal control characters."""
    if not raw_line:
        return ""
    stripped = raw_line.strip("\r\n")
    return CONTROL_CHARS_RE.sub("", stripped)


def parse_syslog_header(
    raw_line: str,
    line_number: int = 1,
) -> Optional[Dict[str, Any]]:
    """Extract the syslog envelope fields from a raw log line."""
    cleaned = sanitize_log_line(raw_line)
    if not cleaned or not cleaned.strip():
        return None

    match = SYSLOG_HEADER_RE.match(cleaned)
    if match is None:
        return None

    pid_str = match.group("pid")
    return {
        "line_number": line_number,
        "timestamp_raw": match.group("timestamp"),
        "hostname": match.group("hostname"),
        "service": match.group("service"),
        "pid": int(pid_str) if pid_str is not None else None,
        "message": match.group("message"),
        "raw_line": cleaned,
    }


def normalize_timestamp(
    timestamp_raw: str,
    reference_year: Optional[int] = None,
) -> Optional[str]:
    """Normalize an ISO-8601 or BSD syslog timestamp into ISO-8601 format."""
    if not timestamp_raw:
        return None

    raw = timestamp_raw.strip()

    # Case 1: ISO-8601 timestamp (e.g. 2026-11-18T08:00:01.100000+05:30 or ...Z)
    if raw[:4].isdigit() and "T" in raw:
        iso_candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            dt = datetime.fromisoformat(iso_candidate)
            return dt.isoformat()
        except ValueError:
            return None

    # Case 2: BSD syslog timestamp (e.g. "Nov 18 08:04:00" or "Nov  5 03:12:09")
    year = reference_year if reference_year is not None else datetime.now().year
    normalized_spaces = " ".join(raw.split())
    try:
        dt = datetime.strptime(f"{year} {normalized_spaces}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return None


def validate_ip_address(ip_candidate: Optional[str]) -> Optional[str]:
    """Validate and canonicalize an IPv4 or IPv6 address string."""
    if not ip_candidate:
        return None
    try:
        return str(ipaddress.ip_address(ip_candidate.strip()))
    except ValueError:
        return None


def validate_port(port_candidate: Optional[str]) -> Optional[int]:
    """Validate that a port string represents a valid TCP/UDP port (1-65535)."""
    if port_candidate is None:
        return None
    try:
        port = int(port_candidate)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def extract_auth_fields(service: str, message: str) -> Dict[str, Any]:
    """Extract authentication event type, username, IP, and metadata from message."""
    fields: Dict[str, Any] = {
        "event_type": "other",
        "username": None,
        "source_ip": None,
        "port": None,
        "auth_method": None,
        "target_user": None,
        "command": None,
        "is_invalid_user": False,
    }

    # 1. SSH Failed Login
    match = SSH_FAILED_RE.match(message)
    if match:
        ip_addr = validate_ip_address(match.group("ip"))
        port = validate_port(match.group("port"))
        if ip_addr is None or port is None:
            fields["event_type"] = "malformed"
            return fields
        fields.update(
            {
                "event_type": "ssh_failed_login",
                "username": match.group("username"),
                "source_ip": ip_addr,
                "port": port,
                "auth_method": match.group("auth_method"),
                "is_invalid_user": match.group("invalid") is not None,
            }
        )
        return fields

    # 2. SSH Successful Login
    match = SSH_ACCEPTED_RE.match(message)
    if match:
        ip_addr = validate_ip_address(match.group("ip"))
        port = validate_port(match.group("port"))
        if ip_addr is None or port is None:
            fields["event_type"] = "malformed"
            return fields
        fields.update(
            {
                "event_type": "ssh_successful_login",
                "username": match.group("username"),
                "source_ip": ip_addr,
                "port": port,
                "auth_method": match.group("auth_method"),
            }
        )
        return fields

    # 3. SSH Invalid User probe
    match = SSH_INVALID_USER_RE.match(message)
    if match:
        ip_addr = validate_ip_address(match.group("ip"))
        raw_port = match.group("port")
        port = validate_port(raw_port) if raw_port is not None else None
        if ip_addr is None or (raw_port is not None and port is None):
            fields["event_type"] = "malformed"
            return fields
        fields.update(
            {
                "event_type": "ssh_invalid_user",
                "username": match.group("username"),
                "source_ip": ip_addr,
                "port": port,
                "is_invalid_user": True,
            }
        )
        return fields

    # 4. Sudo PAM authentication failure
    match = SUDO_PAM_AUTH_FAIL_RE.match(message)
    if match:
        fields.update(
            {
                "event_type": "sudo_auth_failure",
                "username": match.group("username"),
                "target_user": "root",
            }
        )
        return fields

    # 5. Sudo command execution or repeated incorrect password summary
    if service == "sudo":
        match = SUDO_COMMAND_RE.match(message)
        if match:
            attempts = match.group("attempts")
            fields.update(
                {
                    "event_type": (
                        "sudo_auth_failure" if attempts else "sudo_command"
                    ),
                    "username": match.group("username"),
                    "target_user": match.group("target_user"),
                    "command": match.group("command").strip(),
                }
            )
            return fields

    # 6. PAM session opened/closed
    match = PAM_SESSION_RE.match(message)
    if match:
        state = match.group("state")
        actor = match.group("username") or match.group("target_user")
        fields.update(
            {
                "event_type": f"session_{state}",
                "username": actor,
                "target_user": match.group("target_user"),
            }
        )
        return fields

    return fields


def parse_log_entry(
    raw_line: str,
    line_number: int = 1,
    reference_year: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Parse and validate a full log line, returning None for malformed lines."""
    header = parse_syslog_header(raw_line, line_number=line_number)
    if header is None:
        logger.warning(
            "Skipping malformed log line %d: invalid syslog header",
            line_number,
        )
        return None

    timestamp_iso = normalize_timestamp(
        header["timestamp_raw"],
        reference_year=reference_year,
    )
    if timestamp_iso is None:
        logger.warning(
            "Skipping malformed log line %d: invalid timestamp '%s'",
            line_number,
            header["timestamp_raw"],
        )
        return None

    fields = extract_auth_fields(header["service"], header["message"])
    if fields["event_type"] == "malformed":
        logger.warning(
            "Skipping malformed log line %d: invalid IP or port in payload '%s'",
            line_number,
            header["message"],
        )
        return None

    return {
        "line_number": header["line_number"],
        "timestamp": timestamp_iso,
        "timestamp_raw": header["timestamp_raw"],
        "hostname": header["hostname"],
        "service": header["service"],
        "pid": header["pid"],
        "event_type": fields["event_type"],
        "username": fields["username"],
        "source_ip": fields["source_ip"],
        "port": fields["port"],
        "auth_method": fields["auth_method"],
        "target_user": fields["target_user"],
        "command": fields["command"],
        "is_invalid_user": fields["is_invalid_user"],
        "message": header["message"],
        "raw_line": header["raw_line"],
    }