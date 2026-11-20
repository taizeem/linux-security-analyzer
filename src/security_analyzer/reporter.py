from datetime import datetime, timezone
import json
from pathlib import Path
import textwrap
from typing import Any, Dict, List, Optional, Union

from security_analyzer import __app_name__, __version__
from security_analyzer.database import DatabaseManager

REPORT_SCHEMA_VERSION = "1.0"
REPORT_WIDTH = 76


def _derive_posture_status(alerts_by_severity: Dict[str, int]) -> str:
    """Return a concise executive posture banner from severity counts."""
    if alerts_by_severity.get("critical", 0) > 0:
        return "ACTION REQUIRED — Critical alert(s) detected"
    if alerts_by_severity.get("high", 0) > 0:
        return "ELEVATED — High-severity alert(s) detected"
    if (
        alerts_by_severity.get("medium", 0) > 0
        or alerts_by_severity.get("low", 0) > 0
    ):
        return "MONITOR — Medium/low-severity alert(s) detected"
    return "CLEAR — No security alerts detected"


def _format_bar(count: int, max_count: int, width: int = 16) -> str:
    """Render a proportional ASCII bar for terminal tables."""
    if max_count <= 0 or count <= 0:
        return ""
    filled = max(1, round((count / max_count) * width))
    return "#" * filled


def build_report_data(
    db: DatabaseManager,
    top_n: int = 10,
    alert_limit: int = 50,
    since: Optional[str] = None,
    until: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble a canonical security report payload from SQLite."""
    stats = db.get_statistics(top_n=top_n, since=since, until=until)
    alerts = db.query_alerts(since=since, until=until, limit=alert_limit)

    return {
        "metadata": {
            "schema_version": REPORT_SCHEMA_VERSION,
            "app_name": __app_name__,
            "app_version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "database_path": str(db.db_path),
            "period": {
                "since": since,
                "until": until,
            },
        },
        "summary": {
            "posture_status": _derive_posture_status(stats["alerts_by_severity"]),
            "total_events": stats["total_events"],
            "total_successful_logins": stats["total_successful_logins"],
            "total_failed_logins": stats["total_failed_logins"],
            "ssh_failure_rate_percent": stats["ssh_failure_rate_percent"],
            "total_invalid_users": stats["total_invalid_users"],
            "total_sudo_events": stats["total_sudo_events"],
            "unique_source_ips": stats["unique_source_ips"],
            "unique_targeted_usernames": stats["unique_targeted_usernames"],
            "successful_logins_by_method": stats["successful_logins_by_method"],
            "events_by_type": stats["events_by_type"],
            "total_alerts": stats["total_alerts"],
            "alerts_by_severity": stats["alerts_by_severity"],
        },
        "top_source_ips": stats["top_source_ips"],
        "top_targeted_usernames": stats["top_targeted_usernames"],
        "alerts": alerts,
        "scan_runs": stats["recent_scan_runs"],
    }


def render_terminal_report(
    report_data: Dict[str, Any],
    max_evidence_per_alert: int = 5,
) -> str:
    """Render a structured, wrapped, human-readable terminal security report."""
    meta = report_data["metadata"]
    summary = report_data["summary"]
    sev = summary["alerts_by_severity"]
    posture = summary.get("posture_status") or _derive_posture_status(sev)
    lines: List[str] = []

    lines.append("=" * REPORT_WIDTH)
    lines.append("LINUX SECURITY LOG ANALYZER — SECURITY REPORT")
    lines.append("=" * REPORT_WIDTH)
    lines.append(f"Status:       {posture}")
    lines.append(f"Generated At: {meta['generated_at']}")
    lines.append(f"Tool Version: {meta['app_name']} {meta['app_version']}")
    lines.append(f"Database:     {meta['database_path']}")
    period = meta.get("period", {})
    since_label = period.get("since") or "beginning"
    until_label = period.get("until") or "present"
    lines.append(f"Period:       {since_label} -> {until_label}")
    lines.append("")

    lines.append("1. AUTHENTICATION SUMMARY")
    lines.append("-" * REPORT_WIDTH)
    lines.append(f"  Total Events Analyzed:     {summary['total_events']}")
    lines.append(f"  Total Successful Logins:   {summary['total_successful_logins']}")
    lines.append(f"  Total Failed Logins:       {summary['total_failed_logins']}")
    lines.append(
        f"  SSH Failure Rate:          {summary['ssh_failure_rate_percent']:.2f}%"
    )
    lines.append(f"  Invalid Username Probes:   {summary['total_invalid_users']}")
    lines.append(f"  Sudo Events Observed:      {summary['total_sudo_events']}")
    lines.append(f"  Unique Source IPs:         {summary['unique_source_ips']}")
    lines.append(
        f"  Unique Targeted Users:     {summary['unique_targeted_usernames']}"
    )
    methods = summary.get("successful_logins_by_method", {})
    method_label = (
        ", ".join(f"{k}={v}" for k, v in methods.items()) if methods else "none"
    )
    lines.append(f"  Successful Auth Methods:   {method_label}")
    lines.append(f"  Total Alerts Generated:    {summary['total_alerts']}")
    lines.append(
        f"  Alerts by Severity:        "
        f"CRITICAL={sev['critical']}  HIGH={sev['high']}  "
        f"MEDIUM={sev['medium']}  LOW={sev['low']}"
    )
    lines.append("")

    lines.append("2. FREQUENTLY OBSERVED SOURCE IP ADDRESSES")
    lines.append("-" * REPORT_WIDTH)
    top_ips = report_data["top_source_ips"]
    if top_ips:
        max_ip_count = max(item["count"] for item in top_ips)
        for item in top_ips:
            bar = _format_bar(item["count"], max_ip_count)
            lines.append(
                f"  {item['source_ip']:<32} {item['count']:>5} event(s)  {bar}"
            )
    else:
        lines.append("  No source IP activity recorded.")
    lines.append("")

    lines.append("3. MOST TARGETED USERNAMES")
    lines.append("-" * REPORT_WIDTH)
    top_users = report_data["top_targeted_usernames"]
    if top_users:
        max_user_count = max(item["count"] for item in top_users)
        for item in top_users:
            bar = _format_bar(item["count"], max_user_count)
            lines.append(
                f"  {item['username']:<22} {item['count']:>5} attempt(s)  {bar}"
            )
    else:
        lines.append("  No failed or invalid username activity recorded.")
    lines.append("")

    lines.append("4. DETECTED ALERTS & EVIDENCE")
    lines.append("-" * REPORT_WIDTH)
    alerts = report_data["alerts"]
    if not alerts:
        lines.append("  No security alerts generated.")
    else:
        for idx, alert in enumerate(alerts, start=1):
            target = alert["source_ip"] or alert["username"] or "host"
            lines.append(
                f"  [{idx}] [{alert['severity'].upper():<8}] "
                f"{alert['rule_id']} — {alert['title']}"
            )
            lines.append(
                f"      Target: {target} | Events: {alert['event_count']} | "
                f"Window: {alert['first_seen']} -> {alert['last_seen']}"
            )
            wrapped_desc = textwrap.fill(
                alert["description"],
                width=REPORT_WIDTH,
                initial_indent="      Details: ",
                subsequent_indent="               ",
            )
            lines.append(wrapped_desc)

            evidence = alert.get("evidence", [])
            if evidence and max_evidence_per_alert > 0:
                lines.append("      Evidence:")
                shown = evidence[:max_evidence_per_alert]
                for ev in shown:
                    lines.append(
                        f"        - line {ev['line_number']} | "
                        f"{ev['timestamp']} | {ev['message']}"
                    )
                remaining = len(evidence) - len(shown)
                if remaining > 0:
                    lines.append(
                        f"        ... ({remaining} additional evidence line(s) omitted)"
                    )
            lines.append("")

    lines.append("5. SCAN EXECUTION HISTORY")
    lines.append("-" * REPORT_WIDTH)
    if report_data["scan_runs"]:
        for run in report_data["scan_runs"]:
            lines.append(
                f"  Run #{run['id']} | {run['started_at']} | "
                f"lines={run['total_lines']} valid={run['valid_events']} "
                f"malformed={run['malformed_lines']} "
                f"new_events={run['new_events_stored']} "
                f"new_alerts={run['alerts_generated']}"
            )
            lines.append(f"    Source: {run['source_path']}")
    else:
        lines.append("  No scan runs recorded.")

    lines.append("=" * REPORT_WIDTH)
    return "\n".join(lines)


def render_json_report(
    report_data: Dict[str, Any],
    indent: int = 2,
) -> str:
    """Serialize a canonical report payload into formatted JSON text."""
    return json.dumps(report_data, indent=indent, ensure_ascii=False)


def write_report_file(content: str, output_path: Union[str, Path]) -> Path:
    """Write rendered report content to disk, creating parent directories if needed."""
    destination = Path(output_path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content + "\n", encoding="utf-8")
    return destination