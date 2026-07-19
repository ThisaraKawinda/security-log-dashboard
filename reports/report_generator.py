# reports/report_generator.py
"""
Report Generator: produces a structured Markdown security summary
from the current database state and active detection alerts.

In SOC environments this is analogous to an End of Shift Report
or Daily Security Summary handed to the next analyst or manager.
"""

import sqlite3
import sys
import os
from datetime import datetime
from collections import Counter

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_PATH, EVENT_IDS
from detection.rules import run_all_rules


def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _load_events(hours_back: int = 24) -> list:
    conn = _get_connection()
    rows = conn.execute("""
        SELECT * FROM events
        WHERE timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
    """, (f"-{hours_back} hours",)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _load_all_events() -> list:
    conn = _get_connection()
    rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _get_db_stats() -> dict:
    conn = _get_connection()
    row = conn.execute("""
        SELECT COUNT(*) as total,
               MIN(timestamp) as oldest,
               MAX(timestamp) as newest
        FROM events
    """).fetchone()
    by_id = conn.execute("""
        SELECT event_id, event_name, COUNT(*) as count
        FROM events
        GROUP BY event_id
        ORDER BY count DESC
    """).fetchall()
    conn.close()
    return {
        "total":   row["total"],
        "oldest":  row["oldest"],
        "newest":  row["newest"],
        "by_id":   [dict(r) for r in by_id],
    }


def generate_report(hours_back: int = 24, output_path: str = None) -> str:
    """
    Generate a Markdown security summary report.

    Args:
        hours_back:   Time window for event statistics (default 24h).
        output_path:  If provided, write report to this file path.

    Returns:
        The report as a Markdown string.
    """
    now         = datetime.now()
    report_time = now.strftime("%Y-%m-%d %H:%M:%S")
    report_date = now.strftime("%Y-%m-%d")

    # Load data
    recent_events = _load_events(hours_back)
    all_events    = _load_all_events()
    db_stats      = _get_db_stats()
    alerts        = run_all_rules(all_events)

    # Alert counts by severity
    severity_counts = Counter(a["severity"] for a in alerts)

    # Event counts by type in window
    event_counts = Counter(
        e["event_id"] for e in recent_events
    )

    # Failed logon summary
    failed_logons = [e for e in recent_events if e["event_id"] == 4625]
    failed_by_user = Counter(
        e.get("target_user") or "unknown" for e in failed_logons
    )

    # Successful logon summary
    success_logons = [e for e in recent_events if e["event_id"] == 4624]

    # New accounts
    new_accounts = [e for e in recent_events if e["event_id"] == 4720]

    # Suspicious processes
    suspicious_procs = [e for e in recent_events if e["event_id"] == 4688
                        and e.get("command_line")
                        and ("-enc" in (e.get("command_line") or "").lower())]

    # Build report
    lines = []

    # Header
    lines += [
        f"# Security Operations Report",
        f"",
        f"**Generated:** {report_time}  ",
        f"**Period:** Last {hours_back} hours  ",
        f"**Analyst:** Automated — Security Log Analysis Dashboard  ",
        f"**Host:** {_get_hostname()}  ",
        f"",
        f"---",
        f"",
    ]

    # Executive Summary
    total_alerts  = len(alerts)
    critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)

    lines += [
        f"## Executive Summary",
        f"",
        f"During the reporting period, **{len(recent_events):,} security events** were "
        f"recorded across **{len(set(EVENT_IDS.keys()) & set(event_counts.keys()))} event categories**. "
        f"The detection engine identified **{total_alerts} alerts**, "
        f"of which **{critical_high} require immediate attention** "
        f"(CRITICAL or HIGH severity).",
        f"",
    ]

    if critical_high == 0:
        lines.append(f"> **Status: NORMAL** — No critical or high severity alerts detected.")
    elif critical_high <= 2:
        lines.append(f"> **Status: ELEVATED** — {critical_high} high-priority alert(s) require investigation.")
    else:
        lines.append(f"> **Status: HIGH ALERT** — {critical_high} critical/high alerts require immediate response.")

    lines += [f"", f"---", f""]

    # Alert Summary
    lines += [
        f"## Alert Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 CRITICAL | {severity_counts.get('CRITICAL', 0)} |",
        f"| 🟠 HIGH     | {severity_counts.get('HIGH', 0)} |",
        f"| 🟡 MEDIUM   | {severity_counts.get('MEDIUM', 0)} |",
        f"| 🔵 LOW      | {severity_counts.get('LOW', 0)} |",
        f"| **Total**   | **{total_alerts}** |",
        f"",
    ]

    # Alert details
    if alerts:
        lines += [f"### Active Alerts", f""]
        for alert in alerts:
            sev_icon = {
                "CRITICAL": "🔴", "HIGH": "🟠",
                "MEDIUM": "🟡", "LOW": "🔵"
            }.get(alert["severity"], "⚪")
            lines += [
                f"#### {sev_icon} [{alert['severity']}] {alert['rule_id']} — {alert['title']}",
                f"",
                f"- **Description:** {alert['description']}",
                f"- **Evidence events:** {alert['count']}",
                f"- **Detected at:** {alert['fired_at'][:19]}",
                f"",
            ]
    else:
        lines += [f"*No alerts fired in this reporting period.*", f""]

    lines += [f"---", f""]

    # Event Statistics
    lines += [
        f"## Event Statistics (Last {hours_back}h)",
        f"",
        f"**Total events collected:** {len(recent_events):,}  ",
        f"**Database total:** {db_stats['total']:,}  ",
        f"**Oldest record:** {db_stats['oldest']}  ",
        f"**Newest record:** {db_stats['newest']}  ",
        f"",
        f"### Breakdown by Event Type",
        f"",
        f"| Event ID | Event Name | Count |",
        f"|----------|------------|-------|",
    ]

    for event_id, count in sorted(event_counts.items()):
        name = EVENT_IDS.get(event_id, "Unknown")
        lines.append(f"| {event_id} | {name} | {count:,} |")

    lines += [f"", f"---", f""]

    # Authentication Analysis
    lines += [
        f"## Authentication Analysis",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Successful logons | {len(success_logons):,} |",
        f"| Failed logons | {len(failed_logons):,} |",
        f"| New accounts created | {len(new_accounts):,} |",
        f"| Encoded PowerShell executions | {len(suspicious_procs):,} |",
        f"",
    ]

    if failed_logons:
        lines += [
            f"### Failed Logon Breakdown",
            f"",
            f"| Account | Attempts |",
            f"|---------|----------|",
        ]
        for user, count in failed_by_user.most_common(10):
            lines.append(f"| {user} | {count} |")
        lines.append(f"")

    if new_accounts:
        lines += [f"### New Accounts Created", f""]
        for e in new_accounts:
            lines.append(
                f"- `{e.get('target_user', 'unknown')}` created by "
                f"`{e.get('subject_user', 'unknown')}` "
                f"at {str(e.get('timestamp', ''))[:19]}"
            )
        lines.append(f"")

    lines += [f"---", f""]

    # Recommendations
    lines += [f"## Recommendations", f""]

    recs = []
    if severity_counts.get("CRITICAL", 0) > 0:
        recs.append("🔴 **Immediate:** Investigate all CRITICAL alerts before end of shift. Escalate to senior analyst if unresolved.")
    if severity_counts.get("HIGH", 0) > 0:
        recs.append("🟠 **High Priority:** Review HIGH severity alerts within 2 hours. Document findings in ticketing system.")
    if len(failed_logons) > 10:
        recs.append(f"🟠 **Authentication:** {len(failed_logons)} failed logons detected. Review top offending accounts for lockout or compromise.")
    if len(new_accounts) > 0:
        recs.append(f"🟡 **Account Management:** {len(new_accounts)} new account(s) created. Verify authorization with HR/IT.")
    if len(suspicious_procs) > 0:
        recs.append(f"🟠 **Process Execution:** {len(suspicious_procs)} encoded PowerShell execution(s) detected. Review command content for malicious intent.")
    if not recs:
        recs.append("✅ No immediate actions required. Continue routine monitoring.")

    for rec in recs:
        lines.append(f"- {rec}")

    lines += [
        f"",
        f"---",
        f"",
        f"## Report Metadata",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Report generated | {report_time} |",
        f"| Detection rules version | 1.0 |",
        f"| Rules executed | 7 |",
        f"| Events analyzed | {len(all_events):,} |",
        f"| Collection method | Windows EvtQuery API |",
        f"| Storage | SQLite (WAL mode) |",
        f"",
        f"---",
        f"*Generated by Security Log Analysis Dashboard — "
        f"github.com/ThisaraKawinda/security-log-dashboard*",
    ]

    report = "\n".join(lines)

    # Write to file if path provided
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Report written to: {output_path}")

    return report


def _get_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "unknown"


if __name__ == "__main__":
    output = f"data/reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report = generate_report(hours_back=24, output_path=output)
    print()
    print(report[:2000])
    print()
    print(f"[+] Full report saved to: {output}")
