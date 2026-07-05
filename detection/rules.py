# detection/rules.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
from collections import defaultdict
from config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECS,
    UNUSUAL_HOUR_START,
    UNUSUAL_HOUR_END,
    SPRAY_ACCOUNT_THRESHOLD,
    SUSPICIOUS_CMDLINE_PATTERNS,
    SUSPICIOUS_PROCESSES,
)

# System and service accounts excluded from behavioral detections
SYSTEM_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "DWM-1", "DWM-2", "DWM-3",
    "UMFD-0", "UMFD-1", "UMFD-2", "UMFD-3",
    "ANONYMOUS LOGON",
}

# Service accounts (end in common suffixes or are known services)
SERVICE_ACCOUNT_SUFFIXES = ("service", "svc", "daemon")


def _is_system_account(username):
    if not username:
        return True
    if username in SYSTEM_ACCOUNTS:
        return True
    if username.endswith("$"):
        return True
    lower = username.lower()
    if any(lower.endswith(s) for s in SERVICE_ACCOUNT_SUFFIXES):
        return True
    return False


def make_alert(rule_id, severity, title, description, evidence):
    return {
        "rule_id":     rule_id,
        "severity":    severity,
        "title":       title,
        "description": description,
        "evidence":    evidence,
        "fired_at":    datetime.now().isoformat(),
        "count":       len(evidence),
    }


def _parse_ts(ts):
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return datetime.min
    return datetime.min


def detect_brute_force(events):
    alerts = []
    failed = [e for e in events if e["event_id"] == 4625]

    by_user = defaultdict(list)
    for e in failed:
        user = e.get("target_user") or "unknown"
        by_user[user].append(e)

    for user, user_events in by_user.items():
        user_events.sort(key=lambda e: _parse_ts(e["timestamp"]))
        for i, start_event in enumerate(user_events):
            window_start  = _parse_ts(start_event["timestamp"])
            window_end    = window_start + timedelta(seconds=BRUTE_FORCE_WINDOW_SECS)
            window_events = [
                e for e in user_events[i:]
                if _parse_ts(e["timestamp"]) <= window_end
            ]
            if len(window_events) >= BRUTE_FORCE_THRESHOLD:
                alerts.append(make_alert(
                    rule_id="BF-001",
                    severity="HIGH",
                    title=f"Brute Force Detected - {user}",
                    description=(
                        f"{len(window_events)} failed logon attempts for "
                        f"'{user}' within "
                        f"{BRUTE_FORCE_WINDOW_SECS // 60} minutes "
                        f"(threshold: {BRUTE_FORCE_THRESHOLD})."
                    ),
                    evidence=window_events,
                ))
                break
    return alerts


def detect_brute_force_success(events):
    alerts = []
    failed  = [e for e in events if e["event_id"] == 4625]
    success = [e for e in events if e["event_id"] == 4624]

    users_with_failures = defaultdict(list)
    for e in failed:
        user = e.get("target_user") or "unknown"
        users_with_failures[user].append(_parse_ts(e["timestamp"]))

    for user, fail_times in users_with_failures.items():
        if len(fail_times) < BRUTE_FORCE_THRESHOLD:
            continue
        last_failure = max(fail_times)
        user_successes = [
            e for e in success
            if (e.get("target_user") == user
                and _parse_ts(e["timestamp"]) > last_failure)
        ]
        if user_successes:
            alerts.append(make_alert(
                rule_id="BF-002",
                severity="CRITICAL",
                title=f"Successful Login After Brute Force - {user}",
                description=(
                    f"Account '{user}' had {len(fail_times)} failed logon "
                    f"attempts followed by a successful logon at "
                    f"{_parse_ts(user_successes[0]['timestamp']).strftime('%H:%M:%S')}. "
                    f"Possible credential compromise."
                ),
                evidence=user_successes[:3],
            ))
    return alerts


def detect_password_spray(events):
    alerts = []
    failed = [e for e in events if e["event_id"] == 4625]

    by_ip = defaultdict(set)
    for e in failed:
        ip   = e.get("source_ip") or "unknown"
        user = e.get("target_user") or "unknown"
        by_ip[ip].add(user)

    for ip, targeted_users in by_ip.items():
        if len(targeted_users) >= SPRAY_ACCOUNT_THRESHOLD:
            evidence = [
                e for e in failed
                if (e.get("source_ip") or "unknown") == ip
            ]
            alerts.append(make_alert(
                rule_id="BF-003",
                severity="HIGH",
                title=f"Password Spray Detected from {ip}",
                description=(
                    f"Source IP '{ip}' attempted logons against "
                    f"{len(targeted_users)} distinct accounts: "
                    f"{', '.join(list(targeted_users)[:5])}. "
                    f"Consistent with password spray technique."
                ),
                evidence=evidence,
            ))
    return alerts


def detect_new_admin_account(events):
    alerts = []
    created   = [e for e in events if e["event_id"] == 4720]
    escalated = [e for e in events if e["event_id"] in (4728, 4732, 4756)]

    for create_event in created:
        new_user  = create_event.get("target_user") or ""
        create_ts = _parse_ts(create_event["timestamp"])

        matching_escalation = [
            e for e in escalated
            if (
                (e.get("target_user") or "").endswith(new_user)
                and abs((_parse_ts(e["timestamp"]) - create_ts).total_seconds()) <= 600
            )
        ]

        if matching_escalation:
            group = matching_escalation[0].get("group_name", "unknown group")
            alerts.append(make_alert(
                rule_id="ACC-001",
                severity="CRITICAL",
                title=f"New Admin Account Created - {new_user}",
                description=(
                    f"Account '{new_user}' was created at "
                    f"{create_ts.strftime('%H:%M:%S')} and added to "
                    f"'{group}' within minutes. "
                    f"Possible backdoor account creation."
                ),
                evidence=[create_event] + matching_escalation,
            ))
        else:
            alerts.append(make_alert(
                rule_id="ACC-002",
                severity="MEDIUM",
                title=f"New User Account Created - {new_user}",
                description=(
                    f"A new user account '{new_user}' was created by "
                    f"'{create_event.get('subject_user')}' at "
                    f"{create_ts.strftime('%H:%M:%S')}. "
                    f"Verify this is an authorized account creation."
                ),
                evidence=[create_event],
            ))
    return alerts


def detect_suspicious_process(events):
    alerts = []
    proc_events = [e for e in events if e["event_id"] == 4688]

    for e in proc_events:
        cmdline  = (e.get("command_line") or "").lower()
        procname = (e.get("process_name") or "").lower()

        # Check known malicious process names
        for suspicious in SUSPICIOUS_PROCESSES:
            if suspicious.lower() in procname:
                alerts.append(make_alert(
                    rule_id="PROC-001",
                    severity="CRITICAL",
                    title=f"Known Attack Tool Detected - {suspicious}",
                    description=(
                        f"Known attack tool '{suspicious}' was executed by "
                        f"'{e.get('subject_user')}' at "
                        f"{_parse_ts(e['timestamp']).strftime('%H:%M:%S')}."
                    ),
                    evidence=[e],
                ))
                break

        # HIGH confidence: encoded PowerShell (-enc flag)
        if "-enc" in cmdline or "-encodedcommand" in cmdline:
            alerts.append(make_alert(
                rule_id="PROC-002",
                severity="HIGH",
                title=f"Encoded PowerShell Detected - {e.get('subject_user')}",
                description=(
                    f"PowerShell executed with encoded command (-enc) by "
                    f"'{e.get('subject_user')}' at "
                    f"{_parse_ts(e['timestamp']).strftime('%H:%M:%S')}. "
                    f"Encoded commands are commonly used to obfuscate malicious payloads."
                ),
                evidence=[e],
            ))
            continue

        # MEDIUM confidence: multiple suspicious indicators together
        high_risk_patterns = [
            "iex", "invoke-expression", "downloadstring",
            "webclient", "mimikatz", "whoami /all"
        ]
        medium_risk_patterns = ["hidden", "bypass", "net user"]

        high_hits   = [p for p in high_risk_patterns if p in cmdline]
        medium_hits = [p for p in medium_risk_patterns if p in cmdline]

        # Only fire if: one high-risk pattern OR two+ medium-risk patterns
        if high_hits or len(medium_hits) >= 2:
            matched = high_hits + medium_hits
            alerts.append(make_alert(
                rule_id="PROC-002",
                severity="MEDIUM",
                title=f"Suspicious Command Line - {e.get('subject_user')}",
                description=(
                    f"Suspicious pattern(s) detected: "
                    f"{', '.join(matched)}. "
                    f"Process: {os.path.basename(e.get('process_name', 'unknown'))}."
                ),
                evidence=[e],
            ))
    return alerts


def detect_unusual_logon_hours(events):
    alerts = []
    logons = [e for e in events if e["event_id"] == 4624]

    for e in logons:
        user = e.get("target_user") or ""
        if _is_system_account(user):
            continue

        hour = e.get("hour_of_day")
        if hour is None:
            continue

        is_unusual = (hour >= UNUSUAL_HOUR_START or hour < UNUSUAL_HOUR_END)
        if is_unusual:
            alerts.append(make_alert(
                rule_id="TIME-001",
                severity="LOW",
                title=f"Unusual Logon Time - {user}",
                description=(
                    f"User '{user}' logged on at "
                    f"{_parse_ts(e['timestamp']).strftime('%H:%M:%S')} "
                    f"(outside business hours: "
                    f"{UNUSUAL_HOUR_START:02d}:00-{UNUSUAL_HOUR_END:02d}:00)."
                ),
                evidence=[e],
            ))
    return alerts


def detect_account_lockout(events):
    alerts = []
    lockouts = [e for e in events if e["event_id"] == 4740]

    for e in lockouts:
        user = e.get("target_user") or "unknown"
        alerts.append(make_alert(
            rule_id="ACC-003",
            severity="MEDIUM",
            title=f"Account Locked Out - {user}",
            description=(
                f"Account '{user}' was locked out at "
                f"{_parse_ts(e['timestamp']).strftime('%H:%M:%S')}. "
                f"May indicate brute-force or forgotten password."
            ),
            evidence=[e],
        ))
    return alerts


def run_all_rules(events):
    all_alerts = []
    rules = [
        detect_brute_force,
        detect_brute_force_success,
        detect_password_spray,
        detect_new_admin_account,
        detect_suspicious_process,
        detect_unusual_logon_hours,
        detect_account_lockout,
    ]

    for rule in rules:
        try:
            fired = rule(events)
            all_alerts.extend(fired)
        except Exception as e:
            print(f"[!] Rule {rule.__name__} failed: {e}")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))
    return all_alerts


if __name__ == "__main__":
    sys.path.append(".")
    from storage.database import get_connection

    conn = get_connection()
    rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC").fetchall()
    conn.close()

    events = [dict(r) for r in rows]
    print(f"[*] Running detection rules against {len(events)} events...")
    print()

    alerts = run_all_rules(events)
    print(f"[+] {len(alerts)} alerts fired")
    print()

    for alert in alerts[:30]:
        print(f"  [{alert['severity']:8}] {alert['rule_id']} - {alert['title']}")
        print(f"             {alert['description'][:90]}")
        print()
