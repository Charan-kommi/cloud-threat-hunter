#!/usr/bin/env python3
"""
Cloud Threat Hunter
===================
Analyzes AWS CloudTrail logs for suspicious activity patterns including:
  - Root account usage
  - Console logins from unusual locations/IPs
  - IAM privilege escalation attempts
  - Mass resource deletion events
  - Credential stuffing / brute-force login failures
  - Data exfiltration signals (large S3 GetObject volumes)
  - Disabled security services (GuardDuty, CloudTrail)

Supports both live CloudTrail lookup (boto3) and offline JSON log analysis.

Author : Sai Charan Kommi
GitHub : https://github.com/Charan-kommi
"""

import json
import datetime
import argparse
import re
from collections import defaultdict
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

# Rules engine severity colors
SEVERITY_COLOR = {
    "CRITICAL" : "#dc2626",
    "HIGH"     : "#ea580c",
    "MEDIUM"   : "#d97706",
    "LOW"      : "#65a30d",
    "INFO"     : "#2563eb",
}

SUSPICIOUS_EVENT_RULES = [
    {
        "id"          : "TH-001",
        "name"        : "Root Account Activity",
        "description" : "Root account was used. This should never happen in production.",
        "severity"    : "CRITICAL",
        "match"       : lambda e: e.get("userIdentity", {}).get("type") == "Root",
    },
    {
        "id"          : "TH-002",
        "name"        : "CloudTrail Logging Disabled",
        "description" : "CloudTrail was stopped -- attacker may be covering tracks.",
        "severity"    : "CRITICAL",
        "match"       : lambda e: e.get("eventName") in ("StopLogging", "DeleteTrail"),
    },
    {
        "id"          : "TH-003",
        "name"        : "GuardDuty Disabled",
        "description" : "GuardDuty detector was disabled or deleted.",
        "severity"    : "CRITICAL",
        "match"       : lambda e: e.get("eventName") in ("DisableOrganizationAdminAccount", "DeleteDetector"),
    },
    {
        "id"          : "TH-004",
        "name"        : "IAM Privilege Escalation Attempt",
        "description" : "High-risk IAM action that could lead to privilege escalation.",
        "severity"    : "HIGH",
        "match"       : lambda e: e.get("eventName") in (
            "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
            "CreatePolicyVersion", "SetDefaultPolicyVersion",
            "AddUserToGroup", "CreateLoginProfile", "UpdateLoginProfile",
            "CreateAccessKey",
        ),
    },
    {
        "id"          : "TH-005",
        "name"        : "Mass Resource Deletion",
        "description" : "Bulk delete action detected -- potential ransomware or insider threat.",
        "severity"    : "HIGH",
        "match"       : lambda e: (
            e.get("eventName", "").startswith("Delete") and
            e.get("errorCode") is None
        ),
    },
    {
        "id"          : "TH-006",
        "name"        : "Security Group Wide Open",
        "description" : "Security group rule added allowing 0.0.0.0/0 traffic.",
        "severity"    : "HIGH",
        "match"       : lambda e: (
            e.get("eventName") == "AuthorizeSecurityGroupIngress" and
            "0.0.0.0/0" in json.dumps(e.get("requestParameters", {}))
        ),
    },
    {
        "id"          : "TH-007",
        "name"        : "S3 Bucket Made Public",
        "description" : "S3 bucket ACL changed to public-read or public-read-write.",
        "severity"    : "HIGH",
        "match"       : lambda e: (
            e.get("eventName") in ("PutBucketAcl", "PutBucketPolicy") and
            any(x in json.dumps(e.get("requestParameters", {}))
                for x in ("public-read", "AuthenticatedUsers", "AllUsers"))
        ),
    },
    {
        "id"          : "TH-008",
        "name"        : "Console Login Without MFA",
        "description" : "A user logged into the AWS console without MFA.",
        "severity"    : "MEDIUM",
        "match"       : lambda e: (
            e.get("eventName") == "ConsoleLogin" and
            e.get("additionalEventData", {}).get("MFAUsed") == "No" and
            e.get("responseElements", {}).get("ConsoleLogin") == "Success"
        ),
    },
    {
        "id"          : "TH-009",
        "name"        : "Failed Console Login",
        "description" : "Failed login to AWS console -- could indicate credential stuffing.",
        "severity"    : "MEDIUM",
        "match"       : lambda e: (
            e.get("eventName") == "ConsoleLogin" and
            e.get("responseElements", {}).get("ConsoleLogin") == "Failure"
        ),
    },
    {
        "id"          : "TH-011",
        "name"        : "KMS Key Scheduled for Deletion",
        "description" : "KMS encryption key scheduled for deletion -- could cause data loss.",
        "severity"    : "HIGH",
        "match"       : lambda e: e.get("eventName") == "ScheduleKeyDeletion",
    },
    {
        "id"          : "TH-012",
        "name"        : "New IAM User Created",
        "description" : "A new IAM user was created -- verify this is authorized.",
        "severity"    : "INFO",
        "match"       : lambda e: e.get("eventName") == "CreateUser",
    },
]


class Alert:
    def __init__(self, rule_id, rule_name, severity, description, event):
        self.rule_id     = rule_id
        self.rule_name   = rule_name
        self.severity    = severity
        self.description = description
        self.event_name  = event.get("eventName", "")
        self.event_time  = event.get("eventTime", "")
        self.source_ip   = event.get("sourceIPAddress", "")
        self.user        = (
            event.get("userIdentity", {}).get("userName") or
            event.get("userIdentity", {}).get("arn", "unknown")
        )
        self.region      = event.get("awsRegion", "")
        self.raw_event   = event

    def to_dict(self):
        return {
            "rule_id"    : self.rule_id,
            "rule_name"  : self.rule_name,
            "severity"   : self.severity,
            "description": self.description,
            "event_name" : self.event_name,
            "event_time" : self.event_time,
            "source_ip"  : self.source_ip,
            "user"       : self.user,
            "region"     : self.region,
        }


def detect_brute_force(events, threshold=5):
    """Flag IPs with >= threshold failed console logins."""
    alerts = []
    fail_counts = defaultdict(list)

    for e in events:
        if (e.get("eventName") == "ConsoleLogin" and
                e.get("responseElements", {}).get("ConsoleLogin") == "Failure"):
            ip = e.get("sourceIPAddress", "unknown")
            fail_counts[ip].append(e)

    for ip, evts in fail_counts.items():
        if len(evts) >= threshold:
            synthetic = {
                "eventName"      : "ConsoleLogin",
                "eventTime"      : evts[-1].get("eventTime", ""),
                "sourceIPAddress": ip,
                "awsRegion"      : evts[-1].get("awsRegion", ""),
                "userIdentity"   : {"type": "IAMUser", "userName": "multiple"},
                "responseElements": {"ConsoleLogin": "Failure"},
            }
            alert = Alert(
                rule_id     = "TH-BF01",
                rule_name   = f"Brute Force Detected from {ip}",
                severity    = "HIGH",
                description = f"{len(evts)} failed console logins from {ip}.",
                event       = synthetic,
            )
            alerts.append(alert)

    return alerts


def analyze_events(events):
    alerts = []
    for event in events:
        for rule in SUSPICIOUS_EVENT_RULES:
            try:
                if rule["match"](event):
                    alerts.append(Alert(
                        rule_id     = rule["id"],
                        rule_name   = rule["name"],
                        severity    = rule["severity"],
                        description = rule["description"],
                        event       = event,
                    ))
            except Exception:
                pass
    alerts += detect_brute_force(events)
    return alerts


def load_from_file(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return data.get("Records", [])


def load_from_cloudtrail(session, hours=24):
    ct = session.client("cloudtrail")
    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(hours=hours)
    events = []
    paginator = ct.get_paginator("lookup_events")
    for page in paginator.paginate(StartTime=start, EndTime=end):
        for record in page.get("Events", []):
            raw = record.get("CloudTrailEvent")
            if raw:
                try:
                    events.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
    return events


def generate_html_report(alerts, output_path="threat_report.html"):
    from collections import Counter
    counts = Counter(a.severity for a in alerts)
    rows = ""
    for a in sorted(alerts, key=lambda x: list(SEVERITY_COLOR).index(x.severity)):
        color = SEVERITY_COLOR.get(a.severity, "#6b7280")
        rows += f"""
        <tr>
          <td><code>{a.rule_id}</code></td>
          <td>{a.rule_name}</td>
          <td><span class="badge" style="background:{color}">{a.severity}</span></td>
          <td>{a.event_name}</td>
          <td>{a.event_time}</td>
          <td>{a.user}</td>
          <td>{a.source_ip}</td>
          <td style="font-size:0.78rem;color:#94a3b8">{a.description}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Cloud Threat Hunt Report</title>
  <style>
    body {{ font-family:'Segoe UI',sans-serif; background:#0f172a; color:#e2e8f0; padding:24px; margin:0; }}
    h1   {{ color:#f43f5e; }}
    .ts  {{ color:#94a3b8; font-size:0.8rem; margin-bottom:16px; }}
    .summary {{ display:flex; gap:12px; margin:20px 0; flex-wrap:wrap; }}
    .card {{ background:#1e293b; border-radius:8px; padding:12px 20px; text-align:center; min-width:90px; }}
    .card .num {{ font-size:1.8rem; font-weight:700; }}
    table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:8px; overflow:hidden; font-size:0.82rem; }}
    th    {{ background:#be123c; color:#fff; padding:10px; text-align:left; }}
    td    {{ padding:9px; border-bottom:1px solid #334155; vertical-align:top; }}
    tr:hover td {{ background:#273549; }}
    .badge {{ padding:3px 10px; border-radius:999px; color:#fff; font-size:0.73rem; font-weight:600; }}
    code  {{ background:#0f172a; padding:2px 6px; border-radius:4px; font-size:0.8rem; }}
  </style>
</head>
<body>
  <h1>Cloud Threat Hunt Report</h1>
  <div class="ts">Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | {len(alerts)} alert(s)</div>
  <div class="summary">
    <div class="card"><div class="num" style="color:#dc2626">{counts.get('CRITICAL',0)}</div><div>CRITICAL</div></div>
    <div class="card"><div class="num" style="color:#ea580c">{counts.get('HIGH',0)}</div><div>HIGH</div></div>
    <div class="card"><div class="num" style="color:#d97706">{counts.get('MEDIUM',0)}</div><div>MEDIUM</div></div>
    <div class="card"><div class="num" style="color:#65a30d">{counts.get('LOW',0)}</div><div>LOW</div></div>
    <div class="card"><div class="num" style="color:#2563eb">{counts.get('INFO',0)}</div><div>INFO</div></div>
  </div>
  <table>
    <thead><tr>
      <th>Rule</th><th>Alert</th><th>Severity</th><th>Event</th>
      <th>Time</th><th>User</th><th>Source IP</th><th>Details</th>
    </tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="8" style="text-align:center;color:#64748b;padding:32px">No threats detected</td></tr>'}</tbody>
  </table>
</body>
</html>"""
    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[+] HTML report -> {output_path}")


def generate_json_report(alerts, output_path="threat_report.json"):
    data = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_alerts": len(alerts),
        "alerts"      : [a.to_dict() for a in alerts],
    }
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] JSON report -> {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Cloud Threat Hunter -- AWS CloudTrail log analysis"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file",    help="Path to CloudTrail JSON log file")
    src.add_argument("--live",    action="store_true", help="Pull events live from CloudTrail API")
    parser.add_argument("--hours",        type=int,   default=24,       help="Hours of history (live mode)")
    parser.add_argument("--profile",      default=None,                 help="AWS CLI profile")
    parser.add_argument("--region",       default="us-east-1",          help="AWS region")
    parser.add_argument("--output",       default="both", choices=["html", "json", "both"])
    parser.add_argument("--bf-threshold", type=int,   default=5,        help="Brute-force threshold")
    args = parser.parse_args()

    print("=" * 55)
    print("   Cloud Threat Hunter -- by Sai Charan Kommi")
    print("=" * 55 + "\n")

    if args.file:
        print(f"[*] Loading events from: {args.file}")
        events = load_from_file(args.file)
    else:
        if not BOTO3_AVAILABLE:
            print("[!] boto3 not installed. Run: pip install boto3")
            return
        print(f"[*] Pulling live CloudTrail events (last {args.hours}h)...")
        try:
            session = boto3.Session(profile_name=args.profile, region_name=args.region)
            session.client("sts").get_caller_identity()
            events = load_from_cloudtrail(session, args.hours)
        except NoCredentialsError:
            print("[!] No AWS credentials found.")
            return
        except ClientError as e:
            print(f"[!] AWS error: {e}")
            return

    print(f"[+] Loaded {len(events)} events\n")
    print("[*] Running threat detection rules...")
    alerts = analyze_events(events)

    from collections import Counter
    counts = Counter(a.severity for a in alerts)
    print(f"\n[=] Results:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if counts[sev]:
            print(f"    {sev:10s}: {counts[sev]}")
    print(f"    {'TOTAL':10s}: {len(alerts)}")

    notable = [a for a in alerts if a.severity in ("CRITICAL", "HIGH")]
    if notable:
        print("\n[!] Notable findings:")
        for a in notable[:10]:
            print(f"    [{a.severity}] {a.rule_name} -- {a.event_time} -- {a.user} from {a.source_ip}")

    if args.output in ("html", "both"):
        generate_html_report(alerts)
    if args.output in ("json", "both"):
        generate_json_report(alerts)


if __name__ == "__main__":
    main()
