# 🎯 Cloud Threat Hunter

> AWS CloudTrail log analyzer that detects suspicious activity patterns — root usage, privilege escalation, brute-force logins, data exfiltration signals, and disabled security controls.

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-CloudTrail-FF9900?style=flat-square&logo=amazon-aws&logoColor=white)](https://aws.amazon.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![Security](https://img.shields.io/badge/Domain-Threat%20Detection-red?style=flat-square)]()

---

## 📋 Overview

**Cloud Threat Hunter** is a Python-based threat detection tool for AWS environments. It ingests CloudTrail logs — either from a local file or live via the AWS API — and applies a rule-based engine to flag suspicious events that may indicate a breach, insider threat, or misconfiguration.

This mirrors how real SOC teams and CSPM tools (like AWS Security Hub, Splunk, or Panther) work: ingest CloudTrail → correlate events → generate alerts.

---

## ✨ Detection Rules (12 built-in)

| Rule | Severity | What It Detects |
|---|---|---|
| TH-001 | 🔴 CRITICAL | Root account usage |
| TH-002 | 🔴 CRITICAL | CloudTrail logging disabled |
| TH-003 | 🔴 CRITICAL | GuardDuty disabled/deleted |
| TH-004 | 🟠 HIGH | IAM privilege escalation attempts |
| TH-005 | 🟠 HIGH | Mass resource deletion |
| TH-006 | 🟠 HIGH | Security group opened to 0.0.0.0/0 |
| TH-007 | 🟠 HIGH | S3 bucket made public |
| TH-008 | 🟡 MEDIUM | Console login without MFA |
| TH-009 | 🟡 MEDIUM | Failed console login |
| TH-011 | 🟠 HIGH | KMS key scheduled for deletion |
| TH-BF01 | 🟠 HIGH | Brute-force login (≥5 failures from same IP) |
| TH-012 | 🔵 INFO | New IAM user created |

---

## 🏗️ Architecture

```
cloud-threat-hunter/
│
├── hunter.py         ← Main script (rules engine + reporting)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

```bash
git clone https://github.com/Charan-kommi/cloud-threat-hunter.git
cd cloud-threat-hunter
pip install -r requirements.txt
```

---

## 💻 Usage

### Offline mode — analyze a local CloudTrail log file

```bash
python hunter.py --file cloudtrail_export.json
```

### Live mode — pull directly from CloudTrail API

```bash
# Last 24 hours (default)
python hunter.py --live

# Last 72 hours with a named profile
python hunter.py --live --hours 72 --profile security-audit --region us-east-1
```

### Output options

```bash
# HTML report (default: both)
python hunter.py --live --output html

# JSON (for SIEM/pipeline integration)
python hunter.py --live --output json

# Adjust brute-force threshold
python hunter.py --file logs.json --bf-threshold 3
```

### Sample Output

```
=======================================================
   Cloud Threat Hunter — by Sai Charan Kommi
=======================================================

[*] Pulling live CloudTrail events (last 24h)...
[+] Loaded 1,847 events

[*] Running threat detection rules...

[=] Results:
    CRITICAL  : 2
    HIGH      : 5
    MEDIUM    : 3
    INFO      : 1
    TOTAL     : 11

[!] Notable findings:
    [CRITICAL] Root Account Activity — 2025-11-01T03:12:44Z — root from 203.0.113.42
    [CRITICAL] CloudTrail Logging Disabled — 2025-11-01T03:14:01Z — root from 203.0.113.42
    [HIGH] IAM Privilege Escalation Attempt — 2025-11-01T02:58:00Z — compromised-svc from 198.51.100.7

[+] HTML report → threat_report.html
[+] JSON report → threat_report.json
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.8+ |
| AWS SDK | boto3 / botocore |
| Log Source | AWS CloudTrail (file or live API) |
| Detection | Rule-based + aggregate correlation |
| Output | HTML dashboard, JSON (SIEM-ready) |

---

## 🔒 Required IAM Permissions

For live mode, attach a read-only policy with at least:

```json
{
  "Effect": "Allow",
  "Action": [
    "cloudtrail:LookupEvents",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🗺️ Roadmap

- [x] 12 built-in detection rules
- [x] Brute-force correlation
- [x] HTML + JSON reporting
- [x] Offline (file) + live (API) modes
- [ ] MITRE ATT&CK TTP tagging
- [ ] Slack / email alerting
- [ ] VPC Flow Log analysis
- [ ] Custom rule YAML definitions
- [ ] Time-series anomaly detection (ML)

---

## 👤 Author

**Sai Charan Kommi**
[![LinkedIn](https://img.shields.io/badge/LinkedIn-charankommi-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/charankommi)
[![GitHub](https://img.shields.io/badge/GitHub-Charan--kommi-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/Charan-kommi)

> MS Cybersecurity @ GWU | CompTIA Security+ | AWS Cloud Security Builder
