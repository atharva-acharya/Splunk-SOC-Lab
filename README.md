# Splunk SIEM Investigation Lab

A hands-on SOC analyst portfolio project demonstrating threat detection, investigation, and incident response using Splunk Enterprise and the BOTS v3 (Boss of the SOC) dataset. Five SPL detection rules covering a real-world web attack chain — from initial reconnaissance through exploitation, privilege escalation, exfiltration, and cloud credential theft — each backed by an investigation-led IR report mapped to MITRE ATT&CK.

---

## Contents

- [Lab Overview](#lab-overview)
- [Environment](#environment)
- [Dataset](#dataset)
- [Detection Rules](#detection-rules)
- [Incident Reports](#incident-reports)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Attack Chain Narrative](#attack-chain-narrative)
- [Repository Structure](#repository-structure)
- [Related Projects](#related-projects)

---

## Lab Overview

| Component | Detail |
|-----------|--------|
| **SIEM** | Splunk Enterprise 10.4.0 |
| **Dataset** | BOTS v3 (Boss of the SOC v3) |
| **Detection Rules** | 5 SPL analytics rules |
| **IR Reports** | 5 investigation-led reports |
| **MITRE Techniques** | 10 techniques across 7 tactics |
| **Attack Surface** | Web application, Windows endpoints, AWS cloud |

---

## Environment

**Host:** Windows 11, Intel i7-13700HX, 32GB RAM  
**Splunk:** Enterprise 10.4.0, local installation  
**Index:** `botsv3`

Splunk Enterprise was installed natively on the Windows host (not virtualised) to maximise ingestion performance for the BOTS v3 dataset (~30GB uncompressed). The BOTS v3 app package was installed directly via the Splunk web UI.

---

## Dataset

**BOTS v3 (Boss of the SOC Version 3)** is a realistic attack dataset produced by Splunk for CTF-style security investigations. It contains log data from a simulated enterprise environment under active attack, spanning web servers, Windows endpoints, AWS infrastructure, and network traffic.

| Sourcetype | Event Count | Use |
|------------|-------------|-----|
| `syslog` | 283,976 | Linux system logs |
| `stream:ip` | 227,872 | Network IP flows |
| `stream:dns` | 218,456 | DNS query/response |
| `stream:udp` | 157,960 | UDP traffic |
| `winhostmon` | 129,679 | Windows host monitoring |
| `aws:cloudwatchlogs` | 115,145 | AWS CloudWatch |
| `aws:cloudwatchlogs:vpcflow` | 97,448 | VPC flow logs |
| `wineventlog:security` | 46,469 | Windows Security events |
| `stream:http` | 24,191 | HTTP traffic |
| `aws:cloudtrail` | 6,571 | AWS API audit logs |
| `xmlwineventlog:microsoft-windows-sysmon/operational` | 9,212 | Sysmon events |

---

## Detection Rules

Five SPL analytics rules covering distinct attack techniques across web, endpoint, DNS, and cloud attack surfaces.

| # | Rule | Technique | MITRE ID | Sourcetype | Severity |
|---|------|-----------|----------|------------|----------|
| 01 | [Web Reconnaissance](detection-rules/SPL-Rule-01-Web-Recon.md) | Active Scanning | T1595.002 | stream:http | Medium |
| 02 | [Apache Struts RCE](detection-rules/SPL-Rule-02-Struts-RCE.md) | Exploit Public-Facing Application | T1190 | stream:http | Critical |
| 03 | [DNS Exfiltration](detection-rules/SPL-Rule-03-DNS-Exfiltration.md) | Exfiltration Over DNS | T1048.003 | stream:dns | High |
| 04 | [Suspicious LOLBin Execution](detection-rules/SPL-Rule-04-Suspicious-Process.md) | Windows Command Shell | T1059.003 | wineventlog:security | Medium |
| 05 | [AWS IMDS Credential Theft](detection-rules/SPL-Rule-05-AWS-IMDS-Abuse.md) | Cloud Instance Metadata API | T1552.005 | stream:http | Critical |

### Rule Highlights

**Rule 02 — Apache Struts RCE (CVE-2017-9805)**  
Detects OGNL expression injection in HTTP POST bodies targeting Apache Struts REST plugin endpoints. Fires on presence of `OgnlContext`, `ProcessBuilder`, or `Runtime.exec` patterns in `form_data` — none of which appear in legitimate application traffic. This rule detected a complete attack chain including backdoor account creation and reverse shell establishment.

**Rule 05 — AWS IMDS Credential Theft**  
Detects successful queries to the AWS Instance Metadata Service at `169.254.169.254` targeting IAM security credential endpoints. Filters on HTTP 200 responses only — eliminates probing attempts and focuses on confirmed credential retrieval. This technique was used in the 2019 Capital One breach.

---

## Incident Reports

All five reports are investigation-led: each documents the SPL queries used during the investigation, the evidence returned, and how findings drove the next investigative step. Reports are not alert summaries — they reconstruct the analyst's decision-making process.

| Report | Title | Severity | MITRE |
|--------|-------|----------|-------|
| [IR-001](ir-reports/IR-001-Web-Reconnaissance.md) | Web Reconnaissance: Active Scanning Detected | Medium | T1595.002 |
| [IR-002](ir-reports/IR-002-Apache-Struts-RCE.md) | Apache Struts RCE: Full Attack Chain (CVE-2017-9805) | Critical | T1190 |
| [IR-003](ir-reports/IR-003-DNS-Exfiltration.md) | DNS Exfiltration via Froth.ly Subdomains | High | T1048.003 |
| [IR-004](ir-reports/IR-004-LOLBin-Execution.md) | LOLBin Execution: WMIC and reg.exe Abuse | Medium | T1059.003 |
| [IR-005](ir-reports/IR-005-AWS-IMDS-Credential-Theft.md) | AWS Instance Metadata Service Credential Theft | Critical | T1552.005 |

### IR-002 — Attack Chain Summary

IR-002 documents the most complete attack sequence in the lab. The attacker at `192.168.8.103` exploited CVE-2017-9805 against an unpatched Apache Struts instance at `192.168.9.30`, then executed the following post-exploitation sequence entirely via injected OS commands:

```
id → groups → cat /etc/passwd → useradd (UID 0 backdoor) →
uname -a → drop kernel exploit → decode exploit →
compile exploit → establish reverse shell to 45.77.53.176:8088
```

Full command extraction, timeline reconstruction, and IOC documentation in [IR-002](ir-reports/IR-002-Apache-Struts-RCE.md).

---

## MITRE ATT&CK Coverage

![MITRE ATT&CK Navigator Layer](screenshots/mitre-navigator-layer.png)

**Navigator layer:** [Splunk-SOC-Lab-MITRE-Layer.json](mitre-navigator/Splunk-SOC-Lab-MITRE-Layer.json)  
Load via [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) → Open Existing Layer → Upload from local.

| Tactic | Technique | ID |
|--------|-----------|-----|
| Reconnaissance | Active Scanning: Vulnerability Scanning | T1595.002 |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Windows Command Shell | T1059.003 |
| Execution | Windows Management Instrumentation | T1047 |
| Persistence | Create Local Account | T1136.001 |
| Defence Evasion | Modify Registry | T1112 |
| Credential Access | Cloud Instance Metadata API | T1552.005 |
| Command & Control | Ingress Tool Transfer | T1105 |
| Command & Control | Application Layer Protocol: Web | T1071.001 |
| Exfiltration | Exfiltration Over Alternative Protocol: DNS | T1048.003 |

---

## Attack Chain Narrative

The BOTS v3 dataset contains a coherent attack campaign. The five detection rules and reports in this lab map to distinct phases of that campaign:

```
RECONNAISSANCE          INITIAL ACCESS         EXECUTION
IR-001                  IR-002                 IR-002 / IR-004
Web scanning            Apache Struts RCE      OS commands via
192.168.3.130           CVE-2017-9805          OGNL injection +
172.16.197.137          192.168.8.103          LOLBin execution
     │                       │                      │
     └───────────────────────┘                      │
              Scanning identified                    │
              Struts endpoint                        │
                                                     ▼
EXFILTRATION            CREDENTIAL ACCESS       PERSISTENCE
IR-003                  IR-005                  IR-002
DNS tunnelling          AWS IMDS query          Backdoor account
BSTOLL-L →              172.31.12.76 →          tomcat7 (UID 0)
froth.ly subdomains     EC2InstanceRole creds   Reverse shell C2
```

IR-001 and IR-002 are explicitly linked: the scanner `172.16.197.137` identified the Struts endpoint during reconnaissance before exploitation. IR-002 and IR-005 are linked: root access via Struts RCE on an EC2 instance enables direct IMDS queries for credential theft.

---

## Repository Structure

```
Splunk-SOC-Lab/
├── README.md
├── LICENSE
├── detection-rules/
│   ├── SPL-Rule-01-Web-Recon.md
│   ├── SPL-Rule-02-Struts-RCE.md
│   ├── SPL-Rule-03-DNS-Exfiltration.md
│   ├── SPL-Rule-04-Suspicious-Process.md
│   └── SPL-Rule-05-AWS-IMDS-Abuse.md
├── ir-reports/
│   ├── IR-001-Web-Reconnaissance.md
│   ├── IR-002-Apache-Struts-RCE.md
│   ├── IR-003-DNS-Exfiltration.md
│   ├── IR-004-LOLBin-Execution.md
│   └── IR-005-AWS-IMDS-Credential-Theft.md
├── mitre-navigator/
│   └── Splunk-SOC-Lab-MITRE-Layer.json
├── datasets/
│   └── botsv3_data_set.tgz (not tracked — too large for GitHub)
└── screenshots/
    ├── splunk-install-verified.png
    ├── botsv3-ingestion-verified.png
    ├── spl-detection-rules-verified.png
    └── mitre-navigator-layer.png
```

---

## Related Projects

This lab is part of a portfolio of hands-on SOC analyst projects:

| Project | Focus | Link |
|---------|-------|------|
| AD SOC Detection Lab | Active Directory attacks, KQL, Microsoft Sentinel, 7 IR reports | [github.com/atharva-acharya/AD-SOC-Detection-Lab](https://github.com/atharva-acharya/AD-SOC-Detection-Lab) |
| Microsoft Sentinel Detection Lab | Azure SIEM, KQL analytics rules, Sysmon, 5 IR reports | [github.com/atharva-acharya/Sentinel-Detection-Lab](https://github.com/atharva-acharya/Sentinel-Detection-Lab) |
| Splunk SIEM Investigation Lab | Splunk SPL, BOTS v3, web attack chain, cloud threats | This repository |

---

*MSc Cyber Security Engineering — University of Warwick (Merit)*  
*CDSA — HackTheBox (June 2026)*
