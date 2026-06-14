# IR-005 — AWS Instance Metadata Service (IMDS) Credential Theft

| Field | Detail |
|-------|--------|
| **Incident ID** | IR-005 |
| **Date** | 2018-08-20 |
| **Severity** | Critical |
| **Status** | Closed |
| **MITRE ATT&CK** | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| **Analyst** | Atharva Acharya |
| **Dataset** | BOTS v3 (index=botsv3) |

---

## 1. Executive Summary

On 2018-08-20, HTTP traffic analysis identified multiple internal hosts successfully querying the AWS Instance Metadata Service (IMDS) at `169.254.169.254` for IAM security credentials. The primary source, `172.31.12.76`, made 32 successful requests to `/latest/meta-data/iam/security-credentials/EC2InstanceRole`, retrieving temporary AWS access keys associated with the `EC2InstanceRole` IAM role. Successful retrieval of these credentials grants the attacker the same AWS API permissions as the EC2 instance role — potentially including access to S3 buckets, RDS databases, and other AWS services depending on the role's permission set. This technique was used in the 2019 Capital One breach, resulting in exfiltration of over 100 million customer records. The presence of this activity in conjunction with the Struts RCE identified in IR-002 suggests the attacker pivoted from server compromise to cloud credential theft as part of a broader data exfiltration objective.

---

## 2. Detection

**Initial Alert:** SPL Rule 05 — AWS IMDS Credential Theft (T1552.005)

**Detection Query:**
```spl
index=botsv3 sourcetype="stream:http" dest_ip="169.254.169.254"
| where match(uri_path, "(?i)(iam/security-credentials|user-data|instance-id)")
| stats count by src_ip, uri_path, status
| where status=200
| sort -count
| table src_ip, uri_path, status, count
```

The rule detected successful HTTP 200 responses from the metadata service to queries targeting IAM credential endpoints — the definitive indicator of credential retrieval.

---

## 3. Investigation

### 3.1 Confirming Credential Access

The investigation first established the full scope of IMDS queries to determine whether credential retrieval was successful or merely attempted.

**Query — All IMDS queries with response codes:**
```spl
index=botsv3 sourcetype="stream:http" dest_ip="169.254.169.254"
| stats count by src_ip, uri_path, status
| sort -count
```

| src_ip | uri_path | status | count |
|--------|----------|--------|-------|
| 172.31.12.76 | /latest/meta-data/instance-id | 200 | 121 |
| 172.16.0.178 | /latest/meta-data/instance-id | 200 | 73 |
| 172.31.12.76 | /latest/meta-data/iam/security-credentials | 301 | 32 |
| 172.31.12.76 | /latest/meta-data/iam/security-credentials/ | 200 | 32 |
| 172.31.12.76 | /latest/meta-data/iam/security-credentials/EC2InstanceRole | 200 | 32 |
| 172.16.0.178 | /latest/meta-data/iam/security-credentials/EC2InstanceRole | 200 | 17 |

The HTTP 200 responses to `/latest/meta-data/iam/security-credentials/EC2InstanceRole` confirm successful credential retrieval. The 301 redirect from the non-trailing-slash path followed by a 200 response is the standard IMDS query pattern — this is automated tooling, not manual browser access.

### 3.2 Understanding the Credential Exposure

The AWS IMDS returns temporary credentials in the following JSON format when queried successfully:

```json
{
  "Code": "Success",
  "LastUpdated": "2018-08-20T...",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "..."
}
```

These temporary credentials — `AccessKeyId`, `SecretAccessKey`, and `Token` — can be used immediately with the AWS CLI or SDK to perform any API action permitted by the `EC2InstanceRole` policy. Without knowing the exact permissions attached to `EC2InstanceRole`, the worst-case scenario includes read/write access to all S3 buckets, RDS access, EC2 control plane operations, and IAM privilege escalation.

### 3.3 Query Volume Analysis

**Query — IMDS query frequency over time:**
```spl
index=botsv3 sourcetype="stream:http" dest_ip="169.254.169.254"
  src_ip="172.31.12.76"
| bucket _time span=5m
| stats count by _time
| sort _time
```

32 credential queries from a single source in a concentrated timeframe is not consistent with normal application behaviour. Legitimate applications typically query IMDS once on startup and cache the credentials until near-expiry. Repeated queries suggest either a script cycling credentials or tooling designed to harvest and exfiltrate them.

### 3.4 Relationship to IR-002

**Query — Correlating IMDS queries with Struts RCE activity:**
```spl
index=botsv3 sourcetype="stream:http"
| where (dest_ip="169.254.169.254" AND src_ip="172.31.12.76")
   OR (dest_ip="192.168.9.30" AND src_ip="192.168.8.103")
| table _time, src_ip, dest_ip, uri_path
| sort _time
```

The Struts RCE in IR-002 gave the attacker root access to `192.168.9.30`. An attacker with root access on an EC2 instance can query the metadata service directly. While the IMDS queries originate from `172.31.12.76` rather than `192.168.9.30`, the `172.31.12.x` subnet is the AWS internal subnet range, suggesting `172.31.12.76` may be the internal AWS IP of the compromised instance. The attack chain hypothesis is: Struts RCE → root on EC2 instance → IMDS query → IAM credential theft → AWS lateral movement.

### 3.5 CloudTrail Correlation

**Query — AWS API activity following credential retrieval:**
```spl
index=botsv3 sourcetype="aws:cloudtrail"
| stats count by userAgent, eventName, sourceIPAddress
| sort -count
| head 15
```

CloudTrail logs in the dataset should be reviewed for API calls made using the `EC2InstanceRole` credentials after the IMDS queries — this would confirm whether the stolen credentials were actively used for lateral movement within AWS.

---

## 4. Timeline

| Time (UTC) | Event |
|------------|-------|
| 2018-08-20 ~12:05 | Struts RCE gives attacker root on EC2 instance (IR-002) |
| 2018-08-20 (sustained) | 172.31.12.76 queries /latest/meta-data/instance-id (121 times) |
| 2018-08-20 (sustained) | 172.31.12.76 queries /latest/meta-data/iam/security-credentials/EC2InstanceRole (32 successful retrievals) |
| 2018-08-20 (sustained) | 172.16.0.178 also retrieves EC2InstanceRole credentials (17 times) |
| 2018-08-20 (post-retrieval) | Suspected use of stolen credentials for AWS API access (CloudTrail review required) |

---

## 5. Findings

- **Successful IAM credential retrieval** from IMDS was confirmed via HTTP 200 responses to `/latest/meta-data/iam/security-credentials/EC2InstanceRole`
- **Two internal hosts** (`172.31.12.76` and `172.16.0.178`) retrieved credentials — scope is wider than a single compromised instance
- **32 credential retrievals** from `172.31.12.76` indicates automated or scripted activity, not application startup caching
- The IMDS endpoint was accessible without authentication — **IMDSv1 was in use**, which does not require session tokens and is trivially exploitable
- Credential retrieval in conjunction with the Struts RCE (IR-002) suggests a **deliberate cloud pivot** as part of a broader attack campaign
- The `EC2InstanceRole` permissions are unknown but represent the **blast radius** of this incident — a high-privilege role could enable full AWS environment compromise

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Detail |
|-----------|----|--------|
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Direct IMDS query for IAM credentials |
| Valid Accounts: Cloud Accounts | T1078.004 | Use of stolen IAM credentials for AWS access |
| Cloud Infrastructure Discovery | T1580 | Instance metadata enumeration as reconnaissance |

---

## 7. Recommendations

1. **Enforce IMDSv2 immediately** — IMDSv2 requires a session-oriented PUT request before GET requests are served, blocking SSRF-based IMDS abuse; enforce via EC2 instance metadata options: `HttpTokens: required`
2. **Rotate EC2InstanceRole credentials** — any temporary credentials retrieved during this window must be considered compromised; rotate by disassociating and re-associating the IAM role
3. **Audit EC2InstanceRole permissions** — apply least-privilege; the role should only have permissions required for its application function
4. **Review CloudTrail for credential use** — search for API calls using the `EC2InstanceRole` AccessKeyId values from the IMDS retrieval timeframe
5. **Enable VPC flow logs** — correlate IMDS queries with outbound connections to determine if credentials were exfiltrated to external infrastructure
6. **Alert on IMDS credential endpoint access** — any query to `/iam/security-credentials/` should generate a security alert; legitimate applications query this endpoint infrequently and predictably
7. **Consider instance profile scoping** — where possible, use resource-based policies to restrict which principals can assume the EC2 role

---

## 8. Artifacts

| Type | Value |
|------|-------|
| Primary attacker IP | 172.31.12.76 |
| Secondary attacker IP | 172.16.0.178 |
| Target | 169.254.169.254 (AWS IMDS) |
| Compromised role | EC2InstanceRole |
| Credential endpoint | /latest/meta-data/iam/security-credentials/EC2InstanceRole |
| Successful retrievals | 32 (172.31.12.76), 17 (172.16.0.178) |
| IMDS version | v1 (unauthenticated — vulnerable) |
| Related incident | IR-002 (Struts RCE — likely initial access vector) |
| Real-world precedent | Capital One breach, 2019 (CVE-2019-11634) |
