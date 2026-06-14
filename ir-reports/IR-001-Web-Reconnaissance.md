# IR-001 — Web Reconnaissance: Active Scanning Detected

| Field | Detail |
|-------|--------|
| **Incident ID** | IR-001 |
| **Date** | 2018-08-20 |
| **Severity** | Medium |
| **Status** | Closed |
| **MITRE ATT&CK** | T1595.002 — Active Scanning: Vulnerability Scanning |
| **Analyst** | Atharva Acharya |
| **Dataset** | BOTS v3 (index=botsv3) |

---

## 1. Executive Summary

On 2018-08-20, anomalous HTTP traffic was detected originating from multiple source IPs against internal and external web infrastructure. Investigation confirmed automated vulnerability scanning activity from at least five distinct sources, with `192.168.3.130` identified as the most aggressive scanner generating 2,207 HTTP requests across 1,023 unique URI paths. No exploitation was confirmed as a direct result of this scanning activity, however subsequent incidents (IR-002) indicate that reconnaissance data gathered during this phase was leveraged for targeted exploitation.

---

## 2. Detection

**Initial Alert:** SPL Rule 01 — Web Reconnaissance/Scanning (T1595.002)

The detection rule identified source IPs generating more than 100 HTTP requests across more than 10 unique URI paths within the dataset timeframe. This threshold combination is designed to distinguish automated scanners from high-volume but legitimate single-resource traffic.

**Detection Query:**
```spl
index=botsv3 sourcetype="stream:http"
| stats count as request_count dc(uri_path) as unique_paths by src_ip
| where request_count > 100 AND unique_paths > 10
| sort -request_count
| table src_ip, request_count, unique_paths
```

**Initial Results:**

| src_ip | request_count | unique_paths |
|--------|--------------|--------------|
| 192.168.3.130 | 2,207 | 1,023 |
| 91.207.175.249 | 839 | 45 |
| 172.16.197.137 | 752 | 425 |
| 192.168.24.128 | 532 | 338 |
| 192.168.70.186 | 436 | 323 |

---

## 3. Investigation

### 3.1 Scoping the Primary Scanner

`192.168.3.130` was flagged as the primary concern given its volume. The investigation began by profiling the URI paths being requested to determine whether this was a generic scan or targeted reconnaissance.

**Query — URI path distribution for primary scanner:**
```spl
index=botsv3 sourcetype="stream:http" src_ip="192.168.3.130"
| stats count by uri_path
| sort -count
| head 20
```

Results showed requests spanning web application paths including `/wp-admin/`, `/wp-content/plugins/`, and CMS-specific endpoints, consistent with tools such as WPScan or Nikto targeting WordPress infrastructure.

### 3.2 Temporal Analysis

**Query — Request volume over time:**
```spl
index=botsv3 sourcetype="stream:http" src_ip="192.168.3.130"
| bucket _time span=10m
| stats count by _time
| sort _time
```

Traffic was sustained across the dataset timeframe with no single burst spike, indicating a throttled scanner configured to avoid rate-based detection — a deliberate operational security choice by the threat actor.

### 3.3 Secondary Scanner — 172.16.197.137

`172.16.197.137` with 752 requests across 425 unique paths was investigated separately. This IP was also identified in IR-002 conducting Apache Struts exploitation, confirming that the scanning phase directly preceded and informed targeted exploitation activity.

**Query — Destination analysis for 172.16.197.137:**
```spl
index=botsv3 sourcetype="stream:http" src_ip="172.16.197.137"
| stats count by dest_ip, uri_path
| sort -count
| head 10
```

Results confirmed this scanner was specifically probing `192.168.9.30` — the same host later exploited via CVE-2017-9805.

### 3.4 Response Code Analysis

**Query — HTTP response codes from scanning activity:**
```spl
index=botsv3 sourcetype="stream:http" src_ip="172.16.197.137"
| stats count by status
| sort -count
```

A mix of 200, 301, 302, and 404 responses confirmed the scanner was receiving valid responses from target hosts, providing the attacker with a live map of accessible endpoints.

---

## 4. Timeline

| Time (UTC) | Event |
|------------|-------|
| 2018-08-20 ~12:00 | Scanning activity begins from 172.16.197.137 against 192.168.9.30 |
| 2018-08-20 ~12:05 | 192.168.3.130 begins broad web infrastructure scan |
| 2018-08-20 ~12:05 | Apache Struts endpoint identified at /frothlyinventory/integration/saveGangster.action |
| 2018-08-20 ~12:05 | Exploitation begins (IR-002) |

---

## 5. Findings

- **Five source IPs** were identified conducting automated HTTP scanning
- **192.168.3.130** was the highest-volume scanner (2,207 requests, 1,023 unique paths)
- **172.16.197.137** conducted targeted reconnaissance against `192.168.9.30` which was subsequently exploited
- Scanning activity preceded exploitation by minutes, confirming a deliberate attack sequence
- No scanning traffic was blocked at the perimeter, indicating absence of rate-limiting or WAF rules

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Detail |
|-----------|----|--------|
| Active Scanning: Vulnerability Scanning | T1595.002 | Automated HTTP scanning across 1,023+ unique URI paths |
| Gather Victim Host Information | T1592 | OS and application fingerprinting via response analysis |

---

## 7. Recommendations

1. **Deploy WAF rate limiting** — block source IPs generating more than 100 requests per minute against web assets
2. **Alert on 404 spike patterns** — high 404 rates from a single IP are a reliable pre-exploitation indicator
3. **Segment internal web hosts** — `192.168.9.30` should not have been reachable from `172.16.197.137`
4. **Threat intelligence enrichment** — `91.207.175.249` is an external IP; cross-reference against threat intel feeds at time of scanning
5. **Correlate with IR-002** — scanning activity from `172.16.197.137` directly preceded Apache Struts exploitation; these incidents are part of the same attack chain

---

## 8. Artifacts

| Type | Value |
|------|-------|
| Attacker IP (internal) | 192.168.3.130 |
| Attacker IP (internal) | 172.16.197.137 |
| Attacker IP (external) | 91.207.175.249 |
| Target host | 192.168.9.30 |
| Target host | 172.16.0.178 |
| Identified endpoint | /frothlyinventory/integration/saveGangster.action |
| Related incident | IR-002 |
