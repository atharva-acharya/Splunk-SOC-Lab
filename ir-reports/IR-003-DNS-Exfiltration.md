# IR-003 — DNS Exfiltration via Froth.ly Subdomains

| Field | Detail |
|-------|--------|
| **Incident ID** | IR-003 |
| **Date** | 2018-08-20 |
| **Severity** | High |
| **Status** | Closed |
| **MITRE ATT&CK** | T1048.003 — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted DNS |
| **Analyst** | Atharva Acharya |
| **Dataset** | BOTS v3 (index=botsv3) |

---

## 1. Executive Summary

On 2018-08-20, anomalous DNS query patterns were identified originating from multiple internal Windows endpoints. Investigation revealed that several hosts were generating DNS queries containing randomly generated subdomain strings against the `froth.ly` domain — a pattern consistent with DNS tunnelling or data exfiltration via DNS. The primary host of interest, `BSTOLL-L`, generated 21 unique subdomain queries against `froth.ly` including multiple entries with characteristics of encoded or randomly generated strings. DNS exfiltration is a technique frequently overlooked by perimeter controls as DNS traffic is rarely blocked outright, making it a reliable exfiltration channel for advanced threat actors.

---

## 2. Detection

**Initial Alert:** SPL Rule 03 — DNS Exfiltration Detection (T1048.003)

**Detection Query:**
```spl
index=botsv3 sourcetype="stream:dns"
| rex field=query "(?:[^.]+\.){1}(?P<domain>[^.]+\.[^.]+)$"
| stats count dc(query) as unique_subdomains by host, domain
| where unique_subdomains > 15
| sort -unique_subdomains
| table host, domain, unique_subdomains, count
```

The rule identifies hosts generating high volumes of unique subdomain queries against a single parent domain — the primary behavioural indicator of DNS-based exfiltration tooling.

---

## 3. Investigation

### 3.1 Identifying the Anomalous Domain

The investigation began by profiling DNS query patterns across all hosts to identify domains with unusually high unique subdomain counts.

**Query — Top domains by unique subdomain count:**
```spl
index=botsv3 sourcetype="stream:dns"
| rex field=query "(?:[^.]+\.){1}(?P<domain>[^.]+\.[^.]+)$"
| stats count dc(query) as unique_subdomains by domain
| where unique_subdomains > 20
| sort -unique_subdomains
```

`froth.ly` returned 6,034 total queries with 60 unique subdomains — significantly elevated compared to other domains and anomalous given that `froth.ly` is the victim organisation's own domain, not an external service.

### 3.2 Host Attribution

**Query — Per-host breakdown for froth.ly:**
```spl
index=botsv3 sourcetype="stream:dns"
| where match(query, "froth\.ly")
| stats count dc(query) as unique_subdomains by host
| sort -unique_subdomains
```

| Host | Total Queries | Unique Subdomains |
|------|--------------|------------------|
| BSTOLL-L | 553 | 21 |
| BTUN-L | 667 | 13 |
| FYODOR-L | 500 | 17 |
| ABUNGST-L | 373 | 16 |

`BSTOLL-L` was prioritised for investigation given the highest unique subdomain count relative to query volume.

### 3.3 Subdomain Analysis — BSTOLL-L

**Query — All froth.ly subdomains from BSTOLL-L:**
```spl
index=botsv3 sourcetype="stream:dns"
| where match(query, "froth\.ly") AND host="BSTOLL-L"
| stats count by query
| sort -count
```

Results revealed two distinct categories of subdomains:

**Legitimate subdomains:**
- `splunk.froth.ly` (436 queries) — Splunk infrastructure
- `wpad.froth.ly` (52 queries) — Web Proxy Auto-Discovery
- `sepmserver.froth.ly` (33 queries) — Symantec Endpoint Protection Manager
- `vpn.froth.ly` (6 queries) — VPN infrastructure

**Suspicious subdomains (randomly generated strings):**
- `bcemkuoyfkjb.froth.ly`
- `bhfcuibim.froth.ly`
- `cdonezmqixd.froth.ly`
- `cfegsjc.froth.ly`
- `dqwwjitbcykm.froth.ly`
- `iphmhqxocixjs.froth.ly`
- `nknhobjv.froth.ly`
- `rvhogmx.froth.ly`
- `yffrqrjdlrvmvea.froth.ly`
- `yiyieotucqytfkp.froth.ly`
- `zphaqhagqz.froth.ly`

The suspicious subdomains share common characteristics: lowercase alphabetic strings with no semantic meaning, lengths between 7-15 characters, and no corresponding DNS records that would indicate legitimate services. These are consistent with data encoded into DNS labels using Base32 or similar encoding schemes.

### 3.4 Temporal Pattern Analysis

**Query — DNS query timing from BSTOLL-L:**
```spl
index=botsv3 sourcetype="stream:dns"
| where match(query, "froth\.ly") AND host="BSTOLL-L"
| where match(query, "(?i)(bcemk|bhfcu|cdone|cfegs|dqwwj|iphm|nknho|rvhog|yffr|yiyie|zphaq)")
| table _time, query
| sort _time
```

Suspicious subdomain queries were distributed across the dataset timeframe rather than appearing in a single burst, suggesting a low-and-slow exfiltration approach designed to blend with legitimate DNS traffic volume.

### 3.5 Scope Assessment

**Query — All hosts generating suspicious froth.ly subdomains:**
```spl
index=botsv3 sourcetype="stream:dns"
| where match(query, "froth\.ly")
| rex field=query "^(?P<subdomain>[^.]+)\.froth\.ly"
| where len(subdomain) > 6 AND NOT subdomain IN ("splunk","wpad","sepmserver","vpn","tag","localdomain")
| stats count by host, query
| sort host
```

Multiple hosts including `FYODOR-L` and `ABUNGST-L` also generated suspicious subdomain patterns, suggesting either lateral spread of the exfiltration tool or a coordinated campaign across multiple compromised endpoints.

---

## 4. Timeline

| Time (UTC) | Event |
|------------|-------|
| 2018-08-20 (sustained) | Legitimate froth.ly DNS queries from multiple hosts |
| 2018-08-20 (interspersed) | Suspicious randomly-generated subdomain queries begin from BSTOLL-L |
| 2018-08-20 (sustained) | Low-and-slow exfiltration pattern continues across multiple hosts |

---

## 5. Findings

- **Multiple internal hosts** were generating DNS queries with randomly generated subdomain strings against `froth.ly`
- **BSTOLL-L** was the primary host of interest with 11 suspicious subdomain queries across 21 unique subdomains
- Suspicious subdomains exhibit characteristics consistent with **data encoded into DNS labels** for exfiltration
- The use of the **victim's own domain** (`froth.ly`) as the exfiltration channel is a deliberate technique to blend malicious traffic with legitimate internal DNS activity
- DNS exfiltration was conducted in a **low-and-slow pattern** to evade volume-based detection
- No standard perimeter control would block DNS to `froth.ly` as it is the organisation's own domain — making this a **defence evasion technique** as well

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Detail |
|-----------|----|--------|
| Exfiltration Over Alternative Protocol: DNS | T1048.003 | Data encoded into DNS subdomain labels |
| DNS | T1071.004 | Use of DNS protocol for C2 or data transfer |
| Obfuscated Files or Information | T1027 | Data encoded prior to exfiltration |

---

## 7. Recommendations

1. **Deploy DNS monitoring** — alert on hosts generating more than 10 unique subdomains against any single domain per hour
2. **Implement DNS sinkholes** — route internal DNS through an inspecting resolver capable of detecting tunnelling patterns
3. **Baseline DNS behaviour** — establish per-host DNS profiles; deviation from baseline (new domains, unusual subdomain patterns) should trigger alerts
4. **Investigate BSTOLL-L, FYODOR-L, ABUNGST-L** — identify the process generating suspicious DNS queries; likely malware with DNS tunnelling capability
5. **Review froth.ly DNS zone** — audit authoritative DNS server logs for query responses to the suspicious subdomains; the receiving end of the tunnel may be on infrastructure the organisation controls
6. **Consider DNS over HTTPS blocking** — if attacker pivots to DoH, traditional DNS monitoring is bypassed entirely

---

## 8. Artifacts

| Type | Value |
|------|-------|
| Primary host | BSTOLL-L |
| Secondary hosts | FYODOR-L, ABUNGST-L, BTUN-L |
| Exfiltration domain | froth.ly |
| Suspicious subdomains | bcemkuoyfkjb, bhfcuibim, cdonezmqixd, cfegsjc, dqwwjitbcykm, iphmhqxocixjs, nknhobjv, rvhogmx, yffrqrjdlrvmvea, yiyieotucqytfkp, zphaqhagqz |
| Detection method | Unique subdomain count anomaly |
