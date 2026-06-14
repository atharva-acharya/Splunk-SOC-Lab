# SPL Rule 01 — Web Reconnaissance / Scanning
**MITRE ATT&CK:** T1595.002 — Active Scanning: Vulnerability Scanning  
**Severity:** Medium  
**Sourcetype:** stream:http  
**Index:** botsv3  

## Detection Logic
```spl
index=botsv3 sourcetype="stream:http"
| stats count as request_count dc(uri_path) as unique_paths by src_ip
| where request_count > 100 AND unique_paths > 10
| sort -request_count
| table src_ip, request_count, unique_paths
```

## Rule Rationale
Detects hosts generating high volumes of HTTP requests across a large number of 
unique URI paths within the dataset timeframe. A single source IP hitting 100+ 
endpoints across 10+ unique paths is consistent with automated scanning tools 
such as Nikto, Nessus, or Burp Suite.

## Threshold Justification
- request_count > 100: Eliminates normal browsing behaviour
- unique_paths > 10: Distinguishes scanners from high-volume single-resource requests

## Key Indicators
| src_ip | request_count | unique_paths |
|--------|--------------|--------------|
| 192.168.3.130 | 2207 | 1023 |
| 91.207.175.249 | 839 | 45 |
| 172.16.197.137 | 752 | 425 |

## Response Actions
1. Identify asset at src_ip
2. Correlate with firewall/IDS logs for same source
3. Check for subsequent exploitation attempts from same IP
4. Block source IP if confirmed malicious