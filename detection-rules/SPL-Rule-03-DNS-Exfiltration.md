# SPL Rule 03 — DNS Exfiltration Detection
**MITRE ATT&CK:** T1048.003 — Exfiltration Over Alternative Protocol: DNS  
**Severity:** High  
**Sourcetype:** stream:dns  
**Index:** botsv3  

## Detection Logic
```spl
index=botsv3 sourcetype="stream:dns"
| rex field=query "(?:[^.]+\.){1}(?P<domain>[^.]+\.[^.]+)$"
| stats count dc(query) as unique_subdomains by host, domain
| where unique_subdomains > 15
| sort -unique_subdomains
| table host, domain, unique_subdomains, count
```

## Rule Rationale
Detects potential DNS exfiltration by identifying hosts generating high volumes 
of unique subdomain queries against a single parent domain. Legitimate services 
resolve a small set of known subdomains. An endpoint querying 15+ unique 
subdomains against one domain — particularly with randomly generated names — 
is consistent with data being encoded into DNS queries for exfiltration.

## Threshold Justification
- unique_subdomains > 15: Eliminates legitimate CDN and cloud service DNS 
  patterns while catching exfiltration tools that generate unique per-query 
  subdomains

## Key Indicators (BSTOLL-L)
| Query | Assessment |
|-------|-----------|
| splunk.froth.ly | Legitimate |
| wpad.froth.ly | Legitimate (WPAD autoconfiguration) |
| bcemkuoyfkjb.froth.ly | Suspicious — random string |
| yffrqrjdlrvmvea.froth.ly | Suspicious — random string |
| yiyieotucqytfkp.froth.ly | Suspicious — random string |

## Response Actions
1. Capture and decode subdomain strings for exfiltrated data
2. Identify process on BSTOLL-L generating DNS queries
3. Check volume and timing of queries for automated tool signature
4. Block outbound DNS to froth.ly subdomains at perimeter
5. Investigate BSTOLL-L for malware or compromised credentials