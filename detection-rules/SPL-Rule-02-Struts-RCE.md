# SPL Rule 02 — Apache Struts RCE Detection (CVE-2017-9805)
**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application  
**CVE:** CVE-2017-9805 (Apache Struts REST Plugin RCE)  
**Severity:** Critical  
**Sourcetype:** stream:http  
**Index:** botsv3  

## Detection Logic
```spl
index=botsv3 sourcetype="stream:http"
| where match(form_data, "(?i)(ognl|OgnlContext|ProcessBuilder|Runtime\.exec|cmd=)")
| stats count by src_ip, dest_ip, uri_path
| sort -count
| table src_ip, dest_ip, uri_path, count
```

## Rule Rationale
Detects exploitation of CVE-2017-9805 via OGNL expression injection in Apache 
Struts REST plugin. Attackers inject Java OGNL expressions into HTTP POST 
form_data to achieve unauthenticated remote code execution. The presence of 
OgnlContext, ProcessBuilder, or Runtime.exec in POST body is not legitimate 
application behaviour under any circumstance.

## Attack Chain Observed (192.168.8.103)
| Time | Command Executed |
|------|-----------------|
| 12:05:43 | id |
| 12:06:02 | groups |
| 12:06:39 | cat /etc/passwd |
| 12:07:04 | useradd -ou 0 (backdoor root user) |
| 12:07:28 | uname -a |
| 12:08:37 | echo base64 kernel exploit to /tmp/colonel |
| 12:10:56 | base64 --decode /tmp/colonel > /tmp/colonel.c |
| 12:13:57 | reverse shell to 45.77.53.176:8088 |

## Indicators of Compromise
- Attacker IP: 192.168.8.103
- C2 IP: 45.77.53.176:8088
- Target: 192.168.9.30 (/frothlyinventory/integration/saveGangster.action)
- Backdoor user created: tomcat7 (UID 0)
- Kernel