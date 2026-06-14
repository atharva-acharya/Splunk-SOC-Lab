# SPL Rule 05 — AWS Instance Metadata Service (IMDS) Abuse
**MITRE ATT&CK:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API  
**Severity:** Critical  
**Sourcetype:** stream:http  
**Index:** botsv3  

## Detection Logic
```spl
index=botsv3 sourcetype="stream:http" dest_ip="169.254.169.254"
| where match(uri_path, "(?i)(iam/security-credentials|user-data|instance-id)")
| stats count by src_ip, uri_path, status
| where status=200
| sort -count
| table src_ip, uri_path, status, count
```

## Rule Rationale
Detects successful queries to the AWS Instance Metadata Service (IMDS) 
169.254.169.254 targeting IAM credentials or sensitive instance data. 
The metadata endpoint is only accessible from within the instance — external 
access indicates SSRF exploitation or a compromised internal host. Successful 
retrieval of iam/security-credentials returns temporary AWS access keys that 
can be used to pivot across the entire AWS environment.

## Real-World Context
This technique was used in the Capital One breach (2019) where an attacker 
exploited an SSRF vulnerability to query the metadata API and retrieve IAM 
credentials, ultimately exfiltrating 100M+ customer records.

## Key Indicators
| src_ip | uri_path | status | count |
|--------|----------|--------|-------|
| 172.31.12.76 | /latest/meta-data/iam/security-credentials/EC2InstanceRole | 200 | 32 |
| 172.16.0.178 | /latest/meta-data/iam/security-credentials/EC2InstanceRole | 200 | 17 |

## Response Actions
1. Immediately rotate all IAM credentials associated with EC2InstanceRole
2. Review CloudTrail for API calls made using the stolen credentials
3. Identify how 172.31.12.76 gained access to the metadata endpoint
4. Check for SSRF vulnerability in applications running on affected instances
5. Enforce IMDSv2 across all EC2 instances to block unauthenticated metadata access