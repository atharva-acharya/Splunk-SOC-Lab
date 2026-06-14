# SPL Rule 04 — Suspicious LOLBin Execution (WMIC + reg.exe)
**MITRE ATT&CK:** T1059.003 — Command and Scripting Interpreter: Windows Command Shell  
**Secondary:** T1112 — Modify Registry  
**Severity:** Medium  
**Sourcetype:** wineventlog:security (EventCode 4688)  
**Index:** botsv3  

## Detection Logic
```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688
| where New_Process_Name IN (
    "C:\\Windows\\System32\\wbem\\WMIC.exe",
    "C:\\Windows\\System32\\reg.exe",
    "C:\\Windows\\System32\\cmd.exe"
  )
| bucket _time span=5m
| stats dc(New_Process_Name) as distinct_tools count by _time, host
| where distinct_tools >= 2
| sort -count
| table _time, host, distinct_tools, count
```

## Rule Rationale
Detects hosts launching multiple living-off-the-land binaries (LOLBins) within 
a 5-minute window. WMIC.exe and reg.exe are legitimate Windows tools routinely 
abused by attackers for lateral movement, persistence, and defence evasion. 
A single host executing two or more of these tools within 5 minutes is 
statistically anomalous and warrants investigation. Individual execution is 
noise — combined execution in a tight window is signal.

## LOLBin Abuse Context
- WMIC.exe: Remote execution, process creation, AV enumeration
- reg.exe: Persistence via Run keys, disabling security controls
- cmd.exe: Script execution, chaining of above tools

## Response Actions
1. Identify the parent process that spawned WMIC/reg.exe
2. Review full process tree on affected host
3. Check registry Run keys for persistence mechanisms
4. Correlate with network connections from same host at same time
5. Determine if execution was interactive or scheduled task