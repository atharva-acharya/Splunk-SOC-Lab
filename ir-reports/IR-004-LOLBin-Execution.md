# IR-004 — LOLBin Execution: WMIC and reg.exe Abuse

| Field | Detail |
|-------|--------|
| **Incident ID** | IR-004 |
| **Date** | 2018-08-20 |
| **Severity** | Medium |
| **Status** | Closed |
| **MITRE ATT&CK** | T1059.003 — Windows Command Shell, T1112 — Modify Registry |
| **Analyst** | Atharva Acharya |
| **Dataset** | BOTS v3 (index=botsv3) |

---

## 1. Executive Summary

On 2018-08-20, Windows Security event logs captured elevated execution of living-off-the-land binaries (LOLBins) across multiple internal Windows hosts. Analysis of EventCode 4688 (process creation) identified `WMIC.exe` and `reg.exe` executing in close temporal proximity on the same hosts — a pattern inconsistent with normal user behaviour and consistent with attacker use of built-in Windows tools to evade endpoint detection. LOLBin abuse is a primary technique used by threat actors to avoid triggering antivirus and EDR solutions, as these tools are signed Microsoft binaries with legitimate uses. Detection requires behavioural baselining rather than signature-based approaches.

---

## 2. Detection

**Initial Alert:** SPL Rule 04 — Suspicious LOLBin Execution (T1059.003)

**Detection Query:**
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

The rule detected multiple hosts executing two or more LOLBins within a 5-minute window — a statistically anomalous pattern that warrants investigation.

---

## 3. Investigation

### 3.1 LOLBin Execution Volume Baseline

The investigation began by establishing the overall execution profile of high-risk binaries across the dataset.

**Query — Process execution counts by binary:**
```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688
| stats count by New_Process_Name
| sort -count
| head 15
```

Key findings:
- `cmd.exe`: 1,091 executions — too noisy for standalone detection
- `WMIC.exe`: 536 executions — elevated; legitimate WMIC usage is typically low frequency
- `reg.exe`: 523 executions — elevated; interactive registry modification is uncommon in normal operations

### 3.2 Host-Level Analysis

**Query — Hosts with both WMIC and reg.exe execution:**
```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688
| where New_Process_Name IN (
    "C:\\Windows\\System32\\wbem\\WMIC.exe",
    "C:\\Windows\\System32\\reg.exe"
  )
| stats dc(New_Process_Name) as tool_count values(New_Process_Name) as tools by host
| where tool_count >= 2
```

Multiple hosts were identified executing both binaries, narrowing the scope of investigation to those with the tightest temporal correlation between executions.

### 3.3 Process Lineage Investigation

**Query — Parent processes spawning LOLBins:**
```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688
| where New_Process_Name IN (
    "C:\\Windows\\System32\\wbem\\WMIC.exe",
    "C:\\Windows\\System32\\reg.exe"
  )
| stats count by Creator_Process_Name, New_Process_Name
| sort -count
```

Parent process analysis is critical for LOLBin investigations — `WMIC.exe` spawned by `explorer.exe` is likely a user action; `WMIC.exe` spawned by `cmd.exe` which was itself spawned by a suspicious parent is a different risk profile entirely.

### 3.4 WMIC Abuse Context

`WMIC.exe` is abused by threat actors for multiple purposes within the BOTS v3 attack scenario:

- **Remote execution:** `wmic /node: process call create` — execute processes on remote hosts
- **AV enumeration:** `wmic /namespace:\\root\securitycenter2 path antivirusproduct` — identify installed security products
- **System information gathering:** `wmic os get caption` — enumerate OS details
- **Process listing:** `wmic process list brief` — identify running processes and security tools

### 3.5 reg.exe Abuse Context

`reg.exe` command-line registry manipulation is commonly used for:

- **Persistence:** Adding entries to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Defence evasion:** Disabling Windows Defender via registry keys
- **Credential access:** Querying SAM hive for password hashes
- **Configuration tampering:** Modifying security tool registry settings

**Query — Registry activity correlation:**
```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688
| where New_Process_Name="C:\\Windows\\System32\\reg.exe"
| table _time, host, Process_Command_Line
| sort _time
```

---

## 4. Timeline

| Time (UTC) | Event |
|------------|-------|
| 2018-08-20 (multiple) | cmd.exe executions across multiple hosts |
| 2018-08-20 (multiple) | WMIC.exe executions — 536 total across dataset |
| 2018-08-20 (multiple) | reg.exe executions — 523 total across dataset |
| 2018-08-20 (multiple) | Co-execution of multiple LOLBins on same hosts within 5-minute windows |

---

## 5. Findings

- **WMIC.exe** (536 executions) and **reg.exe** (523 executions) were executed at elevated frequency across the dataset
- Multiple hosts exhibited **co-execution** of two or more LOLBins within 5-minute windows — anomalous versus normal administrative baselines
- LOLBin usage is consistent with **post-exploitation activity** — an attacker who has gained initial access using signed Windows tools to avoid triggering AV/EDR
- The volume of `cmd.exe` execution (1,091) suggests **scripted or automated activity** rather than interactive user sessions
- Without process command line logging enabled, full attribution of LOLBin activity to specific attacker commands is limited — this represents a **detection visibility gap**

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Detail |
|-----------|----|--------|
| Windows Command Shell | T1059.003 | cmd.exe used to chain LOLBin execution |
| Windows Management Instrumentation | T1047 | WMIC.exe for remote execution and enumeration |
| Modify Registry | T1112 | reg.exe for persistence and defence evasion |
| Masquerading | T1036 | Use of signed Microsoft binaries to evade detection |

---

## 7. Recommendations

1. **Enable process command line logging** — EventCode 4688 without command line parameters provides limited forensic value; enable via Group Policy: `Computer Configuration > Administrative Templates > System > Audit Process Creation`
2. **Deploy Sysmon** — EventID 1 with full command line and parent process tracking provides significantly richer LOLBin detection capability
3. **Baseline LOLBin execution** — establish per-host and per-user execution profiles for WMIC, reg.exe, and cmd.exe; alert on deviation
4. **Alert on WMIC remote execution** — any `wmic /node:` invocation targeting a remote host should trigger an alert
5. **Monitor reg.exe Run key modification** — autorun key modifications via reg.exe should be treated as high priority
6. **Consider AppLocker/WDAC policies** — restrict WMIC.exe execution to administrators only in environments where user access is not required

---

## 8. Artifacts

| Type | Value |
|------|-------|
| Suspicious binaries | C:\Windows\System32\wbem\WMIC.exe |
| Suspicious binaries | C:\Windows\System32\reg.exe |
| Suspicious binaries | C:\Windows\System32\cmd.exe |
| Event source | wineventlog:security (EventCode 4688) |
| Detection method | Co-execution of multiple LOLBins within 5-minute window |
| Visibility gap | Process command line parameters not captured in this dataset |
