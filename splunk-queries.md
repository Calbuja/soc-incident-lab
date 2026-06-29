# Splunk Detection Queries — SOC Incident Lab

## Index: win_logs | Time Range: June 27-28, 2026

---

### T1059.001 — PowerShell Execution with Evasion Flags
**Severity:** HIGH  
**MITRE Tactic:** Execution

```spl
index=win_logs EventCode=4688
| search CommandLine="*powershell*" OR CommandLine="*-nop*" OR CommandLine="*-w hidden*"
| table _time, NewProcessName, CommandLine
| sort -_time
```

**False Positives:** Legitimate admin scripts using PowerShell with execution policy bypass.

---

### T1110 — Brute Force / Multiple Failed Logons
**Severity:** HIGH  
**MITRE Tactic:** Credential Access

```spl
index=win_logs EventCode=4625
| stats count by TargetUserName, IpAddress
| where count > 3
| sort -count
```

**False Positives:** Users forgetting passwords, expired credentials.

---

### T1053.005 — Scheduled Task Creation
**Severity:** HIGH  
**MITRE Tactic:** Persistence

```spl
index=win_logs EventCode=4698
| table _time, TaskName, TaskContent
| sort -_time
```

**False Positives:** Legitimate software installers creating scheduled tasks.

---

### T1078 — New User Account Creation
**Severity:** CRITICAL  
**MITRE Tactic:** Privilege Escalation

```spl
index=win_logs EventCode=4720
| table _time, TargetUserName, SubjectUserName
| sort -_time
```

**False Positives:** IT administrators creating new accounts during onboarding.

---

### T1018 — Network Discovery Commands
**Severity:** MEDIUM  
**MITRE Tactic:** Discovery

```spl
index=win_logs EventCode=4688
| search CommandLine="*arp*" OR CommandLine="*ipconfig*" OR CommandLine="*net view*"
| table _time, CommandLine
| sort -_time
```

**False Positives:** Network administrators running legitimate diagnostics.
