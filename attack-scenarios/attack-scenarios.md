# Attack Scenarios — MITRE ATT&CK Simulations

## Environment
- **Attacker:** Kali Linux ARM64 (192.168.64.18)
- **Target:** Windows 11 ARM64 (192.168.64.20)
- **Date:** June 27-28, 2026

---

## T1059.001 — PowerShell Execution
**Tactic:** Execution  
**Command simulated:**
powershell -nop -w hidden -c "Write-Host 'Simulated attack T1059.001'"

**Logs generated:** EventID 4688 (New Process Created)  
**Detection:** Splunk query on CommandLine containing -nop and -w hidden flags

---

## T1018 — Remote System Discovery
**Tactic:** Discovery  
**Commands simulated:**
net view /all
arp -a
ipconfig /all

**Logs generated:** EventID 4688  
**Detection:** Splunk query on recon command keywords

---

## T1110 — Brute Force
**Tactic:** Credential Access  
**Command simulated:**
net use \\localhost\IPC$ /user:fakeuser wrongpassword (x5)

**Logs generated:** EventID 4625 (Failed Logon)  
**Detection:** Splunk stats count > 3 failed logons per user

---

## T1053.005 — Scheduled Task
**Tactic:** Persistence  
**Command simulated:**
schtasks /create /tn "WindowsUpdateHelper" /tr "powershell.exe -nop -w hidden -c Write-Host Persistence" /sc onlogon /ru System /f

**Logs generated:** EventID 4698 (Scheduled Task Created)  
**Detection:** Splunk query on EventCode 4698

---

## T1078 — Valid Accounts
**Tactic:** Privilege Escalation  
**Commands simulated:**
net user attacker P@ssw0rd123 /add
net localgroup administrators attacker /add

**Logs generated:** EventID 4720 (User Account Created)  
**Detection:** Splunk query on EventCode 4720
