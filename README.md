# SOC Analyst Incident Investigation Lab

## Overview
Personal SOC lab simulating a real multi-stage cyberattack and full investigation workflow using Splunk SIEM, MITRE ATT&CK framework, Wireshark network analysis, and Python threat intelligence automation.

## Lab Architecture
- **Attacker/Monitor:** Kali Linux ARM64 (192.168.64.18) — Wireshark, Python scripts
- **Target/SIEM:** Windows 11 ARM64 (192.168.64.20) — Splunk Enterprise 10.4.0
- **Host:** MacBook Pro M3 — UTM Virtualization (Shared Network)

## Tools Used
- Splunk Enterprise 10.4.0 (SIEM)
- Windows Security Event Log + Auditpol advanced audit
- Wireshark 4.6.6 (network capture)
- Python 3.13 (threat intel automation)
- AbuseIPDB API + AlienVault OTX API

## MITRE ATT&CK Techniques Simulated

| Technique ID | Name | Tactic | Detection Event |
|---|---|---|---|
| T1059.001 | PowerShell Execution | Execution | EventID 4688 |
| T1018 | Remote System Discovery | Discovery | EventID 4688 |
| T1110 | Brute Force | Credential Access | EventID 4625 |
| T1053.005 | Scheduled Task | Persistence | EventID 4698 |
| T1078 | Valid Accounts | Privilege Escalation | EventID 4720 |

## Repository Structure
- `setup/` — Lab configuration files
- `detection/` — Splunk SPL detection queries
- `threat-intel/` — Python enrichment script and results
- `network-analysis/` — Wireshark captures
- `attack-scenarios/` — Attack simulation documentation
- `evidence/` — Screenshots and Splunk exports
- `report/` — Final incident report (PDF)

## Skills Demonstrated
SIEM | Log Analysis | Threat Detection | MITRE ATT&CK | Incident Response | Python Scripting | Network Analysis | Threat Intelligence

## Analyst
Cristian Benjamín Albuja Izurieta
[LinkedIn](https://linkedin.com/in/cristian-albuja-izurieta) | [GitHub](https://github.com/Calbuja)
