# MITRE ATT&CK Coverage

## Detection Coverage

| # | HomeSOC Detection | ATT&CK Technique | ID | Why It Is Relevant |
|---|---|---|---|---|
| 01 | PowerShell Encoded Command Execution | Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Detects PowerShell execution using `-EncodedCommand`, a common indicator of command obfuscation. |
| 02 | Suspicious Rundll32 Execution from User-Writable Path | System Binary Proxy Execution: Rundll32 | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Detects `rundll32.exe` being used to reference DLL content from a user-writable location. |
| 03 | Suspicious Run Key Persistence to User-Writable Path | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Detects Run-key persistence configured to launch an executable from a user-writable location. |
| 04 | Executable Execution from User-Writable Path | Behavioral detection — no direct ATT&CK mapping | — | Detects execution of an executable from a user-writable directory and requires analyst validation. |

## Coverage Summary

**Techniques covered:** 3  
**Behavioral detections:** 1  
**Telemetry:** Sysmon  
**Primary data source:** Windows endpoint process and registry activity  
**Validation:** Controlled lab activity  
**Alerting:** Splunk real-time, per-result alerts

## Analyst Note

ATT&CK mapping identifies the adversary behavior represented by a detection; a matching event is not, by itself, proof of malicious activity. Analysts must validate execution context, parent-child relationships, user context, artifacts, and follow-on activity before escalation.