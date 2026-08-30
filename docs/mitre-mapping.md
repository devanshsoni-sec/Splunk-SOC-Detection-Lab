# MITRE ATT&CK Coverage

## Detection Coverage

| # | HomeSOC Detection | ATT&CK Mapping | Why It Is Relevant |
|---|---|---|---|
| 01 | PowerShell Encoded Command Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell; [T1027.010](https://attack.mitre.org/techniques/T1027/010/) Command Obfuscation | Detects PowerShell execution using encoded command parameters and associated command obfuscation. |
| 02 | Suspicious Rundll32 Execution from User-Writable Path | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) System Binary Proxy Execution: Rundll32 | Detects `rundll32.exe` executions referencing DLL content from selected user-writable locations. |
| 03 | Suspicious Run Key Persistence to User-Writable Path | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Registry Run Keys / Startup Folder | Detects Run and RunOnce registry values referencing payloads from selected user-writable locations. |
| 04 | Executable Execution from User-Writable Path | No direct ATT&CK mapping | Detects executable execution from selected user-writable locations and provides a behavioral triage signal. |

## Coverage Summary

**ATT&CK techniques covered:** 4  
**Behavioral detections without a direct mapping:** 1  
**Telemetry:** Sysmon  
**Primary data source:** Windows endpoint process and registry activity  
**Validation:** Controlled lab activity  
**Alerting:** Splunk real-time, per-result alerts

## Analyst Note

ATT&CK mappings describe the behavior represented by a detection; a matching event does not by itself establish malicious activity. Analysts should validate execution context, parent-child relationships, user context, artifacts, and follow-on activity before escalation.
