# Suspicious Rundll32 Execution from User-Writable Path

## Objective

Identify rundll32.exe executions that reference DLL content from user-writable locations.

## Data Source

- Sysmon Event ID 1 — Process Creation
- Windows endpoint telemetry collected in Splunk

## Detection Logic

The rule identifies `rundll32.exe` process creation and filters for command lines referencing AppData, Temp, or other user-writable locations.

## Why It Matters

Rundll32 is a Windows signed binary that can be abused to proxy execution of DLL content. A user-writable DLL path increases investigation priority.

## Alerting

- Type: Real-time
- Trigger: Per Result
- Severity: Medium
- Actions: Triggered Alerts + Log Event

## Validation

Validated using controlled HomeSOC lab activity referencing a DLL from the user's Temp directory. The detection successfully generated the corresponding Splunk alert.

## ATT&CK

T1218.011 — System Binary Proxy Execution: Rundll32

## Analyst Checks

Review the DLL path, parent process, command line, user, integrity level, file reputation, signature status, and network activity before escalation.