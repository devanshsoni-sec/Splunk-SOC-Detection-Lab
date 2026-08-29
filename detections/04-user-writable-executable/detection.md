# Executable Execution from a User-Writable Path

## Objective

Identify executable processes launched directly from user-writable locations such as Temp, Users\Public, or Downloads.

## Data Source

Sysmon Event ID 1 — Process Creation.

## Alert Search

```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\Temp\\*.exe" OR Image="*\\Users\\Public\\*.exe" OR Image="*\\Downloads\\*.exe"
```

## Triage Search

```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\Temp\\*.exe" OR Image="*\\Users\\Public\\*.exe" OR Image="*\\Downloads\\*.exe"
| table _time host Image OriginalFileName CommandLine ParentImage ParentCommandLine User IntegrityLevel ProcessId ParentProcessId
| sort - _time
```

## Why It Matters

User-writable directories can be used to stage or launch dropped executables. Execution from these locations is therefore a useful triage signal, but requires contextual investigation.

## Alerting

Real-time, per-result alert with Triggered Alerts and Log Event actions.

## Validation

Validated using controlled HomeSOC lab activity by executing a test executable from the user's Temp directory. The activity generated Sysmon telemetry and successfully triggered the Splunk detection.

## Scope

This analytic detects executable process creation from selected user-writable locations. It is a behavioral triage rule and does not by itself establish malicious execution.

## Analyst Checks

Review the executable path, original filename, command line, parent-child process relationship, user, integrity level, file reputation, signature status, and subsequent process or network activity before escalation.

## ATT&CK Mapping

No direct ATT&CK technique is assigned. This is a behavioral triage rule that can support investigation of multiple techniques rather than map one-to-one to a single technique.
