# Suspicious Rundll32 Execution from a User-Writable Path

## Objective

Identify `rundll32.exe` executions that reference DLL content from user-writable locations.

## Data Source

Sysmon Event ID 1 — Process Creation.

## Alert Search

```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\rundll32.exe"
| search CommandLine="*\\AppData\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*\\Users\\Public\\*"
```

## Triage Search

```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\rundll32.exe"
| search CommandLine="*\\AppData\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*\\Users\\Public\\*"
| table _time host Image CommandLine ParentImage ParentCommandLine User IntegrityLevel ProcessId ParentProcessId
| sort - _time
```

## Why It Matters

Rundll32 is a legitimate Windows binary that can be abused to proxy DLL execution. A DLL reference from a user-writable location warrants investigation.

## Alerting

Real-time, per-result alert with Triggered Alerts and Log Event actions.

## Validation

Validated using controlled HomeSOC lab activity with a Rundll32 invocation referencing a DLL path under the user's Temp directory. The Sysmon process event matched the analytic and triggered the Splunk alert.

The referenced DLL was intentionally non-existent, so the test validated detection of the suspicious invocation and path, not successful DLL loading or execution.

## Scope

This analytic focuses on Rundll32 executions whose command line references selected user-writable locations. It does not identify every possible Rundll32 abuse technique.

## Analyst Checks

Review the DLL path, command line, parent-child process relationship, user, integrity level, file existence and reputation, signature status, and relevant network or module-load telemetry when available.

## ATT&CK Mapping

T1218.011 — System Binary Proxy Execution: Rundll32
