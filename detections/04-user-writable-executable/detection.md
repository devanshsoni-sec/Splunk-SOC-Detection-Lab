# Executable Execution from a User-Writable Path

## Objective

Identify executable process execution from user-writable locations such as Temp, Users\Public, or Downloads.

## Data Source

- Sysmon Event ID 1 — Process Creation
- Windows endpoint telemetry collected in Splunk

## Detection Logic

The rule identifies process creation where the executable image resides in a user-writable directory.

## Why It Matters

User-writable directories can be abused to stage and execute dropped payloads. Execution from these locations warrants analyst validation.

## Alerting

- Type: Real-time
- Trigger: Per Result
- Severity: Medium
- Actions: Triggered Alerts + Log Event

## Validation

Validated using controlled HomeSOC lab activity executing a test executable from the user's Temp directory. The detection successfully generated the corresponding Splunk alert.

## ATT&CK

T1204.002 — User Execution: Malicious File

## Analyst Checks

Review the executable path, command line, parent process, user, integrity level, file reputation, signature status, and subsequent process or network activity before escalation.