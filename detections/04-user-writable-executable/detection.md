# Executable Execution from a User-Writable Path

## Objective

Identify executable processes launched directly from user-writable locations such as Temp, Users\Public, or Downloads.

## Data Source

Sysmon Event ID 1 — Process Creation.

## Detection Logic

The detection identifies process creation where the executable image resides in a user-writable directory.

## Why It Matters

User-writable directories are commonly used to stage or execute dropped payloads. Execution from these locations is therefore a useful triage signal, but requires contextual investigation.

## Alerting

Real-time, per-result alert with Triggered Alerts and Log Event actions.

## Validation

Validated using controlled HomeSOC lab activity by executing a test executable from the user's Temp directory. The activity generated Sysmon telemetry and successfully triggered the Splunk detection.

## Analyst Checks

Review the executable path, command line, parent process, user, integrity level, file reputation, signature status, and subsequent process or network activity before escalation.

## ATT&CK Mapping

No direct ATT&CK technique is assigned to this detection. It is a behavioral detection that can support investigation of multiple execution or payload-staging techniques.
