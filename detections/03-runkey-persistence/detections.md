# Suspicious Run Key Persistence from a User-Writable Path

## Objective

Identify Windows Run/RunOnce persistence that points to an executable or script stored in a user-writable location.

## Data Source

- Sysmon Event IDs 12, 13, 14 — Registry Activity
- Windows endpoint telemetry collected in Splunk

## Detection Logic

The rule looks for Run/RunOnce registry activity and then filters for payload paths under locations such as AppData, Temp, Users\Public, or Downloads.

## Why It Matters

Registry Run keys are a common persistence mechanism. A Run-key value referencing a payload from a user-writable directory warrants investigation.

## Alerting

- Type: Real-time
- Trigger: Per Result
- Severity: Medium
- Actions: Triggered Alerts + Log Event

## Validation

Validated using controlled HomeSOC lab activity that created a Run key pointing to an executable in the user's Temp directory. The detection successfully generated the corresponding Splunk alert.

## ATT&CK

T1547.001 — Registry Run Keys / Startup Folder

## Analyst Checks

Review the registry key, payload path, writing process, user context, executable/script reputation, parent-child activity, and any subsequent execution before escalation.