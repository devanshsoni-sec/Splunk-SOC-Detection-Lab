# Suspicious Run Key Persistence from a User-Writable Path

## Objective

Identify Windows Run and RunOnce registry modifications that reference executable or script payloads stored in user-writable locations.

## Data Source

Sysmon Event ID 13 — Registry Value Set.

## Detection Logic

The detection identifies Run and RunOnce registry value modifications and filters for payload paths under locations such as AppData, Temp, Users\Public, or Downloads.

## Why It Matters

Run and RunOnce keys are common persistence mechanisms. A startup value pointing to a user-writable location warrants investigation.

## Alerting

Real-time, per-result alert with Triggered Alerts and Log Event actions.

## Validation

Validated using controlled HomeSOC lab activity by creating a Run key that referenced an executable in the user's Temp directory. The generic detection matched the resulting Sysmon event and successfully triggered the Splunk alert.

## Analyst Checks

Review the registry target, payload path, writing process, user context, file reputation, signature status, and subsequent execution before escalation.

## ATT&CK Mapping

T1547.001 — Registry Run Keys / Startup Folder
