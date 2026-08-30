# Suspicious Run Key Persistence from a User-Writable Path

## Objective

Identify Windows Run and RunOnce registry modifications that reference executable or script payloads stored in user-writable locations.

## Data Source

Sysmon Event ID 13 — Registry Value Set.

## Alert Search

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search (TargetObject="*\\CurrentVersion\\Run\\*" OR TargetObject="*\\CurrentVersion\\RunOnce\\*")
| search Details="*\\AppData\\*" OR Details="*\\Temp\\*" OR Details="*\\Users\\Public\\*" OR Details="*\\Downloads\\*"
```

## Detection Development

The initial validation search targeted the test value `HomeSOCDiffTest2`, which was useful for confirming the observed registry event but was too specific for a reusable detection. The rule was generalized to detect Run and RunOnce modifications that reference payloads in selected user-writable locations.

The generalized rule was then independently validated with a new registry value, `HomeSOCQA`, pointing to a Temp executable. The generic rule matched the new event and the Splunk alert triggered successfully.

## Triage Search

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| search (TargetObject="*\\CurrentVersion\\Run\\*" OR TargetObject="*\\CurrentVersion\\RunOnce\\*")
| search Details="*\\AppData\\*" OR Details="*\\Temp\\*" OR Details="*\\Users\\Public\\*" OR Details="*\\Downloads\\*"
| table _time host Image TargetObject Details User
| sort - _time
```

## Why It Matters

Run and RunOnce keys are common persistence mechanisms. A startup value pointing to a user-writable location warrants investigation.

## Alerting

Real-time, per-result alert with Triggered Alerts and Log Event actions.

## Validation

Validated using controlled HomeSOC lab activity by creating a Run key that referenced an executable in the user's Temp directory. The generic detection matched the resulting Sysmon event and successfully triggered the Splunk alert.

## Scope

This analytic focuses on Run and RunOnce registry values that reference selected user-writable locations. It does not identify every persistence mechanism or every possible Run Key configuration.

## Known False Positives

Legitimate applications may create startup entries under user-writable locations. Software installers, updaters, virtualization tools, and other application startup components should be considered during triage.

## Analyst Checks

Review the registry target, payload path, writing process, user context, file reputation, signature status, and subsequent execution before escalation.

## ATT&CK Mapping

T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
