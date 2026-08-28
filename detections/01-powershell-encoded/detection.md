# PowerShell Encoded Command Execution

## Objective

Identify PowerShell process creation events containing the `-EncodedCommand` parameter.

## Data Source

Sysmon Event ID 1, Process Creation.

## Detection Logic

The rule searches PowerShell process creation telemetry for the `-EncodedCommand` parameter and retains process context for triage.

## Why It Matters

Encoded PowerShell commands can conceal command content and should be investigated for possible command obfuscation.

## Alerting

Real-time, per-result alert with Triggered Alerts and Log Event actions.

## Validation

Validated using controlled HomeSOC lab activity. The test generated Sysmon process telemetry and successfully triggered the Splunk alert.

## ATT&CK

T1059.001 — PowerShell

## Analyst Checks

Review the command line, parent-child process relationship, user, integrity level, follow-on activity, and network activity before escalation.
