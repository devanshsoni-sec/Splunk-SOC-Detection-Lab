# PowerShell Encoded Command Execution

## Objective

Identify PowerShell process creation containing the `-EncodedCommand` parameter.

## Data Source

Sysmon Event ID 1 — Process Creation.

## Alert Search

```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") CommandLine="*-EncodedCommand*"
```

## Triage Search

```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") CommandLine="*-EncodedCommand*"
| table _time host Image CommandLine ParentImage ParentCommandLine User IntegrityLevel ProcessId ParentProcessId
| sort - _time
```

## Why It Matters

Encoded PowerShell commands can conceal command content and warrant investigation for possible obfuscation or malicious execution.

## Alerting

Real-time, per-result alert with Triggered Alerts and Log Event actions.

## Validation

Validated using controlled HomeSOC lab activity. The test command decoded to:

`Write-Output "HomeSOC Detection Test"`

The resulting Sysmon process event successfully triggered the Splunk alert.

## Scope

This analytic detects direct PowerShell invocations containing `-EncodedCommand`. It does not detect all forms of PowerShell obfuscation or alternate execution methods.

## Analyst Checks

Review the decoded command, parent-child process relationship, user, integrity level, follow-on file activity, and network activity before escalation.

## ATT&CK Mapping

T1059.001 — PowerShell
