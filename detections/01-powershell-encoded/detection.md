# PowerShell Encoded Command Execution

## Objective

Identify PowerShell process creation using encoded-command parameters.

## Data Source

Sysmon Event ID 1 — Process Creation.

## Alert Search

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| regex CommandLine="(?i)\s-(?:e|ec|enc|encodedcommand)\b\s+[A-Za-z0-9+/=]{20,}"
```

## Triage Search

```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| regex CommandLine="(?i)\s-(?:e|ec|enc|encodedcommand)\b\s+[A-Za-z0-9+/=]{20,}"
| table _time host Image CommandLine ParentImage ParentCommandLine User IntegrityLevel ProcessId ParentProcessId
| sort - _time
```

## Why It Matters

Encoded PowerShell commands can conceal command content and warrant investigation for possible obfuscation or malicious execution. MITRE identifies PowerShell execution as T1059.001 and command obfuscation as T1027.010. :contentReference[oaicite:1]{index=1}

## Alerting

Real-time, per-result alert with Triggered Alerts and Log Event actions.

## Validation

Validated using controlled HomeSOC lab activity with encoded PowerShell commands. Both the full `-EncodedCommand` form and the abbreviated `-enc` form generated Sysmon Event ID 1 telemetry and matched the improved detection logic.

The decoded test command was:

`Write-Output "HomeSOC Encoded Test"`

The resulting Sysmon events successfully triggered the Splunk alert.

## Scope

This analytic detects direct PowerShell invocations using selected encoded-command parameter forms: `-e`, `-ec`, `-enc`, and `-EncodedCommand`.

It does not detect all forms of PowerShell obfuscation, encoded content used outside these parameters, or indirect PowerShell execution through other interfaces.

## Analyst Checks

Review the command line and decode the encoded content where appropriate. Examine the parent-child process relationship, user, integrity level, follow-on file activity, network activity, and other endpoint context before escalation.

## ATT&CK Mapping

T1059.001 — PowerShell

T1027.010 — Obfuscated Files or Information: Command Obfuscation
