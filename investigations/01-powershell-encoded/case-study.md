# Case Study — PowerShell Encoded Command Execution

## Alert

SOC - PowerShell Encoded Command Execution

## Timeline

03:53:01 UTC — PowerShell executed with an encoded command parameter.

03:53:03 UTC — Sysmon Event ID 11 recorded creation of `C:\Users\HomeSOC\AppData\Local\Temp\__PSScriptPolicyTest_dsz1s1pt.0md.ps1` by `powershell.exe`. This is a PowerShell script-policy test artifact associated with the controlled execution rather than evidence of a malicious payload.

## Process Chain

`explorer.exe → cmd.exe (PID 6656) → powershell.exe (PID 3660)`

## Investigation

No child process was observed from PID 3660.

No network activity was observed for PID 3660.

The temporary PowerShell file was identified as a script-policy test artifact associated with the controlled execution.

## Assessment

The detection fired successfully. The activity was generated as a controlled benign lab test. The decoded test command was:

`Write-Output "HomeSOC Encoded Test"`

## Analyst Conclusion

Benign controlled activity. The detection is useful for identifying encoded PowerShell execution, but alert disposition requires validation of command content, process lineage, user context, follow-on activity, and network activity.

## ATT&CK

T1059.001 — PowerShell

T1027.010 — Obfuscated Files or Information: Command Obfuscation
