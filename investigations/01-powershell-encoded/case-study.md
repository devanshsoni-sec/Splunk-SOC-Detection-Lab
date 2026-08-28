# Case Study — PowerShell Encoded Command Execution

## Alert
SOC - PowerShell Encoded Command Execution

## Timeline
- 03:53:01 UTC — PowerShell executed with `-EncodedCommand`.
- 03:53:03 UTC — PowerShell created a temporary `.ps1` file.

## Process Chain
`explorer.exe → cmd.exe (PID 6656) → powershell.exe (PID 3660)`

## Investigation
- No child process was observed from PID 3660.
- No network activity was observed for PID 3660.
- Temporary PowerShell file creation was observed immediately after execution.

## Assessment
The detection fired successfully. The activity was generated as a controlled benign lab test and decoded to:

`Write-Output "HomeSOC Detection Test"`

## Analyst Conclusion
Benign controlled activity. The detection is useful for identifying encoded PowerShell execution, but alert disposition requires validation of command content, process lineage, user context, and follow-on activity.

## ATT&CK
T1059.001 — PowerShell