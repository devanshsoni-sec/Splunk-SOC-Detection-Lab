# Case Study — Suspicious Run Key Persistence

## Alert
SOC - Suspicious Run Key Persistence to User-Writable Path

## Timeline
- 05:23:16 UTC — `reg.exe` created the Run key value `HomeSOCDiffTest2`.
- 05:23:23 UTC — Splunk real-time detection triggered.

## Persistence Mechanism
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HomeSOCDiffTest2`

## Payload
`C:\Users\HomeSOC\AppData\Local\Temp\HomeSOC-Test2.exe`

## Investigation
- Registry modification process: `reg.exe` (PID 1724)
- Parent process: `cmd.exe` (PID 6656)
- No network activity was observed in the investigation window.

## Assessment
The detection identified a Run-key persistence mechanism pointing to an executable in a user-writable Temp directory.

## Analyst Conclusion
Benign controlled lab activity. The persistence technique is detection-relevant and would require validation of the payload, process lineage, user context, and subsequent execution in a real investigation.

## ATT&CK
T1547.001 — Registry Run Keys / Startup Folder