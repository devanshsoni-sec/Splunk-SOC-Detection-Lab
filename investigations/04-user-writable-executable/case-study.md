# Case Study — Executable Execution from a User-Writable Path

## Alert
SOC - Executable Execution from User-Writable Path

## Timeline
05:43:15 UTC — `HomeSOC-Test2.exe` executed from the user's Temp directory.
05:43:22 UTC — Splunk real-time detection triggered.

## Execution
`C:\Users\HomeSOC\AppData\Local\Temp\HomeSOC-Test2.exe`

## Process Chain
`HomeSOC-Test.exe (PID 5980) → HomeSOC-Test2.exe (PID 2028)`

## Investigation
User: `DESKTOP-8DB1757\HomeSOC`
Integrity level: High
No network activity was observed for PID 2028.
No file-creation activity was observed in the investigation window.

## Assessment
The detection identified execution of an executable from a user-writable Temp directory.

## Analyst Conclusion
Benign controlled lab activity. Execution from a user-writable location is a useful triage signal because such directories can be used to stage or launch dropped payloads. No malicious follow-on activity was observed.

## ATT&CK
No direct ATT&CK mapping. This detection is a behavioral triage rule rather than a one-to-one ATT&CK technique mapping.
