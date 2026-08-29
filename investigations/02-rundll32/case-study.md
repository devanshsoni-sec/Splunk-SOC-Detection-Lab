# Case Study — Suspicious Rundll32 Execution

## Alert
SOC - Suspicious Rundll32 Execution from User-Writable Path

## Timeline
- 04:10:39 UTC — `rundll32.exe` executed with a DLL reference under the user's Temp directory.
- 04:10:49 UTC — Splunk real-time detection triggered.

## Process Chain
`explorer.exe → cmd.exe (PID 6656) → rundll32.exe (PID 1148)`

## Investigation
- DLL reference: `C:\Users\HomeSOC\AppData\Local\Temp\homesoc-test.dll`
- No network activity was observed for PID 1148.
- No file-creation activity was observed for PID 1148.
- Sysmon Event ID 7 telemetry is not collected in the current configuration, so DLL loading could not be confirmed or excluded.

## Assessment
The detection identified execution of the legitimate Windows `rundll32.exe` binary referencing a DLL from a user-writable Temp directory.

## Analyst Conclusion
Benign controlled lab activity. The behavior is detection-relevant because `rundll32.exe` can be abused to proxy DLL execution. No malicious follow-on activity was observed in the investigation window.

## ATT&CK
T1218.011 — System Binary Proxy Execution: Rundll32
