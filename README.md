# Splunk SOC Detection Lab

Hands-on Windows SOC lab focused on **SIEM monitoring, detection engineering, alerting, and investigation**.

## Stack

Windows 11 · Sysmon · Splunk Enterprise · Splunk Universal Forwarder · SPL · MITRE ATT&CK

## Architecture

Windows Endpoint → Sysmon → Universal Forwarder → Splunk Enterprise → Detections → Alerts → Investigation

## Detections

| Detection | ATT&CK |
|---|---|
| PowerShell Encoded Command Execution | T1059.001 |
| Suspicious Rundll32 Execution | T1218.011 |
| Run Key Persistence | T1547.001 |
| User-Writable Executable Execution | Behavioral detection — no direct ATT&CK mapping |

## What This Demonstrates

- Windows endpoint telemetry collection
- SPL detection development and tuning
- Real-time alerting
- Process and persistence investigation
- False-positive analysis
- MITRE ATT&CK mapping
- SOC dashboarding

## Validation

Each detection was tested with controlled lab activity and verified through **Sysmon telemetry, Splunk searches, and real-time alerts**.

## Evidence

Detection logic, alert configuration, investigation results, and dashboard evidence are included in the repository.

> Controlled home-lab environment. Test activity is benign.
