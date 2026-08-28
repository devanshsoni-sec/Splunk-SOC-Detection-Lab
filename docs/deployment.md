# Deployment

## Environment

- Windows 11 endpoint: `DESKTOP-8DB1757`
- Splunk Enterprise host: `Splunk lab server`
- Splunk receiving port: `9997`
- Splunk Web: `8000`

## Telemetry Pipeline

Windows 11 → Sysmon → Splunk Universal Forwarder → TCP 9997 → Splunk Enterprise

## Data Sources

- Sysmon Event ID 1 — Process Creation
- Sysmon Event ID 11 — File Creation
- Sysmon Event ID 13 — Registry Value Set
- Sysmon Event ID 3 — Network Connection

## Validation

Telemetry was verified in Splunk and all four detection rules were tested with controlled lab activity.