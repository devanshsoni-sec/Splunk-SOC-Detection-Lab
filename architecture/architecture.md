# HomeSOC Architecture

```text
Windows 11 Endpoint
        │
      Sysmon
        │
Splunk Universal Forwarder
        │
      TCP 9997
        │
Splunk Enterprise
        │
   SPL Detections
        │
 Real-Time Alerts
        │
 SOC Investigation
        │
   SOC Dashboard