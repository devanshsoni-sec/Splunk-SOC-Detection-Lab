# Detection Tuning

The detections were tested against broader endpoint activity before finalization. The goal was to reduce expected Windows and application noise while preserving useful security signals.

## Baseline Findings

File creation activity produced 209 events during initial review, including legitimate Windows, Edge, WebView, PowerShell, and Office activity. No standalone file-creation alert was retained.

Run Key activity produced 22 events, including legitimate Edge, VirtualBox, and Windows startup entries. The final analytic was narrowed to Run and RunOnce values referencing payloads in user-writable locations.

Executable execution from user-writable locations initially produced 12 events. Legitimate application activity, including OneDrive-related execution, was observed. The final analytic was narrowed to Temp, Users\Public, and Downloads.

## Detection Design

The final rules prioritize contextual indicators over raw event volume. Path, registry location, process image, command line, and user context are used where relevant.

## Detection Considered but Not Deployed

A candidate network detection was reviewed during validation. Activity involving the Splunk forwarding port was identified as legitimate lab infrastructure traffic rather than suspicious endpoint behavior. The rule was therefore not deployed to avoid generating a known false positive.

## Alerting

Real-time per-result alerts were used to demonstrate immediate detection behavior in the controlled lab. Production deployments should evaluate search cost, event volume, throttling, suppression, routing, and whether scheduled alerting is more appropriate.

## Validation

Each final detection was tested with controlled lab activity and verified through Sysmon telemetry, Splunk searches, and triggered alerts.

## Principle

A detection is not improved by generating more alerts. The objective is to produce alerts that provide useful investigative context and can be reasonably triaged by an analyst.
