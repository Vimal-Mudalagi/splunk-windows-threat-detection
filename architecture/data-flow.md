# Endpoint telemetry pipeline

```mermaid
flowchart TD
    A[Windows 11 Endpoint] --> B[Sysmon + Windows Event Logs]
    B --> C[Splunk Universal Forwarder]
    C -->|TCP 127.0.0.1:9997| D[Splunk Enterprise]
    D --> E[SPL Searches]
    E --> F[Detection Evaluation]
    E --> G[Analyst Investigations]
    E --> H[Dashboard]
```

All components currently run on the same Windows laptop. Sysmon, Security, System and PowerShell Operational logs were observed in Splunk on 16 November 2026.


<!-- TODO SCREENSHOT: ../screenshots/01-splunk-ingestion-summary.png — evidence of four indexed event sources. -->
<!-- TODO: Add a sanitized architecture diagram image if desired, without private machine identifiers. -->
