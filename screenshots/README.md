# Screenshot checklist

Add **redacted** PNG images only after capturing the actual evidence. Do not fabricate results or upload personal data.

- [ ] `01-splunk-ingestion-summary.png` — `index=main | stats count by source sourcetype` (four verified sources)
- [ ] `02-sysmon-process-event.png` — expanded Sysmon Event ID 1 with image/parent/command line
- [ ] `03-powershell-4104.png` — benign PowerShell script-block event, Event ID 4104
- [ ] `04-detection-result.png` — tested SPL query with matching controlled simulation events
- [ ] `05-soc-dashboard.png` — final dashboard overview showing useful panels
- [ ] `06-investigation-timeline.png` — timestamped evidence from a completed investigation
- [ ] `07-coverage-matrix.png` — completed detection coverage / testing summary (optional)

<!-- TODO: Add the images here after they exist; uncomment the Markdown image links in the root README. -->
