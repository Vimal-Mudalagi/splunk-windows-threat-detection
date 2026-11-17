# Windows Threat Detection & Investigation Using Splunk SIEM

**Status:** In progress — log ingestion validated; detection testing and incident investigations pending.

## Objective
Build a single-endpoint Windows security monitoring lab, investigate controlled security-relevant activity, and evaluate MITRE ATT&CK-aligned SPL detections using Splunk Enterprise.

## Architecture
Windows 11 endpoint → Sysmon + Windows Event Logs → Splunk Universal Forwarder → Splunk Enterprise (local receiver on 127.0.0.1:9997) → SPL searches, investigations and dashboard.

See [architecture/data-flow.md](architecture/data-flow.md).

## Current verified progress (16 Nov 2026)
Four sources were observed in Splunk across a 24-hour search window:

| Source | Events |
|---|---:|
| Sysmon Operational | 137,749 |
| Windows Security | 12,570 |
| Windows System | 431 |
| PowerShell Operational | 201 |
| **Total** | **150,951** |

These are **ingestion counts, not detections or incidents**. Counts are historical and environment-specific.

## Tools
- Splunk Enterprise and Splunk Universal Forwarder
- Sysmon 15.22 and Windows Event Logging
- PowerShell and Splunk Search Processing Language (SPL)
- MITRE ATT&CK and Atomic Red Team (planned controlled simulations)

## Planned deliverables
- [x] Validate four Windows log sources in Splunk
- [ ] Select and document five safe ATT&CK-aligned scenarios
- [ ] Develop and validate five SPL detections
- [ ] Complete three evidence-based investigation reports
- [ ] Build and export a SOC dashboard
- [ ] Record coverage, detection gaps, and false positives

## Repository map
- `architecture/` — pipeline diagram and component roles
- `detections/` — initial SPL searches and later validated detections
- `investigations/` — analyst case-report templates and evidence-backed reports
- `evaluation/` — coverage and testing matrix
- `dashboard/` — dashboard design and eventual export
- `config/` — sanitized configuration examples (not production secrets)
- `screenshots/` — redacted evidence screenshots

## Methodology
1. Define a hypothesis and ATT&CK mapping.
2. Review any test commands, prerequisites, and cleanup before execution.
3. Run only authorized, low-risk activity in a controlled environment.
4. Confirm telemetry in Splunk and document event IDs, timestamps, and process relationships.
5. Create a detection query; test true positives and benign activity.
6. Write an analyst verdict and document detection gaps.

## Important SPL note
These Windows Event Log inputs use `renderXml = true`. Event IDs appear as XML `<EventID>...</EventID>` and may not be automatically extracted into the `EventCode` field. Starter searches therefore extract `EventID` from `_raw`. See `detections/README.md`.

## Safety and privacy
No raw personal event logs, credentials, API tokens, unredacted usernames, hostnames, or sensitive command histories should be committed. Use sanitized screenshots and examples. Do not run invasive Atomic tests on an everyday laptop.

## Evidence screenshots (add after capturing and redacting)
<!-- TODO SCREENSHOT 01: screenshots/01-splunk-ingestion-summary.png — Splunk `index=main | stats count by source sourcetype` showing all four sources. Redact identifying hostnames. -->
<!-- ![Verified log ingestion](screenshots/01-splunk-ingestion-summary.png) -->

<!-- TODO SCREENSHOT 02: screenshots/02-sysmon-process-event.png — Expanded Sysmon Event ID 1 with relevant XML process details; redact username and paths. -->
<!-- ![Sysmon process creation evidence](screenshots/02-sysmon-process-event.png) -->

<!-- TODO SCREENSHOT 03: screenshots/03-powershell-4104.png — A benign PowerShell 4104 event in Splunk with timestamp and script block; redact sensitive content. -->
<!-- ![PowerShell script block event](screenshots/03-powershell-4104.png) -->

<!-- TODO SCREENSHOT 04: screenshots/04-detection-result.png — SPL search returning evidence of a controlled test, after validation. -->
<!-- ![Detection result](screenshots/04-detection-result.png) -->

<!-- TODO SCREENSHOT 05: screenshots/05-soc-dashboard.png — Final SOC dashboard overview after building it. -->
<!-- ![SOC dashboard](screenshots/05-soc-dashboard.png) -->

## Results
<!-- TODO: Replace this section ONLY after running tests and validating evidence. -->
**Pending.** Controlled simulations, detection results, investigation findings and false-positive evaluation have not yet been completed.

<!-- TODO: Add a results table with test ID, technique, log source, detection outcome, false positives, and evidence links. -->
<!-- TODO: Add a short lessons-learned paragraph about telemetry quality, gaps and tuning. -->
