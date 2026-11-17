# Detection development

Queries here are **starter searches**, not validated production detections. The forwarder uses XML rendering, so extract the Event ID from `_raw` before filtering. Check that field names and timestamp ranges match your own events.

Validation checklist for each query:
1. Define expected benign and suspicious behaviour.
2. Run a controlled, authorized test and save a redacted event example.
3. Check event timestamps, process context and parent-child relationships.
4. Record false positives and limitations.
5. Update `evaluation/coverage.csv` with the outcome.
