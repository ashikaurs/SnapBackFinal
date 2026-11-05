# SNAP_BACK ML Feature Aggregation

## Output contract

SNAP_BACK emits one JSON object per attributed process for each fixed 5-second UTC window.
The object uses the exact structure requested for the ML input:

- `window_start`, `window_end`, `window_duration_seconds`
- `process`
- `file_activity`
- `activity_rates`
- `entropy`
- `file_changes`
- `directory_activity`
- `decoy_activity`

No extra keys are added to the feature object.

## Output location

Completed objects are appended as JSON Lines to:

`C:\ProgramData\SNAP_BACK\logs\ml_feature_vectors.jsonl`

Each line is one complete JSON object. The same object is also logged and printed when a window is emitted.

## How the features are calculated

- The aggregation window is 5 seconds and is aligned to UTC clock boundaries.
- A 6-second flush grace period allows Sysmon and Security events to arrive and provide process attribution.
- Create/delete events are attributed using the existing Windows + Sysmon correlation.
- Modification and rename attribution uses nearby Windows Security Event 4663 records for the same file path and PID.
- Security 4663 access records are used for attribution and decoy-access detection. They are not independently counted as successful modifications.
- File counts are distinct paths per action within a process/window. A rename pair is counted once.
- `unique_files_affected` counts distinct file identities/paths in the window; a renamed path is treated as the same file when it is also modified in that window.
- Entropy is Shannon entropy in bits per byte, sampled from up to the first 1 MiB of a file.
- The inventory stores baseline file size and entropy. Current entropy and size are measured when a completed window is processed.
- A significant entropy increase is currently defined as at least 1.0 bit/byte.
- `average_size_change_percent` is the average absolute percentage difference from the inventory baseline.
- `extension_changes` counts rename pairs whose old and new extensions differ.
- `suspicious_extension_count` checks the extension list in `monitoring/feature_aggregator.py`.
- Decoy access is counted from Security 4663; decoy modifications/deletions are counted from filesystem notifications.

## Important limitations

- Events that cannot be attributed to a process are not included in a per-process feature object. Process attribution is best-effort and depends on the available Windows, Sysmon, and Security records.
- If an older inventory has no entropy field, SNAP_BACK initializes the missing baseline entropy from the files as they exist at the first run of this version. That cannot reconstruct their entropy from an earlier date.
- Entropy and size averages are `0.0` when no valid before/after baseline comparison is available in that window.
- This implements feature aggregation and produces the agreed ML input JSON. It does not train or execute a classifier.

## Files changed

- `main.py`
- `config/settings.py`
- `inventory/file_inventory.py`
- `monitoring/event_pipeline.py`
- `monitoring/event_correlator.py`
- `monitoring/feature_aggregator.py` (new)
