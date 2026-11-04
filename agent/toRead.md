##Example :
Suppose ransomware starts encrypting files inside our monitored directory.

1. ReadDirectoryChangesW reports that 100 files have been modified within 10 seconds.
2. Our process monitor provides information about currently running processes.
3. Sysmon provides additional process and file activity information.
4. The correlation engine examines the timestamps, process identities, file paths and event sequences.
5. The detection engine determines whether the activity is suspicious.

======================================================================= 2. One important correction: Sysmon Event IDs
You were right to question why I was using only Events 1 and 11.

Those two are insufficient for our intended detection system.

According to Microsoft's Sysmon documentation, these are the events we should consider:
Event ID Information SNAP_BACK usage
1 Process creation Identify process, parent, command line, GUID
2 File creation time changed Detect suspicious timestamp manipulation
3 Network connection Additional suspicious-process evidence
5 Process termination Track process lifecycle
7 Image/DLL loaded Additional process behaviour
10 Process access Detect suspicious inter-process access
11 File created or overwritten Correlate file creation/overwrite
12–14 Registry changes Detect possible persistence
22 DNS queries Additional network evidence
25 Process tampering Detect process-hiding techniques
26 File deletion detected Correlate deletion activity

Sources:
Microsoft Learn+1

We should configure these events selectively, with appropriate filters to control log volume.

But here is the critical distinction:

Sysmon does not provide a general event for every in-place file write or modification.

- Event 11 covers file creation and overwrite.
- Event 26 covers deletion.
- It does not tell us about every write operation that changes an existing file's contents.
  Microsoft provides another mechanism for this: Windows Security Event ID 4663, which can record file access operations, including WriteData, along with the process ID and process name. It requires appropriate filesystem auditing policies and SACLs on the monitored directories.
  Microsoft Learn+1

Therefore, our final architecture should use:

1. ReadDirectoryChangesW for detecting file changes.
2. Sysmon for process lifecycle and additional system activity.
3. Windows Security auditing (4663) for process attribution of audited file access operations.
4. psutil for supplementary process information.
   This is much stronger than pretending Event ID 11 identifies every encryption operation.

========================================================================

## System Architecture Flow

### Input Sources

#### Source 1 – File activity

- **Tool:** `ReadDirectoryChangesW`
- **Actions:** Create | Modify | Delete | Rename

#### Source 2 – Process activity

- **Tool:** `psutil`
- **Attributes:** PID | Name | Executable path | Process lifecycle

#### Source 3 – System events

- **Tool:** `Sysmon`
- **Events:** Process creation | Termination | File creation | Deletion | Other relevant events

#### Source 4 – File access attribution

- **Tool:** `Windows Security Event 4663`
- **Attributes:** Process ID | Process name | File path | Access rights

---

↓

### CORRELATION ENGINE

- Match file paths.
- Match timestamps.
- Associate PID with process lifetime and Sysmon Process GUID.
- Group events by process.
- Calculate file activity within time windows.

---

↓

### RANSOMWARE DETECTION ENGINE

- Rapid file modifications.
- Large numbers of files affected.
- Unusual deletion/creation patterns.
- Suspicious process behaviour.

> **Status:** _Suspicious activity detected_

---

↓

### Terminal alert

Display the suspected process, affected files, event count, and detection reason.

4. What we will implement
   This is our final implementation target, not a prototype.

I want to preserve your existing modules:

- agent/monitoring/windows_monitor.py
- agent/monitoring/process_monitor.py
  We will add the Sysmon event collector and correlation/detection modules to the existing architecture.

The implementation will:

- Continuously collect events.
- Maintain process information and event history.
- Correlate file events with process identities.
- Detect suspicious behaviour using configurable time windows and thresholds.
- Print a detailed terminal alert when ransomware-like activity is detected.
  We will also update your Sysmon configuration. Currently, it has Events 1 and 11 enabled, so we need to extend it.
