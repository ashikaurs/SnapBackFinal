# File Monitoring, Process Monitoring and Sysmon in SNAP_BACK

## 1. What did we implement previously?

We implemented file-system monitoring using the Windows API `ReadDirectoryChangesW`, accessed through Python's `ctypes` module.

It monitors a specified directory and detects the following activities:

| Activity | What it detects                             |
| -------- | ------------------------------------------- |
| Created  | New files and directories                   |
| Modified | Changes to existing files                   |
| Deleted  | Deleted files and directories               |
| Renamed  | Files or directories being renamed or moved |

This is our general file-monitoring mechanism.

**Important:** We are not using the Python Watchdog library in the current implementation.

## 2. What are we doing with Sysmon?

Sysmon (System Monitor) is a Windows system monitoring tool.

It records selected system activities in Windows Event Logs. We can retrieve these events programmatically and use them as additional security telemetry.

We are currently configuring and testing two event types:

| Event ID | Activity                    |
| -------- | --------------------------- |
| 1        | Process creation            |
| 11       | File creation and overwrite |

Event ID 1 provides information such as:

- Process ID (PID)
- Process executable path
- Command-line arguments
- Parent process information
- Executable hash

Event ID 11 provides information about file creation and overwrite activity, including the file path and process-related details.

## 3. Why do we need Sysmon when we already have file monitoring?

Our existing file monitor tells us **what happened to a file**.

However, it does not directly tell us which process caused that activity.

For example:

- Our file monitor detects that `important.txt` was modified.
- Sysmon can provide additional process and file-event information.
- We can use the available information to investigate which process performed the activity.

This additional information is useful for identifying suspicious processes and correlating their activities.

## 4. Why are we initially checking Event ID 11?

We are testing one specific Sysmon event type first to verify that our configuration and event collection work correctly.

File creation alone is not sufficient for ransomware detection.

Ransomware can:

1. Open existing files.
2. Read their contents.
3. Encrypt and overwrite them.
4. Create new encrypted files.
5. Delete original files.

Other Sysmon event types may also be useful:

| Event ID | Activity                     |
| -------- | ---------------------------- |
| 11       | File creation and overwrite  |
| 23       | File deletion with archiving |
| 26       | File deletion detected       |

These additional events are not currently enabled in our Sysmon configuration. We can evaluate and enable them as needed.

## 5. How do the components work together?

| Component                             | Responsibility                                                                                    |
| ------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Windows API (`ReadDirectoryChangesW`) | Monitors file-system changes in selected directories.                                             |
| `psutil`                              | Collects running-process information and detects process starts and terminations through polling. |
| Sysmon                                | Supplies additional Windows security event telemetry.                                             |
| Event Processor                       | Converts raw file events into structured events.                                                  |
| Future Event Correlation              | Attempts to associate file activity with process information using available telemetry.           |
| Detection Engine                      | Analyses suspicious behaviour and assesses ransomware risk.                                       |

### Planned architecture

```text
Windows File Monitor
(ReadDirectoryChangesW)
        |
        v
File System Events
        |
        +----------------------+
        |                      |
        v                      v
   Event Processor         Sysmon Logs
        |                 (Event ID 1, 11...)
        |                      |
        +----------+-----------+
                   |
                   v
          Event Correlation
                   |
                   v
           Detection Engine
                   |
                   v
       Risk Assessment and Response
```

## 6. Current implementation status

- Windows file monitoring using `ReadDirectoryChangesW`: Implemented and tested.
- Event processing and structured event generation: Implemented and tested.
- Process enumeration using `psutil`: Implemented and tested.
- Continuous process monitoring using `psutil`: Implemented and tested.
- Sysmon installation and service: Completed.
- Sysmon configuration for Event IDs 1 and 11: Applied.
- Sysmon event collection through Python: Not yet implemented.
- Event correlation: Pending.
- Ransomware detection and risk assessment: Pending.

**Important distinction:** Sysmon is currently configured independently. We have not yet integrated its event collection into SNAP_BACK's Python application.

Our next objective is to integrate Sysmon event collection and then correlate its telemetry with our existing file-monitoring and process-monitoring components.
