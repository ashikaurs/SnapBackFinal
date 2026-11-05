# SNAP_BACK – Complete Working and Architecture Explanation

Let's understand SNAP_BACK from the beginning, following the actual execution order of your `main.py`, and then connect all the monitoring components into one complete picture.

The central idea behind SNAP_BACK is:

**Detect suspicious file activity, identify the process responsible for it, collect additional security information, extract behavioural features, and eventually use an ML model to classify whether the activity resembles ransomware.**

SNAP_BACK is not relying on one monitoring mechanism. It combines three different sources of system information:

1. Windows File Monitoring API – `ReadDirectoryChangesW`
2. Sysmon – process and system activity monitoring
3. Windows Security Auditing – file access and security-related information

These sources provide different perspectives of the same system activity. SNAP_BACK brings them together through an event pipeline and prepares structured information for ML analysis.

Let's follow the actual execution.

---

## 1. Initial Application Setup

When you execute:

```bash
python -m main
```

Python executes the following:

```python
if __name__ == "__main__":
    main()
```

Inside `main()`, the first function called is:

```python
initialize_application()
```

This performs the initial setup of SNAP_BACK.

### What happens inside initialize_application()?

**1. Platform validation**

```python
validate_platform()
```

SNAP_BACK is designed for Windows because it relies on Windows-specific facilities such as ReadDirectoryChangesW, Sysmon and Windows Security Auditing.

This function validates the operating environment.

**2. Runtime directory initialization**

```python
initialize_runtime_directories()
```

This ensures that the directories required by the application exist.

For example, SNAP_BACK maintains separate locations for configuration, logs, inventory and decoy-related information.

**3. Logging configuration**

```python
configure_logging()
```

The application configures Python's logging system:

```python
logging.basicConfig(
    filename=LOG_DIR / "snapback.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
```

This is important because SNAP_BACK does not depend only on terminal output.

It also maintains a persistent application log.

The main application log is:

`LOG_DIR / snapback.log`

This records events such as:

- Application startup.
- Protected folder additions and removals.
- Inventory initialization.
- Monitoring events.
- Sysmon events.
- Security events.
- Pipeline events.
- ML feature vectors.
- Errors and exceptions.

One important distinction: this is SNAP_BACK's application log, not the original Windows Event Log. Sysmon and Windows Security Auditing maintain their own event records in Windows Event Log channels.

**4. Sysmon configuration and initialization**

```python
if not SYSMON_CONFIG_SOURCE.exists():
    raise FileNotFoundError(...)
```

SNAP_BACK first checks whether its Sysmon configuration file exists.

Then:

```python
shutil.copy2(
    SYSMON_CONFIG_SOURCE,
    SYSMON_CONFIG_FILE
)
```

It copies the source configuration into the application's runtime configuration location.

Finally:

```python
sysmon = SysmonManager(SYSMON_CONFIG_FILE)
sysmon.ensure_sysmon()
```

The SysmonManager handles ensuring that Sysmon is installed and configured.

This is where the initial Sysmon setup takes place.

### What exactly does Sysmon configuration do?

Sysmon is a Windows system monitoring service from Microsoft Sysinternals.

It collects detailed information about selected system activities and writes the events to:

`Microsoft-Windows-Sysmon/Operational`

The configuration file determines which event types and activities Sysmon should record.

For example:

| Sysmon Event ID | What it records              |
| --------------- | ---------------------------- |
| Event ID 1      | Process creation             |
| Event ID 2      | File creation time changed   |
| Event ID 3      | Network connection           |
| Event ID 5      | Process termination          |
| Event ID 7      | Image/DLL loaded             |
| Event ID 11     | File created or overwritten  |
| Event ID 12–14  | Registry events              |
| Event ID 23/26  | File deletion-related events |

Not every event is necessarily enabled in your configuration. The actual configuration determines what SNAP_BACK can receive.

An important distinction: Sysmon does not automatically monitor every possible activity in Windows. It collects the activities covered by its supported event types and configuration rules.

Also, Sysmon is not restricted to your protected folders at the system level. It can collect events across the machine, depending on its configuration. SNAP_BACK subsequently applies its own filtering.

---

## 2. Protected Folder Selection

After initialization, `main()` executes:

```python
protected_folders = folder_management_menu()
```

This is where the user interacts with SNAP_BACK.

The user can:

1. Add a folder.
2. Remove a folder.
3. View protected folders.
4. Continue to monitoring.
5. Exit.

The selected folders are stored persistently in:

`CONFIG_DIR / protected_folders.json`

For example, the file may contain:

```json
{
  "protected_folders": ["C:\\SNAP_BACK_TEST", "D:\\ImportantDocuments"],
  "updated_at": "..."
}
```

This is important because the user does not have to select the same folders every time SNAP_BACK starts.

The application loads previously registered folders using:

```python
load_protected_folders()
```

When a new folder is added, SNAP_BACK performs two additional operations before registering it.

### A. File Inventory Initialization

```python
initialize_inventory(folder)
```

This creates or updates the initial inventory of the folder.

The inventory is handled by:

```python
inventory = FileInventory(INVENTORY_FILE)
inventory.load_inventory()
inventory.scan_directory(str(folder))
inventory.save_inventory()
```

Think of this inventory as a reference record of the files that existed before monitoring begins.

It is useful for understanding changes to files later.

For example, suppose the user protects:

`C:\SNAP_BACK_TEST`

Initially, the folder contains:

```text
report.docx
photo.jpg
notes.txt
database.csv
```

SNAP_BACK scans the directory and stores their inventory information.

This gives us a baseline against which later file activity can be examined.

One important point: the inventory and the event logs serve different purposes.

- Inventory: records information about files.
- Event logs: record activities that occur.
- ML feature output: stores aggregated behavioural information.

### B. Decoy Creation

After inventory initialization:

```python
create_decoys(folder)
```

SNAP_BACK creates decoy files inside:

```text
Protected Folder/
    Reference Archive/
        2024/
```

For example:

```text
Reference Archive/
    2024/
        Q4_Financial_Report.csv
        Employee_Records.txt
        Project_Status.json
        ...
```

These files resemble normal user documents.

**Why?**

Ransomware generally attempts to discover and modify files in a directory. If it encounters a decoy and modifies, overwrites or deletes it, that activity can serve as an additional warning signal.

### What information about decoys is stored?

The metadata is maintained in:

`DECOY_DIR / decoy_metadata.json`

For every registered decoy, the code stores:

- Unique decoy ID.
- File path.
- Protected folder.
- Decoy directory.
- Filename.
- SHA-256 hash.
- Creation timestamp.
- Status.

For example:

```json
{
  "decoy_id": "...",
  "path": "C:\\SNAP_BACK_TEST\\Reference Archive\\2024\\Q4_Financial_Report.csv",
  "protected_folder": "C:\\SNAP_BACK_TEST",
  "filename": "Q4_Financial_Report.csv",
  "sha256": "...",
  "created_at": "...",
  "status": "active"
}
```

The SHA-256 hash here represents the original content of the decoy when it is registered.

It can later help determine whether the decoy's content has changed.

There is also an important distinction between the decoy metadata and the normal file inventory. Your code explicitly removes SNAP_BACK's decoys from the normal inventory.

This prevents decoy files from being treated as ordinary user files.

---

## 3. Starting the Actual Monitoring Process

Once the user selects option 4, the folder management function returns the list of protected folders.

Then `main()` executes:

```python
ensure_windows_auditing(protected_folders)
```

After that:

```python
start_monitoring(protected_folders)
```

This is where the continuous monitoring architecture begins.

The application starts three independent monitoring components.

- Windows File Monitor.
- Sysmon Monitor.
- Security Monitor.

They run in separate threads so that one monitoring source does not have to wait for another to finish collecting information.

Before examining each one, understand the overall architecture:

```text
User selects protected folders
            |
            v
Inventory and decoy initialization
            |
            v
    Three monitoring sources
            |
     -------------------------
     |           |           |
     v           v           v
 Windows       Sysmon     Security
   API         Monitor     Audit
     |           |           |
     -------------------------
                 |
                 v
           EventPipeline
                 |
                 v
       Normalization and
          Correlation
                 |
                 v
         FeatureAggregator
                 |
                 v
       Time-window aggregation
        and feature extraction
                 |
                 v
       Structured ML feature
           vector (JSON)
                 |
                 v
       Feature output file and
       the next processing stage
```

Let's understand each source separately.

---

## 4. Windows File Monitoring – ReadDirectoryChangesW

This is the component responsible for observing changes occurring inside the protected folders.

Your main file imports:

```python
from monitoring.windows_monitor import WindowsFileMonitor
```

Inside `start_monitoring()`:

```python
for folder in folders:
    monitor = WindowsFileMonitor(
        directory=folder,
        recursive=True,
        event_callback=pipeline.handle_windows_event
    )
```

For every protected folder, SNAP_BACK creates a separate monitor.

The important parameters are:

- `directory=folder`: the folder to monitor.
- `recursive=True`: monitor its subdirectories as well.
- `event_callback`: send detected events to the event pipeline.

The monitor is started in a separate thread:

```python
monitor_thread = threading.Thread(
    target=monitor.start,
    name=f"Monitor-{Path(folder).name}",
    daemon=True
)

monitor_thread.start()
```

### What is ReadDirectoryChangesW?

ReadDirectoryChangesW is a Windows API that allows an application to receive notifications about changes occurring within a directory.

Instead of repeatedly scanning every file to check whether something has changed, the application asks Windows to notify it when relevant directory changes occur.

It can notify us about:

| Change                       | Meaning                             |
| ---------------------------- | ----------------------------------- |
| FILE_ACTION_ADDED            | A new file or directory was created |
| FILE_ACTION_MODIFIED         | A file's data or attributes changed |
| FILE_ACTION_REMOVED          | A file or directory was deleted     |
| FILE_ACTION_RENAMED_OLD_NAME | Old name of a renamed item          |
| FILE_ACTION_RENAMED_NEW_NAME | New name of a renamed item          |

The exact event mapping and handling depend on your WindowsFileMonitor implementation.

### What does it actually monitor?

It monitors the directories registered with it, including their subdirectories because you specified `recursive=True`.

It does not monitor every file on the entire system.

For example:

```text
C:\
  Users\
    User\
      Documents\       <-- Protected
        report.docx
        notes.txt

      Downloads\       <-- Not protected
        installer.exe
```

If only Documents is protected, SNAP_BACK observes changes within Documents and its subdirectories, not the unrelated Downloads directory.

### Does it continuously monitor?

Yes. The monitoring thread remains active and waits for notifications from Windows.

When a change happens, Windows provides information to the monitor, which converts that information into an event that can be processed further.

### What happens when a file changes?

The event eventually reaches:

```python
pipeline.handle_windows_event
```

This is the first stage of integration with the other monitoring components.

The Windows API tells SNAP_BACK:

**Something happened to this file, and this is the type of change that occurred.**

It does not, by itself, reliably identify the process responsible for the change.

That is why we need the other monitoring sources.

---

## 5. Sysmon – Process and System Activity Monitoring

Now comes the second monitoring component.

Your main file imports:

```python
from monitoring.sysmon_monitor import SysmonMonitor
```

Inside `start_monitoring()`:

```python
sysmon_monitor = SysmonMonitor(
    event_callback=pipeline.handle_sysmon_event,
    protected_folders=folders
)
```

It is also started in a separate thread:

```python
sysmon_thread = threading.Thread(
    target=sysmon_monitor.start,
    name="Sysmon-Monitor",
    daemon=True
)

sysmon_thread.start()
```

### What is Sysmon actually doing?

Sysmon is a system-level monitoring service.

Unlike ReadDirectoryChangesW, which is configured to observe selected directories, Sysmon can collect configured events from across the Windows system.

For example, suppose your system has these processes running:

```text
chrome.exe
explorer.exe
python.exe
notepad.exe
powershell.exe
cmd.exe
```

Sysmon can record process creation, process termination, network connections, file-related events and other configured activities.

This is particularly useful for ransomware detection because ransomware is also a process running on the system.

We want to understand:

- Which executable was running?
- What was its process ID?
- When was it started?
- What was its parent process?
- What was its executable path?
- Was it creating or deleting files?
- Was it interacting with protected directories?

### Important Sysmon Identifiers

Two identifiers are particularly important for our correlation mechanism.

**Process ID (PID)**

Every running process has a process ID.

For example:

```text
Process: encryptor.exe
PID: 4520
```

**Process GUID**

Sysmon also provides a Process GUID, which uniquely identifies a process instance.

Why do we need this if we already have PID?

Because PIDs can be reused.

For example:

```text
Process A: PID 4520

Process A terminates.

Later:

Process B: PID 4520
```

If we rely only on PID, we might accidentally associate events from different process instances.

Process GUID helps avoid this ambiguity.

### Does Sysmon directly tell us which process modified a file?

There is an important nuance here.

Some Sysmon event types provide a direct association between a process and a file operation.

For example:

- Event ID 11 records file creation or overwrite, including process information and target filename.
- Event ID 23 and 26 record file deletion-related activity, including process information.

However, Sysmon does not provide a universal record of every possible file-content modification.

This is why using Sysmon alongside Windows file notifications and Security Auditing is valuable.

### Does Sysmon monitor all processes or only protected folders?

There are two different levels to understand.

1. The Sysmon service collects configured system events. Its configuration can cover activities throughout the machine.
2. Your SNAP_BACK SysmonMonitor receives `protected_folders=folders`, so it can apply application-level filtering.

The exact filtering behaviour depends on `sysmon_monitor.py`, which is not included in the main file you shared.

The important idea is that Sysmon provides the process-related context that Windows directory notifications do not provide.

---

## 6. Windows Security Auditing – Additional File Access Information

Now comes the third monitoring source.

In `main()`:

```python
ensure_windows_auditing(protected_folders)
```

This executes before monitoring begins.

The purpose is to configure Windows Security Auditing for the selected folders.

Your main file imports:

```python
from setup.windows_audit_setup import ensure_windows_auditing
from monitoring.security_monitor import SecurityMonitor
```

These perform two different jobs:

- `ensure_windows_auditing()` configures the Windows auditing mechanism.
- `SecurityMonitor` reads the resulting security events and passes them to SNAP_BACK.

### What is Windows Security Auditing?

Windows maintains a Security Event Log.

It can record security-related activities, including access to files and directories.

However, Windows does not necessarily audit every file access by default.

For this, we configure two things:

**1. Audit policy**

This determines which categories of security activities Windows should audit.

For our project, we are interested in the File System object-access auditing category.

**2. SACL (System Access Control List)**

This is configured on the protected folders.

A SACL specifies which accesses to an object should generate audit records and whether successful or failed access should be audited.

This is different from a DACL, which determines whether access is allowed or denied.

In simple terms:

- DACL: Who is allowed to access this file?
- SACL: Which access attempts should Windows record?

### What is Event ID 4663?

<text>**Important for SNAP_BACK**</text>

Windows Security Event ID 4663 represents an attempt to access an object where a requested access right was actually used.

For our project, the object is generally a file or directory.

Suppose a process tries to modify:

```text
C:\SNAP_BACK_TEST\report.docx
```

Windows may generate a 4663 event containing information such as:

| Field        | What it tells us                                    |
| ------------ | --------------------------------------------------- |
| Object Name  | Which file or directory was accessed                |
| Process ID   | Which process performed the access                  |
| Process Name | Executable associated with the activity             |
| Accesses     | Type of access performed                            |
| Subject      | Security account under which the operation occurred |
| Handle ID    | Handle associated with the access                   |

The Accesses field can contain operations such as:

- ReadData.
- WriteData.
- AppendData.
- Delete.
- ReadAttributes.
- WriteAttributes.

This is extremely useful for ransomware detection.

Consider the following example:

```text
Process: encryptor.exe
PID: 4520
File: report.docx
Access: WriteData
```

This provides information about the process accessing the file and the access right used.

### Does 4663 tell us the process permissions?

Not exactly.

This is a distinction worth understanding.

A 4663 event records access rights used on an object. It does not give us a complete snapshot of the process's security permissions or the entire Windows access-control configuration.

It helps us understand the actual access operation.

For example, if a process is accessing hundreds of files with WriteData, that is useful behavioural information.

### Why do we need Security Auditing when Sysmon already exists?

Because they provide complementary information.

Imagine a ransomware process:

```text
encryptor.exe
PID: 4520
```

It modifies:

```text
report.docx
notes.txt
photo.jpg
database.csv
```

The Windows API tells us that these files changed.

Sysmon provides process-related information and may directly record certain file operations.

Security Auditing provides additional information about the access rights used on the files, along with the process and security-account context.

Combining these sources gives us a more informative picture of what happened.

### How does SecurityMonitor run?

In `start_monitoring()`:

```python
security_monitor = SecurityMonitor(
    event_callback=pipeline.handle_security_event,
    protected_folders=folders,
    poll_interval=1
)
```

Notice this parameter:

```python
poll_interval=1
```

This means the SecurityMonitor is configured with a one-second polling interval.

It is started in its own thread:

```python
security_thread = threading.Thread(
    target=security_monitor.start,
    name="Security-Monitor",
    daemon=True
)

security_thread.start()
```

The one-second interval belongs to SecurityMonitor. It does not determine how frequently the ML feature vectors are generated.

Also, polling every second does not mean that Windows generates a new security event every second. It means the monitor checks for available events at that interval.

---

## 7. Understanding the Three Monitoring Sources Together

At this point, we have three independent sources of information.

Let's consider a realistic ransomware scenario.

Suppose the user has protected:

```text
C:\SNAP_BACK_TEST
```

A suspicious process starts:

```text
encryptor.exe
PID: 4520
```

It begins modifying files.

### What does each component observe?

| Component             | Information obtained                                                                      |
| --------------------- | ----------------------------------------------------------------------------------------- |
| ReadDirectoryChangesW | report.docx was modified                                                                  |
| Sysmon                | Process-related information, PID 4520, executable identity and any applicable file events |
| Security Auditing     | Access to report.docx with WriteData, process ID and process name                         |

The three sources are not simply duplicates of each other.

They observe different aspects of system behaviour.

### One file modification – Three perspectives

**Windows API**

```text
report.docx → MODIFIED
```

**Sysmon**

```text
encryptor.exe → PID 4520
```

**Security Audit**

```text
report.docx → WriteData → PID 4520
```

**Combined event information**

```text
File + action + process + access + timestamp
```

This is the central idea behind our monitoring architecture.

We want to move from knowing that a file changed to understanding which process was associated with the activity and what kind of access was performed.

But collecting all these events is only half the work.

We now need to bring them together.

---

## 8. EventPipeline – Bringing the Sources Together

Your main file imports:

```python
from monitoring.event_pipeline import EventPipeline
```

Inside `start_monitoring()`:

```python
pipeline = EventPipeline(
    event_callback=lambda event: handle_pipeline_event(
        event,
        feature_aggregator
    ),
    protected_folders=folders
)
```

This is where our event-processing architecture is established.

The pipeline is created before the monitoring threads are started.

Notice that all three monitoring components receive callbacks belonging to this same pipeline.

```python
# Windows
event_callback=pipeline.handle_windows_event

# Sysmon
event_callback=pipeline.handle_sysmon_event

# Security
event_callback=pipeline.handle_security_event
```

This is an important design decision.

Instead of making every monitoring component communicate directly with every other component, we provide a common processing layer.

### What is an event pipeline?

Think of a pipeline as a sequence of processing stages.

Data enters from different sources, gets transformed into a common representation, and is passed to the next stage.

For example:

```text
Windows event ─────┐
                   |
Sysmon event ──────┼──> EventPipeline
                   |
Security event ────┘
                         |
                         v
                 Event normalization
                         |
                         v
                  Event correlation
                         |
                         v
                   Common event
                         |
                         v
                  FeatureAggregator
```

### Why do we need normalization?

Each monitoring source provides information in a different format.

For example, Windows File Monitoring might provide:

```text
Action: MODIFIED
File: report.docx
```

Sysmon might provide:

```text
Event ID: 11
Process ID: 4520
Image: encryptor.exe
Target Filename: report.docx
```

Security Auditing might provide:

```text
Event ID: 4663
Object Name: report.docx
Process ID: 4520
Access: WriteData
```

It would be difficult to work with these different structures directly.

Therefore, the pipeline should convert them into a common event structure.

Your main file shows the structure expected by the next stage through:

```python
event.get("event_category")
event.get("action")
event.get("file", {}).get("path")
event.get("process", {})
event.get("access", {}).get("types", [])
```

This gives us an idea of the normalized event format.

A conceptual example:

```json
{
  "event_category": "FILE",
  "action": "MODIFIED",
  "timestamp": "...",
  "file": {
    "path": "C:\\SNAP_BACK_TEST\\report.docx"
  },
  "process": {
    "pid": 4520,
    "image": "encryptor.exe"
  },
  "access": {
    "types": ["WriteData"]
  }
}
```

This is an illustrative example of the expected structure, not a claim that this exact object is generated by your current implementation.

### What is event correlation?

Normalization and correlation are related, but they are not the same operation.

- Normalization: Convert different event formats into a common format.
- Correlation: Determine whether events from different sources refer to the same underlying activity.

For example:

**Windows event:**

```text
File = report.docx
Action = MODIFIED
Time = 10:00:01
```

**Sysmon event:**

```text
File = report.docx
PID = 4520
Process = encryptor.exe
Time = 10:00:01
```

**Security event:**

```text
File = report.docx
PID = 4520
Access = WriteData
Time = 10:00:01
```

The correlation mechanism can examine:

1. File path.
2. Timestamp.
3. Process ID.
4. Process GUID, when available.
5. Event type.

If the events match sufficiently, SNAP_BACK can associate them.

### A very important concept: Time-based correlation

The events do not necessarily arrive at precisely the same instant.

For example:

```text
10:00:01.100 – Windows notification
10:00:01.250 – Sysmon event
10:00:01.700 – Security event
```

These events may describe the same underlying activity.

Therefore, a correlation mechanism needs some tolerance for differences in timestamps.

Your main file's older correlation display includes:

```python
event["time_difference_seconds"]
```

This indicates that the older correlation code was designed to account for the time difference between related events.

However, we should distinguish that older implementation from the active pipeline.

Your main file imports:

```python
from monitoring.event_processor import EventProcessor
from monitoring.event_correlator import EventCorrelator
```

It also contains:

```python
handle_file_event()
handle_sysmon_event()
print_correlated_event()
```

These functions belong to an earlier/direct integration approach.

In the current `start_monitoring()` implementation, the active path is through EventPipeline.

The imports of EventProcessor and EventCorrelator do not themselves mean that those classes are being executed.

This is an important distinction when understanding your codebase.

---

## 9. FeatureAggregator – Converting Events into ML Features

This is probably the most important component for the ML part of SNAP_BACK.

Your main file imports:

```python
from monitoring.feature_aggregator import FeatureAggregator
```

And initializes it:

```python
feature_aggregator = FeatureAggregator(
    inventory_path=INVENTORY_FILE,
    decoy_paths=decoy_paths,
    output_callback=write_feature_vector,
    window_seconds=FEATURE_WINDOW_SECONDS,
    flush_grace_seconds=FEATURE_FLUSH_GRACE_SECONDS
)
```

Let's understand why this component exists.

### Why can't we directly send every event to an ML model?

Suppose a ransomware process modifies 100 files.

Our monitoring components may produce hundreds of individual events.

But an ML model should not necessarily receive each event independently.

Ransomware is often identified by its behaviour over a period of time.

For example:

- How many files were modified?
- How many files were deleted?
- How quickly were files modified?
- How many different file extensions were affected?
- Was there a high frequency of file operations?
- Did file entropy increase?
- Were decoy files accessed or modified?
- Was the same process responsible for multiple operations?

These are behavioural characteristics.

We need to aggregate individual events and calculate meaningful features.

That is the job of FeatureAggregator.

### What is a time window?

Imagine the following activity:

| Time     | Activity        |
| -------- | --------------- |
| 10:00:01 | File A modified |
| 10:00:02 | File B modified |
| 10:00:03 | File C modified |
| 10:00:04 | File D modified |
| 10:00:05 | File E deleted  |

Instead of treating these as five completely independent observations, we can collect them within a time window.

For example, suppose the aggregation window is 5 seconds.

Then all five events can contribute to one feature vector.

Conceptually:

```text
10:00:00 ───────────────── 10:00:05

File A modified
File B modified
File C modified
File D modified
File E deleted
             |
             v
       Feature extraction
             |
             v
        JSON feature vector
```

The time window allows us to understand the intensity and pattern of activity.

### Where is the interval specified?

In your main file, the values are passed here:

```python
window_seconds=FEATURE_WINDOW_SECONDS,
flush_grace_seconds=FEATURE_FLUSH_GRACE_SECONDS
```

Both constants are imported from:

```python
from config.settings import (
    ...
    FEATURE_WINDOW_SECONDS,
    FEATURE_FLUSH_GRACE_SECONDS
)
```

Therefore:

- `FEATURE_WINDOW_SECONDS` defines the aggregation window.
- `FEATURE_FLUSH_GRACE_SECONDS` provides a grace period for handling events around the window boundary before the feature data is flushed.

The actual numeric values are not present in the main file. They are defined in `config/settings.py`.

Important: The one-second SecurityMonitor polling interval and the feature aggregation window are two entirely different intervals.

The former controls how frequently the security monitor checks for events. The latter controls how events are grouped for feature extraction.

The exact flushing behaviour, including how the grace period is applied, is implemented inside FeatureAggregator, not in `main.py`.

### What information goes into FeatureAggregator?

Look at these two arguments:

```python
inventory_path=INVENTORY_FILE
decoy_paths=decoy_paths
```

These are important.

**A. Inventory information**

The aggregator receives the initial file inventory.

This gives it a reference point for file-related information.

For example, it can use the inventory to obtain baseline information about files and their original characteristics.

The exact inventory fields used for feature extraction depend on `feature_aggregator.py`.

**B. Decoy information**

Before initializing FeatureAggregator, your code loads decoy metadata:

```python
decoy_metadata = load_decoy_metadata()

decoy_paths = [
    record["path"]
    for record in decoy_metadata.get("decoys", [])
    if record.get("status") == "active" and record.get("path")
]
```

This happens inside `start_monitoring()`.

Notice the order:

1. User selects protected folders.
2. Inventory is initialized.
3. Decoys are created.
4. Their metadata is stored.
5. Monitoring starts.
6. Decoy paths are loaded.
7. FeatureAggregator is initialized with those paths.

This is how the aggregator knows which monitored files are SNAP_BACK decoys.

It can then use decoy-related activity as an additional feature.

### What is entropy, and why do we need it?

Entropy is a measure of randomness or unpredictability in data.

In ransomware detection, entropy is useful because encrypted file contents often exhibit high randomness.

For example:

Consider a normal text file:

```text
This is my college assignment.
The subject is computer science.
```

The characters follow relatively predictable patterns.

Now imagine the file gets encrypted.

Its contents become something resembling random binary data.

The entropy of the file may increase significantly.

The Shannon entropy formula is:

\[
H(X)=-\sum\_{i=0}^{255}p_i\log_2(p_i)
\]

Here:

- \(X\) represents the byte values in the file.
- \(p_i\) represents the probability of a particular byte value occurring.
- There are 256 possible byte values (0–255).

The entropy ranges from 0 to 8 bits per byte.

| Entropy    | General interpretation    |
| ---------- | ------------------------- |
| Close to 0 | Highly repetitive data    |
| Moderate   | Somewhat structured data  |
| Close to 8 | Highly unpredictable data |

For example:

- A text file may have relatively low entropy.
- A compressed image may already have high entropy.
- An encrypted file will generally have high entropy.

Very important: High entropy alone does not prove ransomware. ZIP files, JPEGs, videos and other compressed formats can naturally have high entropy.

That is why we combine entropy with other behavioural features.

Also, the main file does not calculate entropy itself. It initializes FeatureAggregator, which is where the entropy-related implementation belongs. I would need to inspect that module to tell you the exact calculation method, whether it uses the entire file or samples, and how it compares current and baseline entropy.

### What about the speed at which files are changing?

This is another important ransomware indicator.

Imagine two situations.

**Situation A: Normal user activity**

```text
10:00:01 – File A modified
10:02:30 – File B modified
10:05:00 – File C modified
```

**Situation B: Suspicious activity**

```text
10:00:01 – File A modified
10:00:01 – File B modified
10:00:02 – File C modified
10:00:02 – File D modified
10:00:03 – File E modified
```

The second situation shows a much higher rate of file modifications.

A feature extractor can calculate quantities such as:

\[
\text{Modification Rate}
=
\frac{\text{Number of modifications}}{\text{Time interval}}
\]

For example, if 100 files are modified within 5 seconds:

\[
\text{Rate}=\frac{100}{5}=20
\]

That means 20 modifications per second.

This kind of information helps an ML model distinguish ordinary file activity from unusually rapid operations.

The same general idea can be applied to file creations, deletions and renames.

The exact features and formulas used by your current aggregator need to be confirmed from its source code.

---

## 10. Writing and Displaying the ML Feature Vector

Now we reach a very specific part of your question.

You asked where the generated JSON is printed and where it is stored.

The answer is in this function:

```python
def write_feature_vector(feature_vector):
```

Let's examine it.

```python
serialized = json.dumps(
    feature_vector,
    ensure_ascii=False
)
```

This converts the Python dictionary into a JSON string.

Then:

```python
with open(FEATURE_OUTPUT_FILE, "a", encoding="utf-8") as file:
    file.write(serialized + "\n")
```

This appends the JSON object to the feature output file.

Notice the `"a"` mode.

It means append, not overwrite.

So every completed feature vector is stored as a separate line.

This format is called JSON Lines (JSONL).

For example:

```json
{"window_start":"10:00:00","modified_count":10,"entropy":6.8}
{"window_start":"10:00:05","modified_count":35,"entropy":7.4}
{"window_start":"10:00:10","modified_count":80,"entropy":7.9}
```

These are illustrative records, not your actual feature schema.

The output path is:

```python
FEATURE_OUTPUT_FILE
```

This is imported from `config.settings`.

So the exact filename and directory need to be checked in that settings file.

### Where is the feature vector printed in the terminal?

Immediately after writing the JSONL record:

```python
logger.info(
    "ML FEATURE VECTOR:\n%s",
    json.dumps(feature_vector, indent=2)
)

print("\n========== ML FEATURE VECTOR ==========")
print(json.dumps(feature_vector, indent=2))
print("=======================================\n")
```

Exact print location: `main.py`, lines 961–963.

This is the location responsible for displaying the completed ML feature vector.

The output is also written to `snapback.log` through the logger.

Therefore, there are two destinations:

1. `FEATURE_OUTPUT_FILE` – machine-readable JSONL records.
2. `LOG_DIR / snapback.log` – human-readable application log entries.

And there is a third destination:

3. Terminal – formatted JSON printed using `print()`.

### At what interval is the feature vector printed?

The main file does not contain a `print()` statement inside a timer or a loop that prints feature vectors every fixed number of seconds.

Instead, it passes this callback:

```python
output_callback=write_feature_vector
```

to FeatureAggregator.

This means that whenever FeatureAggregator completes a feature vector and invokes its output callback, `write_feature_vector()` executes.

The timing is governed by:

```python
FEATURE_WINDOW_SECONDS
FEATURE_FLUSH_GRACE_SECONDS
```

and the internal implementation of FeatureAggregator.

So the accurate explanation is:

**The ML feature vector is printed whenever FeatureAggregator emits a completed aggregation window, not whenever a monitoring event occurs and not necessarily at the one-second SecurityMonitor polling interval.**

---

## 11. One Important Distinction: Are We Actually Sending Data to the ML Model?

At the current stage shown in your main file, we are generating, storing and printing the ML input.

We are not yet invoking an ML model.

Notice:

```python
output_callback=write_feature_vector
```

The callback is connected to a function that:

- Serializes the feature vector.
- Saves it to the JSONL file.
- Writes it to the application log.
- Prints it to the terminal.

There is no model-loading statement, prediction call, HTTP request or inference call in this main file.

Therefore, the current architecture has reached:

```text
Data collection
      |
      v
Event processing and aggregation integration
      |
      v
Feature-vector persistence and display
      |
      v
ML model inference integration
      |
      v
Detection response and automated mitigation
```

We will eventually connect the feature vector to the trained model.

The model will receive the structured data and produce a prediction, such as:

```text
NORMAL
```

or:

```text
SUSPICIOUS / RANSOMWARE-LIKE
```

The exact output will depend on the model we build.

And this is where the next stage of SNAP_BACK begins.

---

## 12. Understanding Where SHA-256 Is Stored

You specifically asked which log contains the SHA-256 information.

Let's separate the different types of hashes and storage.

In the main file, SHA-256 is explicitly calculated in `create_decoys()`:

```python
file_hash = hashlib.sha256(
    decoy_path.read_bytes()
).hexdigest()
```

It is then stored in:

```python
records.append({
    "decoy_id": ...,
    "path": ...,
    "filename": ...,
    "sha256": file_hash,
    "created_at": ...,
    "status": "active"
})
```

This metadata is saved using:

```python
save_decoy_metadata(metadata)
```

Its destination is:

`DECOY_DIR / decoy_metadata.json`

So, the SHA-256 hash calculated explicitly in your main file is stored in the decoy metadata JSON, not in `snapback.log`.

There is also the normal file inventory, managed by FileInventory. Whether it stores SHA-256 hashes for ordinary user files depends on its implementation.

We should not assume that every file's SHA-256 is currently being calculated or logged simply because hashlib is imported.

There are three distinct concepts here:

| Information                       | Storage               |
| --------------------------------- | --------------------- |
| Decoy SHA-256                     | `decoy_metadata.json` |
| Normal file baseline information  | `INVENTORY_FILE`      |
| Monitoring and application events | `snapback.log`        |
| Aggregated ML features            | `FEATURE_OUTPUT_FILE` |

Why are these separate?

Because each file serves a different purpose.

- Metadata helps SNAP_BACK manage its decoys.
- Inventory provides baseline information about protected files.
- Logs provide a record of system activity.
- Feature output contains structured information for ML analysis.

---

## 13. How the Complete Execution Happens in Chronological Order

Let's put everything together.

**1. Application initialization**

Platform validation, runtime directory creation, logging configuration and Sysmon initialization.

**2. User selects protected folders**

Existing folder registrations are loaded or new folders are added.

**3. Initial inventory**

SNAP_BACK scans protected folders and creates or updates the baseline inventory.

**4. Decoy initialization**

Decoys are generated, their SHA-256 hashes are calculated, and metadata is saved.

**5. Windows Security Auditing configuration**

Audit policy and folder auditing configuration are established for the selected folders.

**6. FeatureAggregator initialization**

Inventory path, decoy paths, aggregation window and flush grace period are provided.

**7. EventPipeline initialization**

A common event-processing layer is created.

**8. Three monitoring threads start**

ReadDirectoryChangesW, SysmonMonitor and SecurityMonitor operate independently.

**9. Events are collected and processed**

Source-specific callbacks send events into EventPipeline.

**10. Feature extraction**

FeatureAggregator receives the pipeline events and accumulates behavioural information.

**11. Feature vector generation**

At the completion of an aggregation window, a structured feature vector is emitted.

**12. Feature vector persistence**

The JSON is appended to the JSONL output file, logged and printed to the terminal.

**13. Future ML integration**

The generated vector will be passed to the model for classification.

---

# Final Architecture at a Glance

```text
                  SNAP_BACK
                      |
                      v
             Application Setup
                      |
                      v
             Protected Folders
                      |
             -------------------
             |                 |
             v                 v
        File Inventory     Decoy Creation
             |                 |
             -------------------
                      |
                      v
          Windows Security Auditing
                      |
                      v
             Monitoring Starts
                      |
          -------------------------
          |           |           |
          v           v           v
     Windows API    Sysmon    Security Audit
          |           |           |
          -------------------------
                      |
                      v
                EventPipeline
                      |
                      v
          Normalization and Correlation
                      |
                      v
              FeatureAggregator
                      |
                      v
             Behavioural Features
                      |
                      v
               ML Feature Vector
                      |
          -------------------------
          |           |           |
          v           v           v
        JSONL      Application   Terminal
        File          Log
                      |
                      v
             Future ML Inference
                      |
                      v
             Ransomware Classification
                      |
                      v
             Detection and Response
```

**The core idea:** SNAP_BACK combines file-system notifications, process-related information and security audit records to understand suspicious file activity. It then aggregates that activity into behavioural features that can eventually be used by a machine learning model to identify ransomware-like behaviour.
