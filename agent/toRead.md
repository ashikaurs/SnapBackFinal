# SNAP_BACK — Anti-Ransomware & Real-Time Monitoring Agent

SNAP_BACK is an automated Windows security agent designed to monitor file system activity, detect ransomware behaviors, maintain secure file backups, and coordinate automated/user-guided recovery actions.

---

## 🛠 System Architecture & Setup

### Step 1: Central Configuration (`agent/config/settings.py`)

The application's central configuration file acts as the single source of truth for runtime parameters, system locations, and detection rules.

#### Key Responsibilities
* **Project & System Paths:** Dynamically resolves base paths, backup repositories, and log locations.
* **Monitoring Parameters:** Maintains protected targets and path exclusion filters.
* **Detection & Decoy Settings:** Centralizes entropy and high-frequency modification thresholds for tuning without code edits.
* **OS Validation:** Verifies environment compatibility prior to execution.

#### Design Decisions & Rationale
* **Dynamic Base Path (`PROJECT_ROOT`):** Automatically computes directory structure relative to the project location, eliminating hardcoded paths (e.g., `D:\SNAP_BACK`).
* **Dynamic Monitored List:** `MONITORED_DIRECTORIES` initializes empty so users can dynamically configure protection targets.
* **Centralized Threshold Tuning:** Decouples safety logic from detection algorithms for easier calibration.
* **Safety Defaults:** `REQUIRE_USER_CONFIRMATION` is defaulted to `True` and `AUTO_RECOVERY` is defaulted to `False` to prevent unintentional or destructive actions during initial testing stages.

---

### Step 2: Main Entry Point (`agent/main.py`)

`agent/main.py` is the main orchestrator for the application lifecycle.

#### Core Execution Responsibilities
1. **OS Validation:** Ensures native Windows API requirements are satisfied.
2. **Directory Initialization:** Verifies and creates necessary runtime folders (e.g., `logs/`, `backups/`).
3. **Logging System:** Initializes thread-safe file and console sinks.
4. **Monitoring Core:** Boots file watchers on target paths.
5. **Pipeline Orchestration:** Routes real-time events to detection, response, and recovery modules.

---

### Step 3: Central Logging Infrastructure (`logs/snapback.log`)

All system operations, operational metrics, and security notifications are logged to `logs/snapback.log`.

#### Audited Information
* Application lifecycle state transitions (boot, pause, shutdown).
* File system mutations (Creation, Modification, Deletion).
* Process analysis events (suspicious parent/child process execution).
* Errors occurring during snapshot creation, backup syncing, or file restoration.
* Automated and manual mitigation responses.

**Purpose:** Provides an immutable audit trail for security incident forensics, debugging, and system verification.

---

## 🚀 Milestone 1: Windows Native File Monitoring

Milestone 1 validates native Windows API file monitoring (`ReadDirectoryChangesW`) in real time across specified target paths.

### Test Environment & Execution

#### Target Directory
`C:\SNAP_BACK_TEST`

#### Terminal 1: Synthetic Event Generation
```cmd
echo Hello SNAP_BACK > C:\SNAP_BACK_TEST\test.txt
echo Modified content > C:\SNAP_BACK_TEST\test.txt
del C:\SNAP_BACK_TEST\test.txt
```

#### Terminal 2: Agent Monitor Execution
```powershell
python "Z:\agent\monitoring\windows_monitor.py" "C:\SNAP_BACK_TEST"
```

---

### Test Results

| Action | Detected Event | Result | Status |
| :--- | :--- | :--- | :--- |
| `echo Hello SNAP_BACK > test.txt` | `CREATED` | Event generated | **PASSED** |
| `echo Modified content > test.txt` | `MODIFIED` | Event generated | **PASSED** |
| `echo Modified content > test.txt` | `MODIFIED` | Event generated | **PASSED** |
| `del test.txt` | `DELETED` | Event generated | **PASSED** |
| Re-create `test.txt` | `CREATED` | Event generated | **PASSED** |

> **Technical Note on Duplicate `MODIFIED` Notifications:**  
> Operating systems (specifically the Windows File System Notification API) often emit multiple events for a single file write operation (e.g., handle creation, buffer write, timestamp update, and handle close). This is expected native behavior handled downstream by event deduplication.

---

### Milestone 1 Accomplishments

- [x] Real-time file system monitoring on target Windows directories.
- [x] Detection and categorization of `CREATED`, `MODIFIED`, and `DELETED` file actions.
- [x] Extraction of affected file path strings.
- [x] Parsing of OS notifications into structured dictionary payloads ready for detection analysis.