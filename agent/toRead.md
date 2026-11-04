1. agent/inventory/file_inventory.py
   This module will:

- Recursively scan protected folders.
- Collect file metadata and SHA256 hashes.
- Store the inventory in a JSON file.
- Support create, modify, delete and rename updates later.
- Keep inventory independent of ML features.

=================================

2. What we have implemented
   The inventory stores each file's path, name, extension, size, timestamps and SHA256 hash.

It also provides methods to update the inventory after file operations. These methods are not yet connected to your Windows monitor.

One important distinction: this is a metadata inventory, not a backup. It cannot restore file contents.

================================================

##Achieved:

- Folder selection through CLI.
- Recursive scanning of the selected folder.
- 10 files detected and inventoried.
- SHA256 hashes and metadata collected.
- JSON inventory saved successfully.

# SNAP_BACK

**A Windows-based Ransomware Detection and Protection System**

## 1. Decoy-Based Detection

SNAP_BACK uses **decoy files (honeypot files)** as one of its approaches to ransomware detection.

### How are decoy files created?

- When a user adds a folder for protection, SNAP_BACK creates a nested directory inside it:
  `Reference Archive/2024/`
- Five decoy files are created in this directory, selected randomly from a collection of eight predefined templates.
- These files resemble ordinary business documents, such as financial reports, employee records, invoices, configuration files and project reports.
- The files contain realistic, structured content rather than being empty placeholder files.
- Each decoy is registered in a central metadata file with its path, SHA-256 hash, creation time and other details.

The decoys are placed inside nested directories to make them less conspicuous to ordinary users while remaining accessible to recursive file-scanning processes.

### Detection mechanism

The intended detection mechanism is to monitor these decoy files for unexpected modifications, deletions or renaming.

Since legitimate users should not normally interact with these files, activity involving them can serve as a strong indication of suspicious behaviour.

### Limitations

- Decoys are not guaranteed to be discovered by every ransomware program.
- Some ransomware may skip certain directories, file types or files based on its scanning strategy.
- Placing decoys in nested directories provides obscurity, not guaranteed invisibility.
- Decoy activity alone is not sufficient to classify a process as malicious. It must be considered alongside other behavioural indicators.

**Current status:** Decoy creation and metadata registration are implemented. Integration with the complete detection and alerting pipeline is still in progress.

---

## 2. File Inventory Management

### What is a file inventory?

A file inventory is a record of the files present inside a protected directory at a particular point in time.

SNAP_BACK maintains an inventory containing information such as:

- File path
- File name
- File size
- File modification details
- SHA-256 hash

The inventory is stored centrally in:

`C:\ProgramData\SNAP_BACK\inventory\file_inventory.json`

### Why do we need it?

The inventory acts as a **baseline reference** for the protected files.

By maintaining their initial metadata and hashes, SNAP_BACK can later compare the current state of files against their recorded state.

This is useful for:

1. **Change identification:** Identify files whose contents or metadata have changed.
2. **Deletion detection:** Identify files that existed in the baseline but are no longer present.
3. **Integrity verification:** Use SHA-256 hashes to check whether file contents have changed.
4. **Ransomware behaviour analysis:** Provide information about the number and proportion of files modified or deleted within a monitoring period.

The inventory is therefore an important source of information for detecting abnormal file activity.

**Important:** An inventory is not a backup. It stores file information and hashes, not recoverable copies of the original file contents.

---

## 3. Protected Folder Management

SNAP_BACK maintains a persistent registry of protected folders in:

`C:\ProgramData\SNAP_BACK\config\protected_folders.json`

Users can:

- Add new folders to protection.
- Remove folders from active protection.
- View currently protected folders.

Folder registration is incremental. Adding a new folder initializes its inventory and decoys without intentionally recreating those of previously registered folders.

When a folder is removed, its decoys and corresponding metadata are intended to be deleted, while its original user files and inventory records are preserved.

---

## 4. Current Limitations and Pending Work

- **OneDrive permissions:** Inherited Windows permissions can prevent deletion of SNAP_BACK-created decoy directories. Safe handling and testing for OneDrive-protected folders are pending.
- **Monitoring integration:** Connect the protected-folder registry with continuous file monitoring and process-level activity correlation.
- **Detection engine:** Integrate decoy alerts with behavioural indicators such as file modification rates and entropy changes.
- **Backup and recovery:** Implementation of secure backups, integrity verification and file recovery is pending.

---

## 5. Technology Used

- Python
- Windows APIs (`ReadDirectoryChangesW`) for file-system monitoring
- Sysmon for process and system event telemetry
- SHA-256 for file integrity verification
- JSON for inventory, configuration and metadata storage

---

**Project Status:** Under active development. The current implementation focuses on protected-folder management, initial file inventory and decoy generation as the foundation for ransomware detection and response.

==============================================================

###SETUP folder :
thsi si for intial system setup -> sysmon configuration inside the users system
