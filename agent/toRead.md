##Microsoft sysmon
record process and selected file-system activity

# Understanding Sysmon in SNAP_BACK

## 1. What is Sysmon?

**Sysmon (System Monitor)** is a Windows system monitoring utility developed by Microsoft as part of the Sysinternals suite.

It monitors system activities and records detailed information about them in the Windows Event Log.

It can capture activities such as:

- Process creation and termination.
- Process execution details.
- File creation and deletion (when configured).
- Network connections.
- Changes to certain system resources.

Sysmon helps security applications understand what is happening inside a Windows system.

## 2. Why are we using Sysmon in SNAP_BACK?

Our existing Windows file monitor uses `ReadDirectoryChangesW` to detect file-system activities such as file creation, modification and deletion.

However, it has one important limitation: **it does not directly identify which process performed the file operation.**

For example, our current monitor can report:

```text
File: C:\SNAP_BACK_TEST\god.txt
Event: MODIFIED
```

But it cannot directly tell us whether the modification was performed by Notepad, Python or a potentially malicious application.

This is where Sysmon becomes useful.

Sysmon can provide additional system telemetry, including process information and selected file-system events.

We will use this information to:

- Identify processes performing suspicious activities.
- Correlate process information with file-system events.
- Observe process creation and execution.
- Support ransomware behaviour analysis.
- Provide useful evidence to our detection engine.

**Important:** Sysmon provides monitoring data. SNAP_BACK will implement the logic to correlate and analyse that data to identify potentially malicious behaviour.

## 3. Where is Sysmon?

Sysmon is a Windows system-level monitoring utility.

It records its events in the Windows Event Log.

Its events can be accessed through:

```text
Event Viewer
    |
    v
Applications and Services Logs
    |
    v
Microsoft
    |
    v
Windows
    |
    v
Sysmon
    |
    v
Operational
```

The corresponding PowerShell command to read Sysmon events is:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
```

Sysmon also runs as a Windows service after installation.

## 4. Why are we using PowerShell as Administrator?

Installing and configuring Sysmon involves system-level operations.

Administrator privileges are required to:

- Enable the Windows optional feature.
- Install the Sysmon service.
- Configure system monitoring.
- Access and manage certain system event logs.

Therefore, we use **PowerShell as Administrator** to perform these operations.

to run powershell as administrator :
-> inside powershell only you write :
Start-Process powershell -Verb RunAs -WorkingDirectory "$PWD"

This does not mean our entire SNAP_BACK application must always run as Administrator. We use elevated privileges for the system-level setup and operations that require them.

## 5. Is Sysmon just present or actually installed?

Initially, Sysmon was available as a Windows optional feature, but it was disabled.

We checked its status using:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName Sysmon
```

Initially, the output showed:

```text
FeatureName : Sysmon
State       : Disabled
```

We then enabled it using:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -All
```

The command completed successfully:

```text
Online        : True
RestartNeeded : False
```

However, **enabling the optional Windows feature and installing the Sysmon service are two separate steps.**

The next installation command is:

```powershell
sysmon -i
```

This installs the Sysmon service with its default configuration. We must verify that the service is installed and running before considering the setup complete.

## 6. How Sysmon fits into SNAP_BACK

Our monitoring architecture will now have two sources of information:

```text
                 SNAP_BACK
                     |
          +----------+----------+
          |                     |
          v                     v
   Windows Monitor          Sysmon
          |                     |
          v                     v
   File System Events     System Telemetry
          |                     |
          +----------+----------+
                     |
                     v
             Event Correlation
                     |
                     v
              Detection Engine
                     |
                     v
             Threat Assessment
                     |
                     v
             Response and Recovery
```

The Windows Monitor provides direct file-system notifications, while Sysmon provides additional process and system activity information.

SNAP_BACK will correlate these sources to build a better understanding of potentially suspicious file activity.

---

**Current implementation status:** Windows file monitoring, event processing and continuous process enumeration are implemented. Sysmon's Windows feature has been enabled; service installation and event integration are the next steps.
