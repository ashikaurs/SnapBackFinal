Event Processing and Integration

Implemented event_processor.py and integrated it with windows_monitor.py using a callback mechanism.

Workflow:

Windows Monitor continuously observes the specified directory.

When a file system event occurs, the monitor generates a raw event.

The raw event is automatically forwarded to the Event Processor.

The Event Processor validates and standardizes the event.

A structured event is generated for further analysis.

Structured event contains:

Unique Event ID (UUID)

Event type

File path

File name

File extension

Directory

Timestamp (UTC)

Process ID (currently unassigned)

Event source

Processing status

Current Architecture

SNAP_BACK
|
v
Application Initialization
|
v
Local Logging
|
v
Windows File Monitor
|
| Detects file system activity
v
Raw File System Event
|
v
Event Processor
|
v
Structured Event
|
v
Future: Detection Engine

Current Development Status

Component

Status

Application initialization

Implemented

Local logging

Implemented

Windows file monitoring

Implemented and tested

Event processing

Implemented and tested

Automatic event forwarding

Implemented and tested

Process identification

Pending

Ransomware detection

Pending

Threat assessment

Pending

Incident response

Pending

Backup and recovery integration

Pending

Dashboard

Planned

Testing

The monitoring and event-processing pipeline was tested inside a Windows 11 Virtual Machine using a controlled test directory.

File creation, modification, and deletion operations were performed to verify that:

File system events were detected.

Events were automatically forwarded to the Event Processor.

Structured events were successfully generated.

Application logs were recorded locally.

Note: The current implementation detects file system activity. It does not yet classify activity as malicious or detect ransomware. These capabilities will be developed in subsequent phases.
