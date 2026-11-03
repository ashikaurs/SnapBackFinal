Step 1. Create agent/config/settings.py
New implementation
This file will contain the application's central configuration.

It will manage:

- Project directory paths.
- Backup and log directories.
- Monitoring configuration.
- Detection thresholds.
- Decoy configuration.
- Operating-system validation.

Why are we structuring it this way?
A few important decisions:

- PROJECT_ROOT automatically identifies the project location. We don't need to hardcode D:\SNAP_BACK.
- MONITORED_DIRECTORIES starts empty because the user should eventually select which folders to protect.
- Detection thresholds are centralized, so we can tune them without modifying the detection engine.
- REQUIRE_USER_CONFIRMATION prevents premature automatic actions.
- AUTO_RECOVERY is disabled until our detection and recovery pipeline is sufficiently teste

=====================================================

Step 2. Create agent/main.py
This will become the central entry point of SNAP_BACK.

Its responsibilities will be:

1. Validate the operating system.
2. Initialize application directories.
3. Initialize logging.
4. Start the monitoring system.
5. Coordinate detection, response and recovery.

======================================

ing information such as:

- When the application starts or stops.
- Which files are modified.
- Suspicious processes detected.
- Errors during backup or recovery.
- Actions taken by the detection and response modules.
  These records are stored in logs/snapback.log.

Purpose: To help us debug the application, investigate security incidents and track the application's activities.

=====================================================================================================================
main :

we now have the windows native file monitoring working successfully

with teh following code in one terminal
echo Hello SNAP_BACK > C:\SNAP_BACK_TEST\test.txt
echo Modified content > C:\SNAP_BACK_TEST\test.txt
del C:\SNAP_BACK_TEST\test.txt

and the application runing in another
python "Z:\agent\monitoring\windows_monitor.py" "C:\SNAP_BACK_TEST"

we obtained the following results :

    Detected event	Result

Create test.txt CREATED Passed
Write new content MODIFIED Passed
Write again MODIFIED Passed
Delete file DELETED Passed
Create again CREATED Passed

You also noticed multiple MODIFIED events. This is normal: Windows can generate multiple notifications for operations involving file writes.

What have we achieved?
Milestone 1 completed
Our monitoring module can now:

- Monitor a specified Windows directory.
- Detect file creation.
- Detect file modification.
- Detect file deletion.
- Capture the affected file's path.
- Generate structured event dictionaries.
