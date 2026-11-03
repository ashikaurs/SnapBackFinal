Step 6. Create agent/monitoring/event_processor.py
What is its responsibility?
Currently, windows_monitor.py generates events like:
{ "event_type": "MODIFIED", "file_path": "C:\\SNAP_BACK_TEST\\test.txt", "directory": "C:\\SNAP_BACK_TEST"}

This is raw event information.

Our event_processor.py will convert it into a standardized format that other modules can use.

It will:

1. Validate the incoming event.
2. Generate a unique event ID.
3. Add a timestamp.
4. Extract the filename and file extension.
5. Prepare fields for future process identification.
6. Return a structured event.
   Important: It will not decide whether the activity is malicious. That belongs to our detection engine.

It is hardcoded to test.txt. So even if you create god.txt, the processor will still display test.txt.

Our current status:

1. windows_monitor.py detects actual file events — tested successfully.
2. event_processor.py converts a supplied event into a structured event — tested successfully.
3. Next, we need to connect them. Every event detected by windows_monitor.py should automatically be passed to event_processor.py.
