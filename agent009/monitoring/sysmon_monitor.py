
"""
SNAP_BACK - Sysmon Event Monitor

Monitors relevant Sysmon events from the Windows
Operational Event Log.

Supported events:
    Event ID 1  - Process Creation
    Event ID 2  - File Creation Time Changed
    Event ID 5  - Process Terminated
    Event ID 11 - File Creation
    Event ID 26 - File Deletion Detected

Only file events belonging to registered protected
folders are forwarded to the event callback.

Process events are forwarded for process tracking
and correlation by the detection engine.
"""

import ctypes
import json
import logging
import os
import subprocess
import threading
import xml.etree.ElementTree as ET

from pathlib import Path


logger = logging.getLogger("SNAP_BACK.SYSMON")


# --------------------------------------------------
# 1. CONFIGURATION
# --------------------------------------------------

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

POWERSHELL = "powershell.exe"

MONITORED_EVENT_IDS = (1, 2, 5, 11, 26)

EVENT_TYPES = {
    1: "PROCESS_CREATED",
    2: "FILE_CREATION_TIME_CHANGED",
    5: "PROCESS_TERMINATED",
    11: "FILE_CREATED",
    26: "FILE_DELETED"
}

FILE_EVENT_IDS = {2, 11, 26}

MAX_PROCESS_CACHE = 10000


# --------------------------------------------------
# 2. SYSMON EVENT MONITOR
# --------------------------------------------------

class SysmonMonitor:

    def __init__(
        self,
        event_callback,
        protected_folders,
        poll_interval=1
    ):

        self.event_callback = event_callback
        self.poll_interval = poll_interval

        self.protected_folders = [
            os.path.normcase(
                os.path.abspath(folder)
            )
            for folder in protected_folders
        ]

        self.last_record_number = 0

        self.running = False
        self.stop_event = threading.Event()

        # Store process creation information using
        # Sysmon ProcessGuid for later correlation.
        self.process_cache = {}

        # Identify PowerShell processes started by
        # this monitor so they do not create log noise.
        self.collector_process_ids = set()

        logger.info(
            "Sysmon monitor initialized for %s protected folders.",
            len(self.protected_folders)
        )

    # --------------------------------------------------
    # 3. PATH VALIDATION
    # --------------------------------------------------

    def _is_protected_path(self, target):

        if not target:
            return False

        target = os.path.normcase(
            os.path.abspath(target)
        )

        for folder in self.protected_folders:

            try:

                if os.path.commonpath(
                    [folder, target]
                ) == folder:

                    return True

            except ValueError:
                continue

        return False

    # --------------------------------------------------
    # 4. PROCESS ID CONVERSION
    # --------------------------------------------------

    @staticmethod
    def _convert_process_id(value):

        if not value:
            return None

        try:
            return int(value, 10)

        except (ValueError, TypeError):
            return None

    # --------------------------------------------------
    # 5. GET LATEST EVENT RECORD NUMBER
    # --------------------------------------------------

    def _get_latest_record_number(self):

        command = (
            '$event = Get-WinEvent '
            f'-LogName "{LOG_NAME}" '
            '-MaxEvents 1 '
            '-ErrorAction SilentlyContinue; '

            'if ($null -eq $event) { '
            "'0' "
            '} else { '
            '$event.RecordId '
            '}'
        )

        result = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15
        )

        if result.returncode != 0:
            raise RuntimeError(
                "Could not retrieve the latest Sysmon record: "
                f"{result.stderr}"
            )

        output = result.stdout.strip()

        if not output:
            return 0

        return int(output)

    # --------------------------------------------------
    # 6. READ NEW SYSMON EVENTS
    # --------------------------------------------------

    def _read_new_events(self):

        event_filter = " or ".join(
            f"EventID={event_id}"
            for event_id in MONITORED_EVENT_IDS
        )

        command = f"""
        $query = "*[System[({event_filter}) and (EventRecordID > {self.last_record_number})]]"

        $events = @(
            Get-WinEvent `
                -LogName '{LOG_NAME}' `
                -FilterXPath $query `
                -ErrorAction SilentlyContinue |
            Sort-Object RecordId
        )

        $xmlEvents = @(
            $events | ForEach-Object {{
                $_.ToXml()
            }}
        )

        ConvertTo-Json -InputObject $xmlEvents -Compress
        """

        try:

            result = subprocess.run(
                [
                    POWERSHELL,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20
            )

        except subprocess.TimeoutExpired:

            logger.error(
                "Sysmon event query timed out."
            )

            return

        if result.returncode != 0:

            logger.error(
                "Sysmon query failed: %s",
                result.stderr
            )

            return

        output = result.stdout.strip()

        if not output:
            return

        try:

            events = json.loads(output)

            if isinstance(events, str):
                events = [events]

            if not isinstance(events, list):
                logger.error(
                    "Unexpected Sysmon query response."
                )
                return

            for xml_event in events:

                if not isinstance(xml_event, str):
                    continue

                self._process_xml_event(xml_event)

        except (json.JSONDecodeError, TypeError):
            logger.exception(
                "Could not decode Sysmon event response."
            )

    # --------------------------------------------------
    # 7. PARSE SYSMON XML
    # --------------------------------------------------

    def _parse_xml_event(self, xml_event):

        root = ET.fromstring(xml_event)

        system = root.find("./{*}System")

        if system is None:
            return None

        event_id_element = system.find("./{*}EventID")

        record_element = system.find(
            "./{*}EventRecordID"
        )

        time_element = system.find(
            "./{*}TimeCreated"
        )

        if (
            event_id_element is None
            or record_element is None
        ):
            return None

        event_id = int(event_id_element.text)

        record_id = int(record_element.text)

        timestamp = None

        if time_element is not None:
            timestamp = time_element.get("SystemTime")

        data = {}

        event_data = root.find("./{*}EventData")

        if event_data is not None:

            for item in event_data.findall("./{*}Data"):

                name = item.get("Name")

                if name:
                    data[name] = item.text or ""

        return {
            "event_id": event_id,
            "event_record_id": record_id,
            "timestamp": timestamp,
            "data": data
        }

    # --------------------------------------------------
    # 8. PROCESS XML EVENT
    # --------------------------------------------------

    def _process_xml_event(self, xml_event):

        try:

            parsed = self._parse_xml_event(xml_event)

            if parsed is None:
                return

            event_id = parsed["event_id"]
            record_id = parsed["event_record_id"]
            data = parsed["data"]

            if event_id not in MONITORED_EVENT_IDS:
                return

            # Record IDs must be processed in order.
            if record_id <= self.last_record_number:
                return

            # Ignore the monitor's own PowerShell
            # collector processes.
            if event_id == 1:

                image = data.get("Image", "").lower()

                parent_pid = self._convert_process_id(
                    data.get("ParentProcessId")
                )

                if (
                    image.endswith("\\powershell.exe")
                    and parent_pid == os.getpid()
                ):

                    self.collector_process_ids.add(
                        self._convert_process_id(
                            data.get("ProcessId")
                        )
                    )

                    self.last_record_number = record_id
                    return

            if event_id == 5:

                process_id = self._convert_process_id(
                    data.get("ProcessId")
                )

                if process_id in self.collector_process_ids:

                    self.collector_process_ids.discard(
                        process_id
                    )

                    self.last_record_number = record_id
                    return

            # Filter file events to protected folders.
            if event_id in FILE_EVENT_IDS:

                target = data.get("TargetFilename", "")

                if not self._is_protected_path(target):

                    self.last_record_number = record_id
                    return

            self.last_record_number = record_id

            process_guid = data.get("ProcessGuid")

            process_id = self._convert_process_id(
                data.get("ProcessId")
            )

            # Cache process creation information.
            if event_id == 1:

                if process_guid:

                    self.process_cache[process_guid] = data.copy()

                    # Keep memory usage bounded.
                    if len(self.process_cache) > MAX_PROCESS_CACHE:

                        oldest_guid = next(
                            iter(self.process_cache)
                        )

                        self.process_cache.pop(
                            oldest_guid,
                            None
                        )

            # Retrieve process details for file events.
            process_details = None

            if event_id in FILE_EVENT_IDS and process_guid:

                process_details = self.process_cache.get(
                    process_guid
                )

            # Build standardized Sysmon event.
            event = {

                "sysmon_event_id": event_id,

                "event_record_id": record_id,

                "event_type": EVENT_TYPES[event_id],

                "timestamp": parsed["timestamp"],

                "source": "sysmon",

                "process_id": process_id,

                "process_guid": process_guid,

                "process_image": data.get("Image"),

                "file_path": data.get("TargetFilename"),

                "process_details": process_details,

                "data": data
            }

            logger.info(
                "Sysmon Event %s | Type: %s | PID: %s | File: %s",
                event_id,
                event["event_type"],
                process_id,
                event["file_path"]
            )

            if self.event_callback:

                try:
                    self.event_callback(event)

                except Exception:

                    logger.exception(
                        "Sysmon event callback failed."
                    )

            # Remove terminated process from cache
            # after its termination event is delivered.
            if event_id == 5 and process_guid:

                self.process_cache.pop(
                    process_guid,
                    None
                )

        except (
            ET.ParseError,
            ValueError,
            TypeError,
            KeyError
        ):

            logger.exception(
                "Failed to process Sysmon XML event."
            )

    # --------------------------------------------------
    # 9. START MONITORING
    # --------------------------------------------------

    def start(self):

        if self.running:
            logger.warning(
                "Sysmon monitoring is already running."
            )
            return

        if os.name != "nt":
            raise OSError(
                "Sysmon monitoring requires Windows."
            )

        self.stop_event.clear()

        self.last_record_number = (
            self._get_latest_record_number()
        )

        self.running = True

        logger.info(
            "Sysmon monitoring started after record %s.",
            self.last_record_number
        )

        try:

            while not self.stop_event.is_set():

                self._read_new_events()

                self.stop_event.wait(
                    self.poll_interval
                )

        except Exception:

            logger.exception(
                "Sysmon monitoring encountered an error."
            )

            raise

        finally:

            self.running = False

            logger.info(
                "Sysmon monitoring stopped."
            )

    # --------------------------------------------------
    # 10. STOP MONITORING
    # --------------------------------------------------

    def stop(self):

        self.stop_event.set()
        self.running = False

        logger.info(
            "Sysmon monitoring stop requested."
        )
