
"""
SNAP_BACK - Security Monitor

Collects Windows Security Event ID 4663 records
and extracts file-access and process information.
"""

import logging
import os
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

from datetime import datetime, timezone
from pathlib import Path


logger = logging.getLogger("SNAP_BACK.SECURITY_MONITOR")


class SecurityMonitor:

    LOG_NAME = "Security"
    EVENT_ID = 4663

    def __init__(
        self,
        event_callback,
        protected_folders,
        poll_interval=1
    ):

        self.event_callback = event_callback
        self.poll_interval = poll_interval

        self.protected_folders = [
            self.normalize_path(folder)
            for folder in protected_folders
        ]

        self.last_record_id = 0

        self.stop_event = threading.Event()

        logger.info(
            "Security monitor initialized."
        )

    # --------------------------------------------------
    # 1. NORMALIZE PATH
    # --------------------------------------------------

    @staticmethod
    def normalize_path(file_path):

        if not file_path:
            return None

        return os.path.normcase(
            os.path.normpath(
                os.path.abspath(file_path)
            )
        )

    # --------------------------------------------------
    # 2. CHECK PROTECTED FOLDER
    # --------------------------------------------------

    def is_protected_path(self, file_path):

        normalized_path = self.normalize_path(
            file_path
        )

        if not normalized_path:
            return False

        for folder in self.protected_folders:

            try:

                if os.path.commonpath([
                    normalized_path,
                    folder
                ]) == folder:

                    return True

            except ValueError:
                continue

        return False

    # --------------------------------------------------
    # 3. GET LATEST SECURITY RECORD ID
    # --------------------------------------------------

    def get_latest_record_id(self):

        command = (
            "Get-WinEvent -LogName Security "
            "-MaxEvents 1 -ErrorAction Stop | "
            "Select-Object -ExpandProperty RecordId"
        )

        try:

            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command
                ],
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip())

            return int(result.stdout.strip())

        except Exception:

            logger.exception(
                "Unable to read latest Security record ID."
            )

            return None

    # --------------------------------------------------
    # 4. READ NEW SECURITY RECORDS
    # --------------------------------------------------

    def read_new_records(self):

        xpath = (
            "*[System["
            f"(EventID={self.EVENT_ID}) and "
            f"(EventRecordID > {self.last_record_id})"
            "]]"
        )

        escaped_xpath = xpath.replace("'", "''")

        command = f"""
        $events = @(
            Get-WinEvent `
                -LogName '{self.LOG_NAME}' `
                -FilterXPath '{escaped_xpath}' `
                -MaxEvents 500 `
                -ErrorAction SilentlyContinue |
            Sort-Object RecordId
        )

        $results = @(
            foreach ($event in $events) {{
                [PSCustomObject]@{{
                    RecordId = $event.RecordId
                    Xml = $event.ToXml()
                }}
            }}
        )

        ConvertTo-Json -InputObject $results -Compress -Depth 3
        """

        try:

            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:

                logger.error(
                    "Security event query failed: %s",
                    result.stderr.strip()
                )

                return []

            output = result.stdout.strip()

            if not output:
                return []

            import json

            records = json.loads(output)

            if isinstance(records, dict):
                records = [records]

            return records

        except Exception:

            logger.exception(
                "Error reading Security events."
            )

            return []

    # --------------------------------------------------
    # 5. EXTRACT ACCESS TYPES
    # --------------------------------------------------

    @staticmethod
    def extract_access_types(access_mask):

        try:
            mask = int(access_mask, 16)

        except (ValueError, TypeError):
            return []

        access_types = []

        access_flags = {
            0x0002: "WRITE_DATA",
            0x0004: "APPEND_DATA",
            0x0010: "WRITE_EXTENDED_ATTRIBUTES",
            0x0100: "WRITE_ATTRIBUTES",
            0x0040: "DELETE_CHILD",
            0x10000: "DELETE"
        }

        for flag, name in access_flags.items():

            if mask & flag:
                access_types.append(name)

        return access_types

    # --------------------------------------------------
    # 6. PARSE SECURITY EVENT XML
    # --------------------------------------------------

    def parse_event(self, record):

        try:

            root = ET.fromstring(
                record["Xml"]
            )

            namespace = {
                "e": (
                    "http://schemas.microsoft.com/"
                    "win/2004/08/events/event"
                )
            }

            system_time = root.find(
                ".//e:System/e:TimeCreated",
                namespace
            )

            event_data = {}

            for item in root.findall(
                ".//e:EventData/e:Data",
                namespace
            ):

                name = item.attrib.get("Name")

                if name:
                    event_data[name] = item.text or ""

            file_path = event_data.get(
                "ObjectName"
            )

            process_name = event_data.get(
                "ProcessName"
            )

            process_id = event_data.get(
                "ProcessId"
            )

            access_mask = event_data.get(
                "AccessMask"
            )

            if not file_path:
                return None

            if not self.is_protected_path(file_path):
                return None

            # Convert hexadecimal PID to integer.
            try:

                process_id = int(
                    process_id,
                    16
                )

            except (ValueError, TypeError):
                process_id = None

            # Preserve the original event timestamp.
            timestamp = None

            if system_time is not None:

                timestamp = system_time.attrib.get(
                    "SystemTime"
                )

            if timestamp:

                parsed_time = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )

                timestamp = parsed_time.astimezone(
                    timezone.utc
                ).isoformat(timespec="milliseconds")

            else:

                timestamp = datetime.now(
                    timezone.utc
                ).isoformat(timespec="milliseconds")

            path = Path(file_path)

            security_event = {

                "event_type": "FILE_ACCESS",

                "security_event_id": self.EVENT_ID,

                "event_record_id": int(
                    record["RecordId"]
                ),

                "timestamp": timestamp,

                "source": "security_auditing",

                "file_path": str(path),

                "file_name": path.name,

                "file_extension": path.suffix.lower(),

                "process_id": process_id,

                "process_image": process_name,

                "access_mask": access_mask,

                "access_types": self.extract_access_types(
                    access_mask
                ),

                "access_list": event_data.get(
                    "AccessList"
                ),

                "handle_id": event_data.get(
                    "HandleId"
                ),

                "user_sid": event_data.get(
                    "SubjectUserSid"
                )
            }

            return security_event

        except Exception:

            logger.exception(
                "Unable to parse Security event."
            )

            return None

    # --------------------------------------------------
    # 7. PROCESS NEW RECORDS
    # --------------------------------------------------

    def process_new_records(self):

        records = self.read_new_records()

        for record in records:

            record_id = int(
                record["RecordId"]
            )

            # Advance even when the event is outside
            # protected folders.
            self.last_record_id = max(
                self.last_record_id,
                record_id
            )

            security_event = self.parse_event(
                record
            )

            if security_event is None:
                continue

            logger.info(
                "FILE ACCESS | File: %s | "
                "Process: %s | PID: %s | Access: %s",
                security_event["file_path"],
                security_event["process_image"],
                security_event["process_id"],
                security_event["access_types"]
            )

            try:

                self.event_callback(
                    security_event
                )

            except Exception:

                logger.exception(
                    "Security event callback failed."
                )

    # --------------------------------------------------
    # 8. START MONITORING
    # --------------------------------------------------

    def start(self):

        logger.info(
            "Starting Security Event monitoring."
        )

        # Ignore existing records and monitor only new ones.
        latest_id = self.get_latest_record_id()

        if latest_id is None:

            logger.error(
                "Security monitoring could not start."
            )

            return

        self.last_record_id = latest_id

        logger.info(
            "Initial Security record ID: %s",
            self.last_record_id
        )

        while not self.stop_event.is_set():

            self.process_new_records()

            self.stop_event.wait(
                self.poll_interval
            )

        logger.info(
            "Security monitoring stopped."
        )

    # --------------------------------------------------
    # 9. STOP MONITORING
    # --------------------------------------------------

    def stop(self):

        self.stop_event.set()

        logger.info(
            "Security monitor stop requested."
        )
