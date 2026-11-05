
"""
SNAP_BACK - Unified Event Pipeline

Receives events from:
    1. WindowsFileMonitor
    2. SysmonMonitor
    3. SecurityMonitor

Normalizes events into a common JSON structure and
uses EventCorrelator to identify matching file events.
"""

import json
import logging
import threading
import uuid
import os

from datetime import datetime, timezone
from pathlib import Path

from monitoring.event_correlator import EventCorrelator


logger = logging.getLogger("SNAP_BACK.EVENT_PIPELINE")


class EventPipeline:

    def __init__(self, event_callback=None, protected_folders=None):

        self.event_callback = event_callback
        self.lock = threading.RLock()

        self.correlator = EventCorrelator()

        self.known_directories = set()

        self.recent_security_events = {}
        self.security_dedup_window = 1.0

        # Record existing directories.
        for folder in (protected_folders or []):

            for root, directories, files in os.walk(folder):

                self.known_directories.add(
                    os.path.normcase(os.path.abspath(root))
                )

        logger.info("Unified event pipeline initialized.")

    # --------------------------------------------------
    # 1. TIMESTAMP NORMALIZATION
    # --------------------------------------------------

    @staticmethod
    def normalize_timestamp(timestamp=None):

        if timestamp:
            try:
                parsed = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )

                if parsed.tzinfo is None:
                    parsed = parsed.replace(
                        tzinfo=timezone.utc
                    )

                return parsed.astimezone(
                    timezone.utc
                ).isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z"
                )

            except (ValueError, TypeError, AttributeError):
                pass

        return datetime.now(
            timezone.utc
        ).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )

    # --------------------------------------------------
    # 2. FILE INFORMATION
    # --------------------------------------------------

    @staticmethod
    def get_file_information(file_path):

        if not file_path:
            return {
                "path": None,
                "name": None,
                "extension": None
            }

        path = Path(file_path)

        return {
            "path": str(path),
            "name": path.name,
            "extension": path.suffix.lower()
        }

    # --------------------------------------------------
    # 3. DIRECTORY FILTERING
    # --------------------------------------------------

    def is_directory_path(self, file_path):

        if not file_path:
            return False

        normalized = os.path.normcase(
            os.path.abspath(file_path)
        )

        if os.path.isdir(file_path):

            self.known_directories.add(normalized)
            return True

        return normalized in self.known_directories

    # --------------------------------------------------
    # 4. SECURITY EVENT DEDUPLICATION
    # --------------------------------------------------

    def is_duplicate_security_event(self, event):

        file_path = os.path.normcase(
            os.path.abspath(event.get("file_path", ""))
        )

        process_id = event.get("process_id")

        access_types = tuple(sorted(
            event.get("access_types", [])
        ))

        process_image = (
            event.get("process_image") or ""
        ).lower()

        key = (
            file_path,
            process_id,
            process_image,
            access_types
        )

        timestamp = self.normalize_timestamp(
            event.get("timestamp")
        )

        parsed_timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        # Remove expired entries.
        expired_keys = []

        for existing_key, existing_time in (
            self.recent_security_events.items()
        ):

            age = (
                parsed_timestamp - existing_time
            ).total_seconds()

            if age > self.security_dedup_window:
                expired_keys.append(existing_key)

        for expired_key in expired_keys:
            self.recent_security_events.pop(
                expired_key, None
            )

        previous_timestamp = self.recent_security_events.get(key)

        if previous_timestamp:

            difference = abs(
                (parsed_timestamp - previous_timestamp).total_seconds()
            )

            if difference <= self.security_dedup_window:

                logger.debug(
                    "Duplicate Security event suppressed: %s",
                    file_path
                )

                return True

        self.recent_security_events[key] = parsed_timestamp

        return False

    # --------------------------------------------------
    # 5. NORMALIZE WINDOWS FILE EVENTS
    # --------------------------------------------------

    def handle_windows_event(self, event):

        with self.lock:

            file_path = event.get("file_path")

            # Ignore directory events.
            if self.is_directory_path(file_path):

                logger.debug(
                    "Directory event filtered: %s",
                    file_path
                )

                return

            event_id = str(uuid.uuid4())

            normalized = {
                "event_id": event_id,
                "timestamp": self.normalize_timestamp(
                    event.get("timestamp")
                ),
                "event_category": "FILE_ACTIVITY",
                "action": event.get("event_type"),
                "file": self.get_file_information(file_path),
                "process": {
                    "pid": event.get("process_id"),
                    "guid": None,
                    "image": None,
                    "command_line": None
                },
                "access": {
                    "types": []
                },
                "sources": ["windows_monitor"]
            }

            correlator_event = dict(event)
            correlator_event["pipeline_event_id"] = event_id
            correlator_event["timestamp"] = normalized["timestamp"]

            self._emit(normalized)

            correlated = self.correlator.add_windows_event(
                correlator_event
            )

            if correlated:
                self._emit_correlation(correlated)

    # --------------------------------------------------
    # 6. NORMALIZE SYSMON EVENTS
    # --------------------------------------------------

    def handle_sysmon_event(self, event):

        with self.lock:

            event_type = event.get("event_type")

            # Sysmon file events are used for correlation.
            if event_type in (
                "FILE_CREATED",
                "FILE_DELETED"
            ):

                correlator_event = dict(event)

                correlated = self.correlator.add_sysmon_event(
                    correlator_event
                )

                if correlated:
                    self._emit_correlation(correlated)

                return

            # Process creation and termination.
            if event_type in (
                "PROCESS_CREATED",
                "PROCESS_TERMINATED"
            ):

                process_details = event.get(
                    "process_details", {}
                ) or {}

                normalized = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": self.normalize_timestamp(
                        event.get("timestamp")
                    ),
                    "event_category": "PROCESS_ACTIVITY",
                    "action": event_type,
                    "file": {
                        "path": None,
                        "name": None,
                        "extension": None
                    },
                    "process": {
                        "pid": event.get("process_id"),
                        "guid": event.get("process_guid"),
                        "image": event.get("process_image"),
                        "command_line": process_details.get(
                            "CommandLine"
                        )
                    },
                    "access": {
                        "types": []
                    },
                    "sources": ["sysmon"],
                    "sysmon": {
                        "event_id": event.get("sysmon_event_id"),
                        "record_id": event.get("event_record_id")
                    }
                }

                self._emit(normalized)

    # --------------------------------------------------
    # 7. NORMALIZE SECURITY AUDITING EVENTS
    # --------------------------------------------------

    def handle_security_event(self, event):

        with self.lock:

            file_path = event.get("file_path")

            # Ignore directory access events.
            if self.is_directory_path(file_path):

                logger.debug(
                    "Directory access event filtered: %s",
                    file_path
                )

                return

            # Suppress repeated Security 4663 events.
            if self.is_duplicate_security_event(event):
                return

            normalized = {
                "event_id": str(uuid.uuid4()),
                "timestamp": self.normalize_timestamp(
                    event.get("timestamp")
                ),
                "event_category": "FILE_ACCESS",
                "action": "ACCESS",
                "file": self.get_file_information(file_path),
                "process": {
                    "pid": event.get("process_id"),
                    "guid": None,
                    "image": event.get("process_image"),
                    "command_line": None
                },
                "access": {
                    "types": event.get("access_types", [])
                },
                "sources": ["security_auditing"],
                "security": {
                    "event_id": event.get("security_event_id"),
                    "record_id": event.get("event_record_id"),
                    "access_mask": event.get("access_mask"),
                    "handle_id": event.get("handle_id"),
                    "user_sid": event.get("user_sid")
                }
            }

            self._emit(normalized)

    # --------------------------------------------------
    # 8. CORRELATION OUTPUT
    # --------------------------------------------------

    def _emit_correlation(self, correlated):

        normalized = {
            "event_id": str(uuid.uuid4()),
            "timestamp": self.normalize_timestamp(
                correlated.get("timestamp")
            ),
            "event_category": "CORRELATION_METADATA",
            "action": "PROCESS_ENRICHMENT",
            "file": self.get_file_information(
                correlated.get("file_path")
            ),
            "process": {
                "pid": correlated.get("process_id"),
                "guid": correlated.get("process_guid"),
                "image": correlated.get("process_image"),
                "command_line": (
                    correlated.get("process_details", {}) or {}
                ).get("CommandLine")
            },
            "access": {
                "types": []
            },
            "sources": [
                "windows_monitor",
                "sysmon"
            ],
            "correlation": {
                "matched": True,
                "file_event_type": correlated.get(
                    "file_event_type"
                ),
                "sysmon_event_id": correlated.get(
                    "sysmon_event_id"
                ),
                "sysmon_record_id": correlated.get(
                    "sysmon_record_id"
                ),
                "time_difference_seconds": correlated.get(
                    "time_difference_seconds"
                )
            }
        }

        self._emit(normalized)

    # --------------------------------------------------
    # 9. SEND NORMALIZED EVENT
    # --------------------------------------------------

    def _emit(self, event):

        try:

            if self.event_callback:
                self.event_callback(event)

            else:
                logger.info(
                    "PIPELINE EVENT: %s",
                    json.dumps(event, indent=2)
                )

        except Exception:

            logger.exception(
                "Failed to deliver normalized event."
            )
