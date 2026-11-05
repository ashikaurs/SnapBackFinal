
"""
SNAP_BACK - Event Correlator

Correlates filesystem events from WindowsFileMonitor
with file events collected by Sysmon.

Supported correlations:
    CREATED  <-> FILE_CREATED
    DELETED  <-> FILE_DELETED

General file modifications and renames are not
correlated with Sysmon because the configured
Sysmon events do not provide equivalent events.
"""

import logging
import os

from datetime import datetime, timezone


logger = logging.getLogger("SNAP_BACK.CORRELATOR")


class EventCorrelator:

    # Windows event type -> Sysmon event type
    EVENT_MAPPING = {
        "CREATED": "FILE_CREATED",
        "DELETED": "FILE_DELETED"
    }

    def __init__(
        self,
        time_window_seconds=5,
        pending_ttl_seconds=15,
        max_pending_events=1000
    ):

        self.time_window_seconds = time_window_seconds
        self.pending_ttl_seconds = pending_ttl_seconds
        self.max_pending_events = max_pending_events

        # Pending events waiting for their counterpart.
        self.pending_windows = {}
        self.pending_sysmon = {}

        logger.info(
            "Event correlator initialized. "
            "Time window: %s seconds.",
            self.time_window_seconds
        )

    # --------------------------------------------------
    # 1. NORMALIZE FILE PATH
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
    # 2. PARSE TIMESTAMP
    # --------------------------------------------------

    @staticmethod
    def parse_timestamp(timestamp):

        if not timestamp:
            return None

        try:

            parsed = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:

                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(timezone.utc)

        except (ValueError, TypeError, AttributeError):

            return None

    # --------------------------------------------------
    # 3. CLEAN EXPIRED EVENTS
    # --------------------------------------------------

    def _cleanup_expired_events(self):

        now = datetime.now(timezone.utc)

        for event_store in (
            self.pending_windows,
            self.pending_sysmon
        ):

            for file_path in list(event_store):

                remaining = []

                for entry in event_store[file_path]:

                    age = (
                        now - entry["timestamp"]
                    ).total_seconds()

                    if age <= self.pending_ttl_seconds:
                        remaining.append(entry)

                if remaining:
                    event_store[file_path] = remaining

                else:
                    event_store.pop(file_path, None)

        self._enforce_cache_limit()

    # --------------------------------------------------
    # 4. ENFORCE CACHE LIMIT
    # --------------------------------------------------

    def _enforce_cache_limit(self):

        while True:

            total = sum(
                len(entries)
                for entries in self.pending_windows.values()
            ) + sum(
                len(entries)
                for entries in self.pending_sysmon.values()
            )

            if total <= self.max_pending_events:
                break

            oldest_store = None
            oldest_path = None
            oldest_index = None
            oldest_timestamp = None

            for store in (
                self.pending_windows,
                self.pending_sysmon
            ):

                for file_path, entries in store.items():

                    for index, entry in enumerate(entries):

                        timestamp = entry["timestamp"]

                        if (
                            oldest_timestamp is None
                            or timestamp < oldest_timestamp
                        ):

                            oldest_timestamp = timestamp
                            oldest_store = store
                            oldest_path = file_path
                            oldest_index = index

            if oldest_store is None:
                break

            oldest_store[oldest_path].pop(
                oldest_index
            )

            if not oldest_store[oldest_path]:
                oldest_store.pop(oldest_path, None)

    # --------------------------------------------------
    # 5. ADD WINDOWS EVENT
    # --------------------------------------------------

    def add_windows_event(self, event):

        event_type = event.get("event_type")

        expected_sysmon_type = self.EVENT_MAPPING.get(
            event_type
        )

        # Only correlate event types with an equivalent
        # Sysmon event.
        if expected_sysmon_type is None:
            return None

        file_path = self.normalize_path(
            event.get("file_path")
        )

        timestamp = self.parse_timestamp(
            event.get("timestamp")
        )

        if not file_path or timestamp is None:
            return None

        self._cleanup_expired_events()

        self.pending_windows.setdefault(
            file_path, []
        ).append({
            "timestamp": timestamp,
            "event": event
        })

        self._enforce_cache_limit()

        return self._find_match(
            file_path,
            expected_sysmon_type
        )

    # --------------------------------------------------
    # 6. ADD SYSMON EVENT
    # --------------------------------------------------

    def add_sysmon_event(self, event):

        event_type = event.get("event_type")

        # Reverse mapping: Sysmon event -> Windows event.
        expected_windows_type = {
            sysmon_type: windows_type
            for windows_type, sysmon_type
            in self.EVENT_MAPPING.items()
        }.get(event_type)

        if expected_windows_type is None:
            return None

        file_path = self.normalize_path(
            event.get("file_path")
        )

        timestamp = self.parse_timestamp(
            event.get("timestamp")
        )

        if not file_path or timestamp is None:
            return None

        self._cleanup_expired_events()

        self.pending_sysmon.setdefault(
            file_path, []
        ).append({
            "timestamp": timestamp,
            "event": event
        })

        self._enforce_cache_limit()

        return self._find_match(
            file_path,
            event_type
        )

    # --------------------------------------------------
    # 7. FIND MATCHING EVENTS
    # --------------------------------------------------

    def _find_match(
        self,
        file_path,
        expected_sysmon_type
    ):

        windows_entries = self.pending_windows.get(
            file_path, []
        )

        sysmon_entries = self.pending_sysmon.get(
            file_path, []
        )

        best_match = None
        smallest_difference = None

        for windows_entry in windows_entries:

            for sysmon_entry in sysmon_entries:

                windows_event = windows_entry["event"]

                expected_type = self.EVENT_MAPPING.get(
                    windows_event.get("event_type")
                )

                if expected_type != expected_sysmon_type:
                    continue

                difference = abs(
                    (
                        windows_entry["timestamp"]
                        - sysmon_entry["timestamp"]
                    ).total_seconds()
                )

                if difference > self.time_window_seconds:
                    continue

                if (
                    smallest_difference is None
                    or difference < smallest_difference
                ):

                    best_match = (
                        windows_entry,
                        sysmon_entry
                    )

                    smallest_difference = difference

        if best_match is None:
            return None

        windows_entry, sysmon_entry = best_match

        # Remove both events so they cannot be reused.
        windows_entries.remove(windows_entry)
        sysmon_entries.remove(sysmon_entry)

        if not windows_entries:
            self.pending_windows.pop(file_path, None)

        if not sysmon_entries:
            self.pending_sysmon.pop(file_path, None)

        windows_event = windows_entry["event"]
        sysmon_event = sysmon_entry["event"]

        # Build a separate correlated event.
        correlated_event = {

            "event_type": "FILE_ACTIVITY_CORRELATED",

            "file_event_type": windows_event["event_type"],

            "file_path": windows_event["file_path"],

            "timestamp": windows_event["timestamp"],

            "source": "windows_monitor + sysmon",

            "correlated": True,

            "process_id": sysmon_event.get("process_id"),

            "process_guid": sysmon_event.get("process_guid"),

            "process_image": sysmon_event.get("process_image"),

            "process_details": sysmon_event.get(
                "process_details"
            ),

            "sysmon_event_id": sysmon_event.get(
                "sysmon_event_id"
            ),

            "sysmon_record_id": sysmon_event.get(
                "event_record_id"
            ),

            "time_difference_seconds": round(
                smallest_difference, 4
            )
        }

        logger.info(
            "FILE ACTIVITY CORRELATED | Type: %s | "
            "File: %s | Process: %s | PID: %s",
            correlated_event["file_event_type"],
            correlated_event["file_path"],
            correlated_event["process_image"],
            correlated_event["process_id"]
        )

        return correlated_event
