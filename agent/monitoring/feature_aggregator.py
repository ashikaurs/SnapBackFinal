"""
SNAP_BACK - Five-second feature aggregation.

Consumes normalized EventPipeline events and produces one JSON object
per attributed process per fixed five-second UTC window.
"""

import json
import logging
import math
import os
import ntpath
import threading
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("SNAP_BACK.FEATURE_AGGREGATOR")

WINDOW_SECONDS = 5
FLUSH_GRACE_SECONDS = 6.0
ENTROPY_SAMPLE_BYTES = 1024 * 1024
SIGNIFICANT_ENTROPY_INCREASE = 1.0

SUSPICIOUS_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".enc", ".wncry",
    ".locky", ".zepto", ".ryk", ".akira", ".conti",
    ".ryuk", ".cryptolocker", ".pay", ".ransom"
}

WRITE_ACCESS_TYPES = {
    "WRITE_DATA", "APPEND_DATA", "WRITE_ATTRIBUTES",
    "WRITE_EXTENDED_ATTRIBUTES", "DELETE", "DELETE_CHILD"
}


def _parse_timestamp(value):
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def _iso_timestamp(value):
    return value.astimezone(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _normal_path(value):
    if not value:
        return None
    return os.path.normcase(os.path.abspath(os.path.normpath(str(value))))


def calculate_entropy(file_path, sample_bytes=ENTROPY_SAMPLE_BYTES):
    """Calculate Shannon entropy (bits/byte) from up to the first 1 MiB."""
    try:
        with open(file_path, "rb") as file:
            data = file.read(sample_bytes)
        if not data:
            return 0.0

        counts = [0] * 256
        for byte in data:
            counts[byte] += 1

        length = len(data)
        entropy = 0.0
        for count in counts:
            if count:
                probability = count / length
                entropy -= probability * math.log2(probability)
        return round(entropy, 4)
    except (OSError, PermissionError):
        return None


class FeatureAggregator:
    """
    Builds the agreed ML JSON contract from normalized pipeline events.

    File notifications are initially unattributed. Sysmon correlation metadata
    and Security 4663 process/access records are used to attach a PID before
    the relevant time window is emitted.
    """

    def __init__(
        self,
        inventory_path,
        decoy_paths=None,
        output_callback=None,
        window_seconds=WINDOW_SECONDS,
        flush_grace_seconds=FLUSH_GRACE_SECONDS,
        poll_interval=0.25
    ):
        self.inventory_path = Path(inventory_path)
        self.output_callback = output_callback
        self.window_seconds = int(window_seconds)
        self.flush_grace_seconds = float(flush_grace_seconds)
        self.poll_interval = float(poll_interval)

        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.thread = None

        self.baseline = self._load_baseline()
        self.decoy_paths = {
            _normal_path(path)
            for path in (decoy_paths or [])
            if path
        }

        # bucket_start_epoch -> {"activities": [], "decoy_accesses": []}
        self.windows = {}
        self.activity_index = {}
        self.process_cache = {}

        # Recent Security 4663 attribution keyed by normalized file path.
        self.recent_path_processes = defaultdict(list)

        # Pending old names for ReadDirectoryChangesW rename pairs.
        self.pending_rename_old = []

        logger.info(
            "Feature aggregator initialized: %s-second windows, "
            "%s baseline files, %s decoys.",
            self.window_seconds,
            len(self.baseline),
            len(self.decoy_paths)
        )

    def _load_baseline(self):
        try:
            with open(self.inventory_path, "r", encoding="utf-8") as file:
                data = json.load(file)
            baseline = {
                _normal_path(path): metadata
                for path, metadata in data.items()
                if _normal_path(path)
            }

            # Older inventory files may predate entropy collection.
            # Initialize only missing baseline entropy values and persist them.
            changed = False
            for normalized_path, metadata in baseline.items():
                if "entropy" not in metadata:
                    entropy = calculate_entropy(normalized_path)
                    metadata["entropy"] = entropy
                    changed = True

            if changed:
                temporary_path = self.inventory_path.with_suffix(".tmp")
                with open(temporary_path, "w", encoding="utf-8") as file:
                    json.dump(data, file, indent=4)
                os.replace(temporary_path, self.inventory_path)
                logger.warning(
                    "Added missing entropy baselines to the existing inventory. "
                    "These values reflect files as they exist at SNAP_BACK startup."
                )

            return baseline
        except FileNotFoundError:
            logger.warning("File inventory not found: %s", self.inventory_path)
            return {}
        except (OSError, json.JSONDecodeError, AttributeError):
            logger.exception("Could not load file inventory baseline.")
            return {}

    def _bucket_start(self, timestamp):
        epoch = timestamp.timestamp()
        start_epoch = int(epoch // self.window_seconds) * self.window_seconds
        return start_epoch

    def _get_window(self, timestamp):
        start_epoch = self._bucket_start(timestamp)
        return self.windows.setdefault(
            start_epoch,
            {"activities": [], "decoy_accesses": []}
        ), start_epoch

    def _process_info(self, pid, image=None):
        cached = self.process_cache.get(pid, {})
        image = image or cached.get("process_path") or cached.get("process_image")
        process_name = ntpath.basename(image) if image else cached.get("process_name")
        return {
            "pid": int(pid) if pid is not None else None,
            "process_name": process_name or "unknown",
            "process_path": image
        }

    def _remember_process(self, pid, image=None):
        if pid is None:
            return
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return
        current = self.process_cache.setdefault(pid, {})
        if image:
            current["process_path"] = image
            current["process_image"] = image
            current["process_name"] = ntpath.basename(image)

    def consume(self, event):
        """Receive one normalized EventPipeline event."""
        if not isinstance(event, dict):
            return

        category = event.get("event_category")
        action = event.get("action")
        timestamp = _parse_timestamp(event.get("timestamp"))

        with self.lock:
            process = event.get("process") or {}
            pid = process.get("pid")
            image = process.get("image")

            if category == "PROCESS_ACTIVITY":
                self._remember_process(pid, image)
                return

            if category == "FILE_ACTIVITY":
                self._consume_file_activity(event, timestamp, pid, image)
                return

            if category == "CORRELATION_METADATA":
                self._consume_correlation(event, timestamp)
                return

            if category == "FILE_ACCESS":
                self._consume_file_access(event, timestamp, pid, image)
                return

    def _consume_file_activity(self, event, timestamp, pid=None, image=None):
        action = event.get("action")
        file_info = event.get("file") or {}
        file_path = file_info.get("path")
        normalized = _normal_path(file_path)

        if not normalized or action not in {
            "CREATED", "MODIFIED", "DELETED",
            "RENAMED_OLD", "RENAMED_NEW"
        }:
            return

        window, bucket_start = self._get_window(timestamp)
        activity = {
            "event_id": event.get("event_id"),
            "timestamp": timestamp,
            "action": action,
            "path": str(file_path),
            "normalized_path": normalized,
            "pid": int(pid) if pid is not None else None,
            "image": image,
            "bucket_start": bucket_start,
            "rename_old_path": None,
            "rename_new_path": None
        }

        if activity["pid"] is None:
            self._apply_recent_attribution(activity)

        window["activities"].append(activity)
        if activity["event_id"]:
            self.activity_index[activity["event_id"]] = activity

        # Pair the two notifications emitted by ReadDirectoryChangesW.
        if action == "RENAMED_OLD":
            self.pending_rename_old.append(activity)
        elif action == "RENAMED_NEW":
            self._pair_rename(activity)

    def _apply_recent_attribution(self, activity):
        candidates = self.recent_path_processes.get(
            activity["normalized_path"], []
        )
        best = None
        best_delta = None
        for entry in candidates:
            delta = abs(
                (activity["timestamp"] - entry["timestamp"]).total_seconds()
            )
            if delta <= 2.0 and (best_delta is None or delta < best_delta):
                best = entry
                best_delta = delta
        if best:
            activity["pid"] = best["pid"]
            activity["image"] = best["image"]

    def _consume_correlation(self, event, timestamp):
        correlation = event.get("correlation") or {}
        pipeline_event_id = correlation.get("pipeline_event_id")
        pid = (event.get("process") or {}).get("pid")
        image = (event.get("process") or {}).get("image")

        if pid is None:
            return

        self._remember_process(pid, image)
        activity = self.activity_index.get(pipeline_event_id)
        if activity is None:
            # Fallback: match the most recent same-path action.
            path = _normal_path((event.get("file") or {}).get("path"))
            action = correlation.get("file_event_type")
            candidates = []
            for window in self.windows.values():
                for item in window["activities"]:
                    if item["normalized_path"] == path and item["action"] == action:
                        delta = abs((timestamp - item["timestamp"]).total_seconds())
                        if delta <= 5:
                            candidates.append((delta, item))
            if candidates:
                activity = min(candidates, key=lambda item: item[0])[1]

        if activity is not None:
            activity["pid"] = int(pid)
            activity["image"] = image

    def _consume_file_access(self, event, timestamp, pid=None, image=None):
        file_info = event.get("file") or {}
        file_path = file_info.get("path")
        normalized = _normal_path(file_path)
        if not normalized or pid is None:
            return

        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return

        self._remember_process(pid, image)
        access_types = set((event.get("access") or {}).get("types") or [])

        self.recent_path_processes[normalized].append({
            "timestamp": timestamp,
            "pid": pid,
            "image": image
        })

        # Keep only recent attribution records.
        cutoff = timestamp.timestamp() - 5
        self.recent_path_processes[normalized] = [
            item for item in self.recent_path_processes[normalized]
            if item["timestamp"].timestamp() >= cutoff
        ]

        # Security 4663 is access evidence, not proof of a successful write.
        # Use it for attribution and decoy access only; file changes are counted
        # from ReadDirectoryChangesW notifications.
        window, _ = self._get_window(timestamp)
        if normalized in self.decoy_paths:
            window["decoy_accesses"].append({
                "path": normalized,
                "pid": pid,
                "image": image,
                "timestamp": timestamp
            })

        # Attach the Security process to a nearby filesystem notification.
        if access_types.intersection(WRITE_ACCESS_TYPES):
            best = None
            best_delta = None
            for bucket in self.windows.values():
                for activity in bucket["activities"]:
                    matches_path = (
                        activity["normalized_path"] == normalized
                        or (
                            activity.get("rename_old_path")
                            and _normal_path(activity["rename_old_path"]) == normalized
                        )
                    )
                    if not matches_path:
                        continue
                    if activity["pid"] is not None:
                        continue
                    delta = abs(
                        (timestamp - activity["timestamp"]).total_seconds()
                    )
                    if delta <= 2 and (best_delta is None or delta < best_delta):
                        best = activity
                        best_delta = delta
            if best:
                best["pid"] = pid
                best["image"] = image

                # If the matched notification is the old side of a rename,
                # propagate its process attribution to the paired new side.
                if best["action"] == "RENAME_OLD_CONSUMED":
                    for bucket in self.windows.values():
                        for paired in bucket["activities"]:
                            if (
                                paired.get("rename_old_path")
                                and _normal_path(paired["rename_old_path"]) == normalized
                            ):
                                paired["pid"] = pid
                                paired["image"] = image

    def _pair_rename(self, new_activity):
        candidates = []
        for old_activity in self.pending_rename_old:
            delta = abs(
                (new_activity["timestamp"] - old_activity["timestamp"]).total_seconds()
            )
            if delta <= 3:
                candidates.append((delta, old_activity))

        if not candidates:
            return

        _, old_activity = min(candidates, key=lambda item: item[0])
        self.pending_rename_old.remove(old_activity)

        new_activity["rename_old_path"] = old_activity["path"]
        new_activity["rename_new_path"] = new_activity["path"]

        # Prefer a known PID from either side of the rename pair.
        if new_activity["pid"] is None and old_activity["pid"] is not None:
            new_activity["pid"] = old_activity["pid"]
            new_activity["image"] = old_activity["image"]

        if new_activity["pid"] is None:
            recent = self.recent_path_processes.get(
                old_activity["normalized_path"], []
            )
            for entry in reversed(recent):
                if abs(
                    (new_activity["timestamp"] - entry["timestamp"]).total_seconds()
                ) <= 2.0:
                    new_activity["pid"] = entry["pid"]
                    new_activity["image"] = entry["image"]
                    break

        # Mark the old notification as consumed; only RENAMED_NEW is counted.
        old_activity["action"] = "RENAME_OLD_CONSUMED"

    def _file_metrics(self, old_path, current_path):
        old_key = _normal_path(old_path)
        new_key = _normal_path(current_path)
        baseline = self.baseline.get(old_key) or self.baseline.get(new_key) or {}

        before_entropy = baseline.get("entropy")
        before_size = baseline.get("size")

        after_entropy = calculate_entropy(current_path) if current_path and os.path.isfile(current_path) else None
        try:
            after_size = os.path.getsize(current_path) if current_path and os.path.isfile(current_path) else None
        except OSError:
            after_size = None

        size_change_percent = None
        if isinstance(before_size, (int, float)) and before_size > 0 and isinstance(after_size, (int, float)):
            size_change_percent = abs(after_size - before_size) / before_size * 100.0

        entropy_increase = None
        if isinstance(before_entropy, (int, float)) and isinstance(after_entropy, (int, float)):
            entropy_increase = after_entropy - before_entropy

        return {
            "entropy_before": before_entropy,
            "entropy_after": after_entropy,
            "entropy_increase": entropy_increase,
            "size_change_percent": size_change_percent
        }

    def _build_process_output(self, bucket_start, process_key, activities, decoy_accesses):
        start = datetime.fromtimestamp(bucket_start, timezone.utc)
        end = datetime.fromtimestamp(
            bucket_start + self.window_seconds, timezone.utc
        )

        process_info = self._process_info(
            process_key,
            next((item["image"] for item in activities if item["image"]), None)
            or next((item["image"] for item in decoy_accesses if item["image"]), None)
        )

        created = set()
        modified = {}
        deleted = set()
        renamed = {}
        directories = set()
        decoy_modified = set()
        decoy_deleted = set()
        entropy_records = []
        size_changes = []
        extension_changes = 0
        suspicious_extension_count = 0
        unique_files = set()
        renamed_path_aliases = {
            _normal_path(item["path"]): _normal_path(item["rename_old_path"])
            for item in activities
            if item["pid"] == process_key
            and item["action"] == "RENAMED_NEW"
            and item.get("rename_old_path")
        }

        for item in activities:
            if item["pid"] != process_key:
                continue

            action = item["action"]
            path = item["path"]
            normalized = item["normalized_path"]

            if action == "CREATED":
                created.add(normalized)
                unique_files.add(renamed_path_aliases.get(normalized, normalized))
                directories.add(os.path.dirname(path))
            elif action == "MODIFIED":
                modified[normalized] = path
                unique_files.add(renamed_path_aliases.get(normalized, normalized))
                directories.add(os.path.dirname(path))
                if normalized in self.decoy_paths:
                    decoy_modified.add(normalized)
            elif action == "DELETED":
                deleted.add(normalized)
                unique_files.add(renamed_path_aliases.get(normalized, normalized))
                directories.add(os.path.dirname(path))
                if normalized in self.decoy_paths:
                    decoy_deleted.add(normalized)
            elif action == "RENAMED_NEW" and item.get("rename_old_path"):
                old_path = item["rename_old_path"]
                old_key = _normal_path(old_path)
                renamed[old_key] = (old_path, path)
                unique_files.add(old_key)
                directories.add(os.path.dirname(old_path))
                directories.add(os.path.dirname(path))

                old_ext = Path(old_path).suffix.lower()
                new_ext = Path(path).suffix.lower()
                if old_ext != new_ext:
                    extension_changes += 1
                if new_ext in SUSPICIOUS_EXTENSIONS:
                    suspicious_extension_count += 1
                if old_key in self.decoy_paths or normalized in self.decoy_paths:
                    decoy_modified.add(old_key if old_key in self.decoy_paths else normalized)

        # Content-based features are sampled once per affected file/window.
        for path in modified.values():
            metrics = self._file_metrics(path, path)
            if metrics["entropy_before"] is not None and metrics["entropy_after"] is not None:
                entropy_records.append(metrics)
            if metrics["size_change_percent"] is not None:
                size_changes.append(metrics["size_change_percent"])

        for old_path, new_path in renamed.values():
            metrics = self._file_metrics(old_path, new_path)
            if metrics["entropy_before"] is not None and metrics["entropy_after"] is not None:
                entropy_records.append(metrics)
            if metrics["size_change_percent"] is not None:
                size_changes.append(metrics["size_change_percent"])

        entropy_before_values = [item["entropy_before"] for item in entropy_records]
        entropy_after_values = [item["entropy_after"] for item in entropy_records]
        entropy_increases = [item["entropy_increase"] for item in entropy_records]
        significant_count = sum(
            1 for value in entropy_increases
            if value is not None and value >= SIGNIFICANT_ENTROPY_INCREASE
        )

        process_decoy_accesses = {
            item["path"] for item in decoy_accesses
            if item["pid"] == process_key
        }
        decoy_accessed = len(process_decoy_accesses)
        decoy_modified_count = len(decoy_modified)
        decoy_deleted_count = len(decoy_deleted)

        files_created = len(created)
        files_modified = len(modified)
        files_deleted = len(deleted)
        files_renamed = len(renamed)
        total_operations = (
            files_created + files_modified + files_deleted + files_renamed
        )
        duration = float(self.window_seconds)

        average = lambda values: round(sum(values) / len(values), 4) if values else 0.0

        return {
            "window_start": _iso_timestamp(start),
            "window_end": _iso_timestamp(end),
            "window_duration_seconds": self.window_seconds,
            "process": process_info,
            "file_activity": {
                "files_created": files_created,
                "files_modified": files_modified,
                "files_deleted": files_deleted,
                "files_renamed": files_renamed,
                "unique_files_affected": len(unique_files)
            },
            "activity_rates": {
                "modifications_per_second": round(files_modified / duration, 4),
                "deletions_per_second": round(files_deleted / duration, 4),
                "renames_per_second": round(files_renamed / duration, 4),
                "total_operations_per_second": round(total_operations / duration, 4)
            },
            "entropy": {
                "average_entropy_before": average(entropy_before_values),
                "average_entropy_after": average(entropy_after_values),
                "average_entropy_increase": average(entropy_increases),
                "files_with_significant_entropy_increase": significant_count
            },
            "file_changes": {
                "average_size_change_percent": average(size_changes),
                "extension_changes": extension_changes,
                "suspicious_extension_count": suspicious_extension_count
            },
            "directory_activity": {
                "directories_affected": len(directories)
            },
            "decoy_activity": {
                "decoy_files_accessed": decoy_accessed,
                "decoy_files_modified": decoy_modified_count,
                "decoy_files_deleted": decoy_deleted_count,
                "decoy_triggered": bool(
                    decoy_accessed or decoy_modified_count or decoy_deleted_count
                )
            }
        }

    def flush_ready_windows(self, force=False):
        now_epoch = datetime.now(timezone.utc).timestamp()
        completed_buckets = []

        with self.lock:
            for bucket_start in sorted(list(self.windows)):
                window_end = bucket_start + self.window_seconds
                if not force and now_epoch < window_end + self.flush_grace_seconds:
                    continue

                bucket = self.windows.pop(bucket_start)
                grouped_activities = defaultdict(list)
                grouped_decoys = defaultdict(list)

                for item in bucket["activities"]:
                    if item["pid"] is not None and item["action"] != "RENAME_OLD_CONSUMED":
                        grouped_activities[int(item["pid"])].append(item)

                for item in bucket["decoy_accesses"]:
                    grouped_decoys[int(item["pid"])].append(item)

                # Snapshot completed data while holding the lock. Entropy and
                # size inspection happens after releasing it so file reads do
                # not block the live event pipeline.
                completed_buckets.append((
                    bucket_start,
                    grouped_activities,
                    grouped_decoys
                ))

                for item in bucket["activities"]:
                    if item.get("event_id"):
                        self.activity_index.pop(item["event_id"], None)

            cutoff = now_epoch - 10
            self.pending_rename_old = [
                item for item in self.pending_rename_old
                if item["timestamp"].timestamp() >= cutoff
            ]
            for path in list(self.recent_path_processes):
                self.recent_path_processes[path] = [
                    item for item in self.recent_path_processes[path]
                    if item["timestamp"].timestamp() >= cutoff
                ]
                if not self.recent_path_processes[path]:
                    self.recent_path_processes.pop(path, None)

        ready = []
        for bucket_start, grouped_activities, grouped_decoys in completed_buckets:
            process_ids = set(grouped_activities) | set(grouped_decoys)
            for pid in sorted(process_ids):
                ready.append(
                    self._build_process_output(
                        bucket_start,
                        pid,
                        grouped_activities.get(pid, []),
                        grouped_decoys.get(pid, [])
                    )
                )

        for result in ready:
            self._deliver(result)

        return ready

    def _deliver(self, feature_vector):
        serialized = json.dumps(feature_vector, indent=2)
        try:
            if self.output_callback:
                self.output_callback(feature_vector)
            else:
                logger.info("ML_FEATURE_VECTOR:\n%s", serialized)
        except Exception:
            logger.exception("Feature vector delivery failed.")

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()

        def worker():
            while not self.stop_event.wait(self.poll_interval):
                self.flush_ready_windows()

        self.thread = threading.Thread(
            target=worker,
            name="Feature-Aggregator",
            daemon=True
        )
        self.thread.start()
        logger.info("Feature aggregation thread started.")

    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
        self.flush_ready_windows(force=True)
        logger.info("Feature aggregation stopped.")
