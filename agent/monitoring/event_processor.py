
"""
SNAP_BACK - Event Processor

Converts raw Windows file-system notifications
into standardized events for further analysis.
"""

import logging
import uuid

from datetime import datetime, timezone
from pathlib import Path


logger = logging.getLogger("SNAP_BACK.EVENT_PROCESSOR")


# --------------------------------------------------
# 1. SUPPORTED EVENT TYPES
# --------------------------------------------------

VALID_EVENT_TYPES = {
    "CREATED",
    "MODIFIED",
    "DELETED",
    "RENAMED_OLD",
    "RENAMED_NEW"
}


# --------------------------------------------------
# 2. EVENT PROCESSOR
# --------------------------------------------------

class EventProcessor:

    def __init__(self):

        logger.info("Event processor initialized.")

    # --------------------------------------------------
    # PROCESS RAW EVENT
    # --------------------------------------------------

    def process_event(self, raw_event):

        """
        Validate and standardize a raw file event.
        """

        if not isinstance(raw_event, dict):
            logger.warning("Invalid event received.")
            return None

        event_type = raw_event.get("event_type")
        file_path = raw_event.get("file_path")
        directory = raw_event.get("directory")

        # Validate required fields
        if event_type not in VALID_EVENT_TYPES:
            logger.warning(
                "Unsupported event type: %s",
                event_type
            )
            return None

        if not file_path or not directory:
            logger.warning(
                "Event is missing required information."
            )
            return None

        # Extract file information
        path = Path(file_path)

        # Generate standardized event
        processed_event = {

            "event_id": str(uuid.uuid4()),

            "event_type": event_type,

            "file_path": str(path),

            "file_name": path.name,

            "file_extension": path.suffix.lower(),

            "directory": str(Path(directory)),

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(timespec="milliseconds"),

            # Process correlation will be implemented later.
            "process_id": None,

            "source": "windows_monitor",

            "processed": True
        }

        logger.info(
            "Event processed: %s | %s",
            event_type,
            path.name
        )

        return processed_event


# --------------------------------------------------
# 3. STANDALONE TEST
# --------------------------------------------------

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    processor = EventProcessor()

    sample_event = {

        "event_type": "MODIFIED",

        "file_path": (
            "C:\\SNAP_BACK_TEST\\test.txt"
        ),

        "directory": "C:\\SNAP_BACK_TEST"
    }

    result = processor.process_event(sample_event)

    print("\nProcessed Event:")
    print(result)
