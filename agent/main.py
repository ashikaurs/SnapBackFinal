
"""
SNAP_BACK - Main Application Entry Point
"""

import logging

from monitoring.windows_monitor import WindowsFileMonitor
from monitoring.event_processor import EventProcessor

from config.settings import (
    APPLICATION_NAME,
    APPLICATION_VERSION,
    LOG_DIR,
    initialize_runtime_directories,
    validate_platform
)


# --------------------------------------------------
# 1. LOGGING CONFIGURATION
# --------------------------------------------------

def configure_logging():

    logging.basicConfig(
        level=logging.INFO,

        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(name)s | "
            "%(message)s"
        ),

        handlers=[
            logging.FileHandler(
                LOG_DIR / "snapback.log",
                encoding="utf-8"
            ),

            logging.StreamHandler()
        ]
    )


logger = logging.getLogger("SNAP_BACK")


# --------------------------------------------------
# 2. APPLICATION INITIALIZATION
# --------------------------------------------------

def initialize_application():

    validate_platform()

    initialize_runtime_directories()

    configure_logging()

    logger.info("=" * 55)

    logger.info(
        "%s v%s starting...",
        APPLICATION_NAME,
        APPLICATION_VERSION
    )




    logger.info("Platform validation successful.")

    logger.info("Runtime directories initialized.")

    logger.info("Application initialization completed.")


# --------------------------------------------------
# 3. MAIN FUNCTION
# --------------------------------------------------

def main():

    try:

        initialize_application()

        processor = EventProcessor()

        def handle_event(raw_event):
            processed_event = processor.process_event(raw_event)

            if processed_event:
                print("\nProcessed Event:")
                print(processed_event)

        monitor = WindowsFileMonitor(
            directory=r"C:\SNAP_BACK_TEST",
            event_callback=handle_event
        )

        logger.info("SNAP_BACK is ready.")
        monitor.start()


        # Monitoring integration will be added here.
        # Detection and response integration will follow.

    except Exception:

        logger.exception(
            "SNAP_BACK encountered an initialization error."
        )

        raise


# --------------------------------------------------
# 4. APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()
