
import logging
import psutil
from datetime import datetime, timezone

logger = logging.getLogger("SNAP_BACK.PROCESS_MONITOR")


class ProcessMonitor:

    def __init__(self):
        logger.info("Process monitor initialized.")

    def get_process_details(self, pid):

        try:
            process = psutil.Process(pid)

            process_info = {
                "process_id": process.pid,
                "process_name": process.name(),
                "executable_path": process.exe(),
                "parent_process_id": process.ppid(),
                "creation_time": datetime.fromtimestamp(
                    process.create_time(),
                    timezone.utc
                ).isoformat(timespec="milliseconds"),
                "status": process.status()
            }

            logger.info(
                "Process identified: %s | PID: %s",
                process_info["process_name"],
                process_info["process_id"]
            )

            return process_info

        except psutil.NoSuchProcess:
            logger.warning("Process with PID %s no longer exists.", pid)

        except psutil.AccessDenied:
            logger.warning("Access denied while inspecting PID %s.", pid)

        except psutil.Error:
            logger.exception("Failed to inspect PID %s.", pid)

        return None


if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    monitor = ProcessMonitor()

    current_pid = psutil.Process().pid

    print("\nCurrent Process Details:")
    print(monitor.get_process_details(current_pid))
