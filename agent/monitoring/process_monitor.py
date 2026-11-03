
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


    
    def get_running_processes(self):

        running_processes = []

        for process in psutil.process_iter(
            ['pid', 'name', 'exe', 'ppid', 'create_time', 'status']
        ):

            try:
                info = process.info

                process_info = {
                    "process_id": info["pid"],
                    "process_name": info["name"],
                    "executable_path": info["exe"],
                    "parent_process_id": info["ppid"],
                    "creation_time": datetime.fromtimestamp(
                        info["create_time"],
                        timezone.utc
                    ).isoformat(timespec="milliseconds")
                    if info["create_time"] else None,
                    "status": info["status"]
                }

                running_processes.append(process_info)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        logger.info(
            "Collected information for %d running processes.",
            len(running_processes)
        )

        return running_processes



if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    monitor = ProcessMonitor()

    processes = monitor.get_running_processes()

    print(f"\nTotal running processes: {len(processes)}")

    print("\nFirst 10 processes:")

    for process in processes[:10]:
        print(process)