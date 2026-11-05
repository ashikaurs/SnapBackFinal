import logging

from monitoring.security_monitor import SecurityMonitor


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def handle_event(event):

    print("\n========== SECURITY EVENT ==========")

    for key, value in event.items():
        print(f"{key}: {value}")


protected_folders = [
    r"C:\Users\kanik\Downloads\snapBackTest"
]


monitor = SecurityMonitor(
    event_callback=handle_event,
    protected_folders=protected_folders,
    poll_interval=1
)

monitor.start()