import logging

from agent.monitoring.sysmon_monitor import SysmonMonitor


logging.basicConfig(level=logging.INFO)


def handle_sysmon_event(event):

    print("\n========== SYSMON EVENT ==========")
    print(event)


monitor = SysmonMonitor(
    event_callback=handle_sysmon_event
)

monitor.start()