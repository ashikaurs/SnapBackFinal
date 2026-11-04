
"""
SNAP_BACK - Sysmon Event Monitor
Reads Event ID 1 and 11 from the Sysmon Operational log.
"""

import logging
import subprocess
import time
import json
import xml.etree.ElementTree as ET

logger = logging.getLogger("SNAP_BACK.SYSMON")

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

POWERSHELL = "powershell.exe"


class SysmonMonitor:

    def __init__(self, event_callback, poll_interval=1):

        self.event_callback = event_callback
        self.poll_interval = poll_interval
        self.running = False
        self.last_record_number = 0

        logger.info("Sysmon monitor initialized.")

    def _get_latest_record_number(self):

        command = (
            'Get-WinEvent -LogName '
            '"Microsoft-Windows-Sysmon/Operational" '
            '-MaxEvents 1 | Select-Object -ExpandProperty RecordId'
        )

        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True
        )

        if result.returncode != 0 or not result.stdout.strip():
            raise RuntimeError(
                f"Failed to read Sysmon record number: {result.stderr}"
            )

        return int(result.stdout.strip())

    
    def _read_new_events(self):

        command = f"""
        $events = @(
            Get-WinEvent -LogName '{LOG_NAME}' `
                -FilterXPath "*[System[(EventID=1 or EventID=11) and (EventRecordID > {self.last_record_number})]]" `
                -ErrorAction SilentlyContinue |
            Sort-Object RecordId
        )

        $results = foreach ($event in $events) {{

            [xml]$xml = $event.ToXml()
            $data = @{{}}

            foreach ($item in $xml.Event.EventData.Data) {{
                $data[[string]$item.Name] = [string]$item.InnerText
            }}

            [PSCustomObject]@{{
                event_id = $event.Id
                event_record_id = $event.RecordId
                timestamp = $event.TimeCreated.ToUniversalTime().ToString("o")
                source = "sysmon"
                data = $data
            }}
        }}

        ConvertTo-Json -InputObject @($results) -Depth 5 -Compress
        """

        result = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20
        )

        if result.returncode != 0:
            logger.error("Sysmon query failed: %s", result.stderr)
            return

        output = result.stdout.strip()

        if not output:
            return

        try:
            events = json.loads(output)

            if isinstance(events, dict):
                events = [events]

            if events is None:
                return

            for event in events:

                record_id = int(event["event_record_id"])
                event_id = int(event["event_id"])
                data = event["data"]

                # Filter Event ID 11 outside monitored directory
                if event_id == 11:
                    target = data.get("TargetFilename", "")

                    if not target.lower().startswith(r"c:\snap_back_test"):
                        self.last_record_number = max(
                            self.last_record_number, record_id
                        )
                        continue

                # Filter collector's own PowerShell processes
                if event_id == 1:
                    image = data.get("Image", "").lower()
                    parent_image = data.get("ParentImage", "").lower()

                    if (
                        image.endswith("\\powershell.exe")
                        and parent_image.endswith("\\python.exe")
                    ):
                        self.last_record_number = max(
                            self.last_record_number, record_id
                        )
                        continue

                self.last_record_number = max(
                    self.last_record_number, record_id
                )

                parsed_event = {
                    "event_id": event_id,
                    "event_record_id": record_id,
                    "timestamp": event["timestamp"],
                    "source": event["source"],
                    **data
                }

                logger.info(
                    "Sysmon Event %s | PID: %s",
                    event_id,
                    parsed_event.get("ProcessId")
                )

                if self.event_callback:
                    self.event_callback(parsed_event)

        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            logger.exception("Failed to process Sysmon events.")

               
    def start(self):

        self.last_record_number = self._get_latest_record_number()

        self.running = True

        logger.info(
            "Sysmon monitoring started. Starting after record %s.",
            self.last_record_number
        )

        try:
            while self.running:
                self._read_new_events()
                time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            logger.info("Sysmon monitoring stopped.")

        finally:
            self.stop()

    def stop(self):
        self.running = False
