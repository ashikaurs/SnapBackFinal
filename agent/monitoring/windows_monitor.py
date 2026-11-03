
"""
SNAP_BACK - Windows File Monitoring

Uses the Windows ReadDirectoryChangesW API
to monitor directory changes in real time.
"""

import ctypes
import logging
import os
import struct

from pathlib import Path
from ctypes import wintypes


logger = logging.getLogger("SNAP_BACK.MONITOR")


# --------------------------------------------------
# 1. WINDOWS API CONSTANTS
# --------------------------------------------------

FILE_LIST_DIRECTORY = 0x0001

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004

OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_CREATION = 0x00000040

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# --------------------------------------------------
# 2. FILE SYSTEM EVENT TYPES
# --------------------------------------------------

EVENT_ACTIONS = {
    1: "CREATED",
    2: "DELETED",
    3: "MODIFIED",
    4: "RENAMED_OLD",
    5: "RENAMED_NEW"
}


# --------------------------------------------------
# 3. WINDOWS API SETUP
# --------------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

CreateFileW = kernel32.CreateFileW
CreateFileW.restype = wintypes.HANDLE
CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE
]

ReadDirectoryChangesW = kernel32.ReadDirectoryChangesW
ReadDirectoryChangesW.restype = wintypes.BOOL
ReadDirectoryChangesW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
    wintypes.LPVOID
]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]


# --------------------------------------------------
# 4. WINDOWS FILE MONITOR
# --------------------------------------------------

class WindowsFileMonitor:

    def __init__(self, directory, recursive=True):

        self.directory = Path(directory)
        self.recursive = recursive
        self.handle = None

        self.buffer_size = 64 * 1024

        self.notify_filter = (
            FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_CREATION
        )

    # --------------------------------------------------
    # OPEN DIRECTORY HANDLE
    # --------------------------------------------------

    def _open_directory(self):

        if os.name != "nt":
            raise OSError(
                "Windows monitoring requires Windows."
            )

        if not self.directory.is_dir():
            raise NotADirectoryError(
                f"Directory does not exist: {self.directory}"
            )

        self.handle = CreateFileW(
            str(self.directory),
            FILE_LIST_DIRECTORY,
            (
                FILE_SHARE_READ
                | FILE_SHARE_WRITE
                | FILE_SHARE_DELETE
            ),
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

        if self.handle == INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()

            raise ctypes.WinError(error)

        logger.info(
            "Monitoring started: %s",
            self.directory
        )

    # --------------------------------------------------
    # PROCESS WINDOWS FILE EVENTS
    # --------------------------------------------------

    def _process_events(self, buffer, bytes_returned):

        offset = 0

        while offset < bytes_returned:

            next_offset, action, filename_length = (
                struct.unpack_from("<III", buffer, offset)
            )

            filename_start = offset + 12

            filename = buffer[
                filename_start:
                filename_start + filename_length
            ].decode("utf-16-le")

            event_type = EVENT_ACTIONS.get(
                action,
                "UNKNOWN"
            )

            full_path = self.directory / filename

            event = {
                "event_type": event_type,
                "file_path": str(full_path),
                "directory": str(self.directory)
            }

            logger.info(
                "File event: %s | %s",
                event_type,
                full_path
            )

            # Event processing integration will be added later.
            print(event)

            if next_offset == 0:
                break

            offset += next_offset

    # --------------------------------------------------
    # START MONITORING
    # --------------------------------------------------

    def start(self):

        self._open_directory()

        buffer = ctypes.create_string_buffer(
            self.buffer_size
        )

        bytes_returned = wintypes.DWORD()

        try:

            print(f"\nMonitoring: {self.directory}")
            print("Press CTRL+C to stop.\n")

            while True:

                success = ReadDirectoryChangesW(
                    self.handle,
                    buffer,
                    self.buffer_size,
                    self.recursive,
                    self.notify_filter,
                    ctypes.byref(bytes_returned),
                    None,
                    None
                )

                if not success:

                    error = ctypes.get_last_error()

                    raise ctypes.WinError(error)

                if bytes_returned.value == 0:

                    logger.warning(
                        "Monitoring buffer returned no events."
                    )

                    continue

                self._process_events(
                    buffer.raw,
                    bytes_returned.value
                )

        except KeyboardInterrupt:

            logger.info("Monitoring stopped by user.")

        finally:

            self.close()

    # --------------------------------------------------
    # CLOSE DIRECTORY HANDLE
    # --------------------------------------------------

    def close(self):

        if self.handle is not None:

            CloseHandle(self.handle)

            self.handle = None

            logger.info("Directory monitoring handle closed.")


# --------------------------------------------------
# 5. STANDALONE TEST
# --------------------------------------------------

if __name__ == "__main__":

    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )

    parser = argparse.ArgumentParser(
        description="SNAP_BACK Windows File Monitor"
    )

    parser.add_argument(
        "directory",
        help="Directory to monitor"
    )

    args = parser.parse_args()

    monitor = WindowsFileMonitor(args.directory)

    monitor.start()
