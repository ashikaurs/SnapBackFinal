
import ctypes
import logging
import shutil
import subprocess

from pathlib import Path

logger = logging.getLogger("SNAP_BACK.SysmonManager")


class SysmonManager:

    def __init__(self, config_path):
        self.config_path = Path(config_path).resolve()

        self.project_root = Path(__file__).resolve().parents[2]

        self.binary_candidates = [
            self.project_root / "agent" / "bin" / "sysmon64.exe",
            self.project_root / "agent" / "bin" / "sysmon.exe"
        ]

        self.sysmon_exe = None

    @staticmethod
    def is_admin():
        try:
            return bool(
                ctypes.windll.shell32.IsUserAnAdmin()
            )
        except Exception:
            return False

    def locate_sysmon(self):

        # Check system PATH first.
        executable = shutil.which("sysmon64.exe")

        if not executable:
            executable = shutil.which("sysmon.exe")

        if executable:
            self.sysmon_exe = Path(executable)
            return self.sysmon_exe

        # Check bundled binaries.
        for candidate in self.binary_candidates:
            if candidate.is_file():
                self.sysmon_exe = candidate
                return candidate

        raise FileNotFoundError(
            "Sysmon executable not found. "
            "Place the approved Sysmon executable "
            "inside agent/bin."
        )

    def run_command(self, arguments):

        result = subprocess.run(
            [str(self.sysmon_exe), *arguments],
            capture_output=True,
            text=True,
            timeout=60
        )

        output = (
            (result.stdout or "") +
            (result.stderr or "")
        )

        logger.info("Sysmon output: %s", output.strip())

        if result.returncode != 0:
            raise RuntimeError(
                f"Sysmon command failed: {output}"
            )

        return output

    def is_installed(self):

        result = subprocess.run(
            [
                "sc.exe",
                "query",
                "Sysmon"
            ],
            capture_output=True,
            text=True
        )

        return result.returncode == 0

    def ensure_sysmon(self):

        if not self.is_admin():
            raise PermissionError(
                "Administrator privileges are required "
                "to install or configure Sysmon. "
                "Restart SNAP_BACK as Administrator."
            )

        if not self.config_path.is_file():
            raise FileNotFoundError(
                f"Sysmon configuration not found: "
                f"{self.config_path}"
            )

        self.locate_sysmon()

        logger.info("Using Sysmon executable: %s", self.sysmon_exe)

        if self.is_installed():

            logger.info("Existing Sysmon installation detected.")

            self.run_command([
                "-c",
                str(self.config_path)
            ])

            logger.info("Sysmon configuration updated.")

        else:

            logger.info("Sysmon is not installed. Installing...")

            self.run_command([
                "-accepteula",
                "-i",
                str(self.config_path)
            ])

            logger.info("Sysmon installation completed.")

        # Verify the final configuration.
        output = self.run_command(["-c"])

        if "Current configuration" not in output:
            raise RuntimeError(
                "Sysmon configuration verification failed."
            )

        logger.info("Sysmon is installed and configured successfully.")
        return True
