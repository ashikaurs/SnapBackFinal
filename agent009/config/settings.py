
"""
SNAP_BACK - Central Application Configuration

All application-wide paths and configuration values
are maintained in this file.
"""

import os
from pathlib import Path






# --------------------------------------------------
# 1. PROJECT PATHS
# --------------------------------------------------



PROGRAM_DATA = Path(
    os.environ.get("PROGRAMDATA", r"C:\ProgramData")
)


# Root directory of the SNAP_BACK project
PROJECT_ROOT = Path(__file__).resolve().parents[2]

AGENT_DIR = PROJECT_ROOT / "agent"


APP_DATA_DIR = PROGRAM_DATA / "SNAP_BACK"



# Runtime directories
CONFIG_DIR = APP_DATA_DIR / "config"
LOG_DIR = APP_DATA_DIR / "logs"
INVENTORY_DIR = APP_DATA_DIR / "inventory"
DECOY_DIR = APP_DATA_DIR / "decoys"
BACKUP_DIR = APP_DATA_DIR / "backups"

INVENTORY_FILE = INVENTORY_DIR / "file_inventory.json"




SYSMON_CONFIG_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "setup"
    / "sysmonconfig.xml"
)

SYSMON_CONFIG_FILE = CONFIG_DIR / "sysmonconfig.xml"




# --------------------------------------------------
# 2. MONITORING CONFIGURATION
# --------------------------------------------------

# Directories selected by the user for protection.
# Initially empty; we will implement folder selection later.
MONITORED_DIRECTORIES = []

# Maximum size of a Windows directory monitoring buffer
MONITOR_BUFFER_SIZE = 64 * 1024

# Process monitoring interval (seconds)
PROCESS_CHECK_INTERVAL = 2


# --------------------------------------------------
# 3. DETECTION CONFIGURATION
# --------------------------------------------------

# Entropy ranges from 0 to 8 bits per byte.
ENTROPY_THRESHOLD = 7.2

# Minimum suspicious file modification ratio
MODIFICATION_RATIO_THRESHOLD = 0.30

# Risk score thresholds
RISK_LOW = 30
RISK_MEDIUM = 60
RISK_HIGH = 80


# --------------------------------------------------
# 4. DECOY CONFIGURATION
# --------------------------------------------------

DECOY_ENABLED = True

# Number of decoy files to create initially
DECOY_FILE_COUNT = 5


# --------------------------------------------------
# 5. RESPONSE CONFIGURATION
# --------------------------------------------------

# Require confirmation before taking destructive actions
REQUIRE_USER_CONFIRMATION = True

# Automatically initiate recovery only after
# an incident has been confirmed.
AUTO_RECOVERY = False


# --------------------------------------------------
# 6. BACKUP CONFIGURATION
# --------------------------------------------------

# Backup integrity verification is mandatory
VERIFY_BACKUPS = True

# Preserve original file metadata where possible
PRESERVE_METADATA = True


# --------------------------------------------------
# 7. APPLICATION CONFIGURATION
# --------------------------------------------------

APPLICATION_NAME = "SNAP_BACK"
APPLICATION_VERSION = "1.0.0"

SUPPORTED_OS = "Windows"









# --------------------------------------------------
# 8. RUNTIME DIRECTORY INITIALIZATION
# --------------------------------------------------

def initialize_runtime_directories():
    """
    Create application runtime directories
    if they do not already exist.
    """

    directories = [
        CONFIG_DIR,
        BACKUP_DIR,
        LOG_DIR,
        DECOY_DIR,
        INVENTORY_DIR
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)




# --------------------------------------------------
# 9. PLATFORM VALIDATION
# --------------------------------------------------

def validate_platform():
    """
    Ensure SNAP_BACK is running on Windows.
    """

    if os.name != "nt":
        raise OSError(
            "SNAP_BACK currently supports Windows only."
        )
