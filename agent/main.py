import subprocess
import hashlib
import json
import logging
import os
import random
import shutil
from datetime import datetime, timezone
from pathlib import Path

from inventory.file_inventory import FileInventory

from config.settings import (
    APPLICATION_NAME,
    APPLICATION_VERSION,
    CONFIG_DIR,
    LOG_DIR,
    INVENTORY_FILE,
    DECOY_DIR,
    SYSMON_CONFIG_SOURCE,
    SYSMON_CONFIG_FILE,
    initialize_runtime_directories,
    validate_platform,
    DECOY_FILE_COUNT
)

from setup.sysmon_manager import SysmonManager


logger = logging.getLogger("SNAP_BACK")

PROTECTED_FOLDERS_FILE = CONFIG_DIR / "protected_folders.json"
DECOY_METADATA_FILE = DECOY_DIR / "decoy_metadata.json"

DECOYS_PER_FOLDER = DECOY_FILE_COUNT


# --------------------------------------------------
# LOGGING
# --------------------------------------------------

def configure_logging():
    logging.basicConfig(
        filename=LOG_DIR / "snapback.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


# --------------------------------------------------
# APPLICATION INITIALIZATION
# --------------------------------------------------

def initialize_application():
    validate_platform()
    initialize_runtime_directories()
    configure_logging()

    logger.info(
        "%s version %s starting",
        APPLICATION_NAME,
        APPLICATION_VERSION
    )

    if not SYSMON_CONFIG_SOURCE.exists():
        raise FileNotFoundError(
            f"Sysmon configuration not found: {SYSMON_CONFIG_SOURCE}"
        )

    shutil.copy2(
        SYSMON_CONFIG_SOURCE,
        SYSMON_CONFIG_FILE
    )

    sysmon = SysmonManager(SYSMON_CONFIG_FILE)
    sysmon.ensure_sysmon()

    print("\nSNAP_BACK initialized successfully.")


# --------------------------------------------------
# PATH UTILITIES
# --------------------------------------------------

def normalize_path(path):
    return os.path.normcase(
        str(Path(path).resolve())
    )


# --------------------------------------------------
# PROTECTED FOLDER REGISTRY
# --------------------------------------------------

def load_protected_folders():
    if not PROTECTED_FOLDERS_FILE.exists():
        return []

    try:
        with open(
            PROTECTED_FOLDERS_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Invalid protected folder registry.")

        folders = data.get("protected_folders", [])

        if not isinstance(folders, list):
            raise ValueError("Invalid protected folder list.")

        valid_folders = []

        for folder in folders:
            path = Path(folder)

            if path.exists() and path.is_dir():
                valid_folders.append(str(path.resolve()))

        return valid_folders

    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(
            f"Could not read protected folder registry: {error}"
        )


def save_protected_folders(folders):
    data = {
        "protected_folders": folders,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }

    temp_file = PROTECTED_FOLDERS_FILE.with_suffix(".tmp")

    with open(
        temp_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(data, file, indent=4)

    temp_file.replace(PROTECTED_FOLDERS_FILE)


# --------------------------------------------------
# DECOY METADATA
# --------------------------------------------------

def load_decoy_metadata():
    if not DECOY_METADATA_FILE.exists():
        return {"decoys": []}

    try:
        with open(
            DECOY_METADATA_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Invalid decoy metadata.")

        if not isinstance(data.get("decoys"), list):
            raise ValueError("Invalid decoy records.")

        return data

    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError(
            f"Could not read decoy metadata: {error}"
        )


def save_decoy_metadata(metadata):
    temp_file = DECOY_METADATA_FILE.with_suffix(".tmp")

    with open(
        temp_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(metadata, file, indent=4)

    temp_file.replace(DECOY_METADATA_FILE)


# --------------------------------------------------
# INVENTORY INITIALIZATION
# --------------------------------------------------

def initialize_inventory(folder):
    print(f"\nInitializing inventory for: {folder}")

    inventory = FileInventory(INVENTORY_FILE)

    # Load the existing inventory instead of starting fresh.
    inventory.load_inventory()

    inventory.scan_directory(str(folder))

    # Remove existing SNAP_BACK decoys from the normal
    # user-file inventory. This matters if a folder is
    # removed and later added again.
    decoy_directory = (
        Path(folder) / "Reference Archive" / "2024"
    )

    if decoy_directory.exists():
        for decoy_file in decoy_directory.iterdir():
            if decoy_file.is_file():
                inventory.remove_file(str(decoy_file))

    inventory.save_inventory()

    print("Inventory updated successfully.")
    logger.info("Inventory updated for %s", folder)





def configure_decoy_permissions(directory, recursive=False):
    """
    Remove inherited Everyone: DENY (Delete Child)
    permissions from SNAP_BACK-owned directories.
    """

    command = [
        "icacls",
        str(directory),
        "/inheritance:d"
    ]

    if recursive:
        command.extend(["/T", "/C"])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Could not configure directory permissions: "
            f"{result.stderr or result.stdout}"
        )

    command = [
        "icacls",
        str(directory),
        "/remove:d",
        "*S-1-1-0"
    ]

    if recursive:
        command.extend(["/T", "/C"])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Could not remove inherited DENY permissions: "
            f"{result.stderr or result.stdout}"
        )


def prepare_decoy_directory_for_deletion(directory):
    """
    Prepare only the SNAP_BACK-owned decoy directory
    for safe deletion.
    """

    if not directory.exists():
        return

    configure_decoy_permissions(
        directory,
        recursive=True
    )

    result = subprocess.run(
        [
            "attrib",
            "-R",
            str(directory),
            "/S",
            "/D"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Could not remove read-only attributes: "
            f"{result.stderr or result.stdout}"
        )



# --------------------------------------------------
# DECOY CREATION
# --------------------------------------------------


def create_decoys(folder):
    folder = Path(folder).resolve()

    reference_directory = folder / "Reference Archive"
    decoy_directory = reference_directory / "2024"

    # Create the SNAP_BACK-owned parent directory.
    reference_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    # Fix inherited permissions before creating 2024.
    configure_decoy_permissions(reference_directory)

    # Create the actual decoy directory.
    decoy_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    # Fix permissions on an existing decoy directory too.
    configure_decoy_permissions(
        decoy_directory,
        recursive=True
    )

    metadata = load_decoy_metadata()
    records = metadata["decoys"]

    templates = {
        "Q4_Financial_Report.csv": (
            "Department,Revenue,Expenses,Profit\n"
            "Sales,450000,210000,240000\n"
            "Operations,320000,180000,140000\n"
        ),

        "Employee_Records.txt": (
            "EMPLOYEE RECORDS\n"
            "Employee ID: EMP-1042\n"
            "Department: Operations\n"
            "Status: Active\n"
        ),

        "Project_Status.json": (
            '{\n'
            '    "project": "Internal Operations",\n'
            '    "status": "In Progress",\n'
            '    "completion": 72\n'
            '}\n'
        ),

        "Client_Invoice_Log.csv": (
            "InvoiceID,Client,Amount,Status\n"
            "INV-1001,Client-A,25000,Paid\n"
            "INV-1002,Client-B,18000,Pending\n"
        ),

        "System_Configuration.ini": (
            "[Application]\n"
            "Version=2.4\n"
            "Environment=Production\n\n"
            "[Database]\n"
            "ConnectionTimeout=30\n"
            "RetryCount=3\n"
        ),

        "Research_Notes.md": (
            "# Research Notes\n\n"
            "## Current Activities\n"
            "- Data collection\n"
            "- Performance analysis\n"
            "- Documentation\n"
        ),

        "Department_Activity.log": (
            "2024-10-01 INFO Department initialized\n"
            "2024-10-02 INFO Monthly report generated\n"
        ),

        "Asset_Register.xml": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Assets>\n'
            '    <Asset id="A101">\n'
            '        <Name>Workstation</Name>\n'
            '    </Asset>\n'
            '</Assets>\n'
        )
    }

    existing_files = [
        path for path in decoy_directory.iterdir()
        if path.is_file()
        and path.name.lower() not in {
            "desktop.ini",
            "thumbs.db"
        }
    ]

    registered_paths = {
        normalize_path(record["path"])
        for record in records
        if "path" in record
    }

    # Register files left behind by an interrupted run.
    for existing_file in existing_files:
        normalized = normalize_path(existing_file)

        if normalized in registered_paths:
            continue

        file_hash = hashlib.sha256(
            existing_file.read_bytes()
        ).hexdigest()

        records.append({
            "decoy_id": os.urandom(8).hex(),
            "path": str(existing_file.resolve()),
            "protected_folder": str(folder),
            "decoy_directory": str(decoy_directory),
            "filename": existing_file.name,
            "sha256": file_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "active"
        })

        registered_paths.add(normalized)
        save_decoy_metadata(metadata)

    missing_count = max(
        0,
        DECOYS_PER_FOLDER - len(existing_files)
    )

    available_templates = {
        name: content
        for name, content in templates.items()
        if not (decoy_directory / name).exists()
    }

    for _ in range(missing_count):
        if not available_templates:
            break

        filename = random.choice(
            list(available_templates.keys())
        )

        content = available_templates.pop(filename)
        decoy_path = decoy_directory / filename

        try:
            with open(
                decoy_path,
                "x",
                encoding="utf-8"
            ) as file:
                file.write(content)

        except FileExistsError:
            continue

        file_hash = hashlib.sha256(
            decoy_path.read_bytes()
        ).hexdigest()

        records.append({
            "decoy_id": os.urandom(8).hex(),
            "path": str(decoy_path.resolve()),
            "protected_folder": str(folder),
            "decoy_directory": str(decoy_directory),
            "filename": filename,
            "sha256": file_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "active"
        })

        save_decoy_metadata(metadata)

        print(f"Created decoy: {decoy_path}")

    print(f"Decoy initialization completed for: {folder}")
    logger.info("Decoys initialized for %s", folder)


# --------------------------------------------------
# ADD PROTECTED FOLDER
# --------------------------------------------------

def add_protected_folder(folders):
    folder_input = input(
        "\nEnter the folder path to protect: "
    ).strip().strip('"')

    folder = Path(folder_input)

    if not folder.exists() or not folder.is_dir():
        print("Invalid folder. Please enter an existing directory.")
        return

    folder = folder.resolve()
    normalized = normalize_path(folder)

    existing = {
        normalize_path(path)
        for path in folders
    }

    if normalized in existing:
        print("This folder is already protected.")
        return

    print("\nAdding new protected folder...")

    # Only initialize data for this newly added folder.
    initialize_inventory(folder)
    create_decoys(folder)

    # Append to the existing registry.
    folders.append(str(folder))
    save_protected_folders(folders)

    print("\nFolder added to SNAP_BACK protection.")
    logger.info("Added protected folder: %s", folder)


# --------------------------------------------------
# REMOVE PROTECTED FOLDER
# --------------------------------------------------


def remove_protected_folder(folders):
    if not folders:
        print("\nNo protected folders available.")
        return

    print("\nCurrently protected folders:\n")

    for index, folder in enumerate(folders, start=1):
        print(f"{index}. {folder}")

    try:
        choice = int(
            input("\nEnter the folder number to remove: ")
        )

        if choice < 1 or choice > len(folders):
            print("Invalid selection.")
            return

    except ValueError:
        print("Please enter a valid number.")
        return

    removed_folder = Path(folders[choice - 1]).resolve()

    confirmation = input(
        f"\nRemove {removed_folder} from SNAP_BACK protection "
        "and delete its decoys? (yes/no): "
    ).strip().lower()

    if confirmation != "yes":
        print("Removal cancelled.")
        return

    # Remove only the registered decoy directory.
    decoy_directory = (
        removed_folder / "Reference Archive" / "2024"
    )

    metadata = load_decoy_metadata()

    if decoy_directory.exists():
        shutil.rmtree(decoy_directory)
        print("Decoy directory deleted.")

    # Remove only metadata records belonging to this folder.
    normalized_folder = normalize_path(removed_folder)

    metadata["decoys"] = [
        record
        for record in metadata["decoys"]
        if normalize_path(record["protected_folder"])
        != normalized_folder
    ]

    save_decoy_metadata(metadata)

    # Remove folder from active protection.
    folders.pop(choice - 1)
    save_protected_folders(folders)

    print("\nFolder removed from SNAP_BACK protection.")
    print("Its decoys and decoy metadata have been deleted.")
    print("Original user files and inventory records are preserved.")

    logger.info(
        "Removed protected folder and its decoys: %s",
        removed_folder
    )



# --------------------------------------------------
# VIEW PROTECTED FOLDERS
# --------------------------------------------------

def view_protected_folders(folders):
    print("\n========== PROTECTED FOLDERS ==========\n")

    if not folders:
        print("No folders are currently protected.")
        return

    for index, folder in enumerate(folders, start=1):
        print(f"{index}. {folder}")

    print("\n=======================================")


# --------------------------------------------------
# FOLDER MANAGEMENT MENU
# --------------------------------------------------

def folder_management_menu():
    folders = load_protected_folders()

    while True:
        print("\n======================================")
        print("              SNAP_BACK")
        print("======================================")

        if folders:
            print("\nCurrently protected folders:")

            for index, folder in enumerate(folders, start=1):
                print(f"{index}. {folder}")
        else:
            print("\nNo folders are currently protected.")

        print("\n1. Add a folder to protection")
        print("2. Remove a folder from protection")
        print("3. View protected folders")
        print("4. Continue to monitoring")
        print("5. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            add_protected_folder(folders)

        elif choice == "2":
            remove_protected_folder(folders)

        elif choice == "3":
            view_protected_folders(folders)

        elif choice == "4":
            if not folders:
                print("\nAdd at least one folder before continuing.")
                continue

            return folders

        elif choice == "5":
            print("\nExiting SNAP_BACK.")
            return None

        else:
            print("\nInvalid choice. Try again.")


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():
    try:
        initialize_application()

        protected_folders = folder_management_menu()

        if protected_folders is None:
            return

        print("\n======================================")
        print("SNAP_BACK folder setup completed.")
        print(f"Protected folders: {len(protected_folders)}")
        print("======================================")

        # Monitoring handoff:
        # Connect your existing ReadDirectoryChangesW
        # monitoring entry point here.

        logger.info(
            "Folder management completed. Active folders: %s",
            len(protected_folders)
        )

    except Exception as error:
        logger.exception("SNAP_BACK initialization failed.")
        print(f"\nSNAP_BACK error: {error}")


if __name__ == "__main__":
    main()
