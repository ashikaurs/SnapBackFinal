
import os
import json
import hashlib
import logging

from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger("SNAP_BACK.FileInventory")


class FileInventory:

    def __init__(self, inventory_path):
        self.inventory_path = Path(inventory_path)
        self.inventory_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.inventory = {}
        self.load_inventory()

    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as file:
                for chunk in iter(
                    lambda: file.read(1024 * 1024),
                    b""
                ):
                    sha256.update(chunk)

            return sha256.hexdigest()

        except (OSError, PermissionError) as error:
            logger.warning(
                "Could not hash %s: %s",
                file_path,
                error
            )
            return None

    def get_file_metadata(self, file_path):
        path = Path(file_path)

        try:
            stat = path.stat()

            return {
                "file_path": str(path.resolve()),
                "file_name": path.name,
                "extension": path.suffix.lower(),
                "size": stat.st_size,
                "created_at": datetime.fromtimestamp(
                    stat.st_ctime,
                    timezone.utc
                ).isoformat(),
                "modified_at": datetime.fromtimestamp(
                    stat.st_mtime,
                    timezone.utc
                ).isoformat(),
                "sha256": self.calculate_hash(path),
                "last_scanned": datetime.now(
                    timezone.utc
                ).isoformat()
            }

        except OSError as error:
            logger.warning(
                "Could not read metadata for %s: %s",
                file_path,
                error
            )
            return None

    def scan_directory(self, directory):
        root = Path(directory).resolve()

        if not root.exists() or not root.is_dir():
            raise ValueError(
                f"Invalid directory: {root}"
            )

        scanned_count = 0

        for current_root, _, filenames in os.walk(root):
            for filename in filenames:
                file_path = Path(current_root) / filename

                metadata = self.get_file_metadata(file_path)

                if metadata:
                    self.inventory[str(file_path)] = metadata
                    scanned_count += 1

        self.save_inventory()

        logger.info(
            "Inventory scan completed: %s files in %s",
            scanned_count,
            root
        )

        return scanned_count

    def update_file(self, file_path):
        path = Path(file_path)

        if not path.exists() or not path.is_file():
            self.remove_file(path)
            return False

        metadata = self.get_file_metadata(path)

        if metadata:
            self.inventory[str(path.resolve())] = metadata
            self.save_inventory()
            return True

        return False

    def remove_file(self, file_path):
        key = str(Path(file_path).resolve())

        if key in self.inventory:
            del self.inventory[key]
            self.save_inventory()

    def rename_file(self, old_path, new_path):
        self.remove_file(old_path)
        self.update_file(new_path)

    def save_inventory(self):
        temporary_path = self.inventory_path.with_suffix(".tmp")

        with open(temporary_path, "w", encoding="utf-8") as file:
            json.dump(
                self.inventory,
                file,
                indent=4
            )

        os.replace(temporary_path, self.inventory_path)

    def load_inventory(self):
        if not self.inventory_path.exists():
            self.inventory = {}
            return

        try:
            with open(
                self.inventory_path,
                "r",
                encoding="utf-8"
            ) as file:
                self.inventory = json.load(file)

        except (json.JSONDecodeError, OSError) as error:
            logger.error(
                "Could not load inventory: %s",
                error
            )
            self.inventory = {}

    def get_inventory(self):
        return self.inventory

    def get_file_count(self):
        return len(self.inventory)
