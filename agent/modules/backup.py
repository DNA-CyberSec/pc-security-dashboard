"""
backup.py — Backup and restore module
---------------------------------------
Creates ZIP archives before any cleanup operation.
Supports full restore (undo) from backup.
Backups stored in: %USERPROFILE%\.pc-security-agent\backups\
"""

import os
import zipfile
import logging
import shutil
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

BACKUP_ROOT = os.path.join(os.path.expanduser("~"), ".pc-security-agent", "backups")


class BackupManager:
    def __init__(self):
        os.makedirs(BACKUP_ROOT, exist_ok=True)

    def create_backup(self, items: list) -> str:
        """
        Creates a ZIP backup of the given file paths.
        Returns the path to the backup archive.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{timestamp}.zip"
        backup_path = os.path.join(BACKUP_ROOT, backup_filename)

        backed_up = 0
        with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in items:
                path = item.get("path") if isinstance(item, dict) else str(item)
                if path and os.path.isfile(path):
                    try:
                        # Store with full absolute path preserved inside zip
                        arcname = path.lstrip(os.sep).replace(":", "_drive")
                        zf.write(path, arcname)
                        backed_up += 1
                    except (PermissionError, FileNotFoundError) as e:
                        log.warning(f"Could not back up {path}: {e}")

        log.info(f"Backup created: {backup_path} ({backed_up} files)")
        return backup_path

    def restore_backup(self, backup_path: str) -> dict:
        """
        Restores files from a backup ZIP to their original locations.
        """
        if not os.path.isfile(backup_path):
            raise FileNotFoundError(f"Backup not found: {backup_path}")

        restored = []
        failed = []

        with zipfile.ZipFile(backup_path, "r") as zf:
            for member in zf.namelist():
                # Reconstruct original path
                original_path = os.sep + member.replace("_drive", ":").replace(os.sep + os.sep, os.sep)
                original_path = original_path.replace("/", os.sep)

                dest_dir = os.path.dirname(original_path)
                try:
                    os.makedirs(dest_dir, exist_ok=True)
                    with zf.open(member) as src, open(original_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    restored.append(original_path)
                    log.info(f"Restored: {original_path}")
                except Exception as e:
                    failed.append({"path": original_path, "error": str(e)})
                    log.error(f"Failed to restore {original_path}: {e}")

        return {"restored": restored, "failed": failed}

    def list_backups(self) -> list:
        backups = []
        for fname in sorted(os.listdir(BACKUP_ROOT), reverse=True):
            if fname.endswith(".zip"):
                fpath = os.path.join(BACKUP_ROOT, fname)
                size = os.path.getsize(fpath)
                backups.append({
                    "filename": fname,
                    "path": fpath,
                    "sizeBytes": size,
                    "created": datetime.fromtimestamp(os.path.getctime(fpath)).isoformat(),
                })
        return backups

    def delete_old_backups(self, keep_last: int = 10):
        backups = self.list_backups()
        to_delete = backups[keep_last:]
        for b in to_delete:
            try:
                os.remove(b["path"])
                log.info(f"Removed old backup: {b['path']}")
            except Exception as e:
                log.warning(f"Could not remove backup {b['path']}: {e}")
