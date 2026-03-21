"""
cleaner.py — Safe file cleanup module
--------------------------------------
Safety principles:
  - Blocked entirely when read_only=True
  - Uses send2trash (recycle bin) instead of permanent delete when possible
  - Never deletes system files or files outside approved paths
  - Returns detailed result for audit logging
"""

import os
import logging
import platform
from pathlib import Path

log = logging.getLogger(__name__)

# Paths that must never be touched
PROTECTED_ROOTS = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    os.environ.get("SystemRoot", r"C:\Windows"),
]

SAFE_EXTENSIONS = {
    ".tmp", ".temp", ".log", ".old", ".bak", ".chk", ".gid", ".dmp",
}


class Cleaner:
    def __init__(self, read_only: bool = True):
        self.read_only = read_only

    def clean_items(self, items: list) -> dict:
        if self.read_only:
            log.warning("Cleaner blocked — agent is in read-only mode")
            return {"cleaned": [], "failed": [{"error": "read-only mode", "items": items}]}

        cleaned = []
        failed = []

        for item in items:
            path = item.get("path") if isinstance(item, dict) else str(item)
            if not path:
                continue

            if not self._is_safe_to_delete(path):
                log.warning(f"Skipping protected path: {path}")
                failed.append({"path": path, "error": "protected path"})
                continue

            try:
                if platform.system() == "Windows":
                    # Use recycle bin — reversible
                    import send2trash
                    send2trash.send2trash(path)
                else:
                    os.remove(path)
                cleaned.append({"path": path, "status": "deleted"})
                log.info(f"Deleted: {path}")
            except Exception as e:
                failed.append({"path": path, "error": str(e)})
                log.error(f"Failed to delete {path}: {e}")

        return {"cleaned": cleaned, "failed": failed}

    def _is_safe_to_delete(self, path: str) -> bool:
        abs_path = os.path.abspath(path)

        # Block protected roots
        for protected in PROTECTED_ROOTS:
            if protected and abs_path.lower().startswith(protected.lower()):
                return False

        # Only allow safe extensions in non-temp scenarios
        ext = Path(path).suffix.lower()
        if ext not in SAFE_EXTENSIONS:
            # Allow if it's inside a known temp dir
            temp_dirs = [
                os.environ.get("TEMP", "").lower(),
                os.environ.get("TMP", "").lower(),
                r"c:\windows\temp",
            ]
            is_in_temp = any(abs_path.lower().startswith(t) for t in temp_dirs if t)
            if not is_in_temp:
                return False

        # File must actually exist
        return os.path.isfile(abs_path)
