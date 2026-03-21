"""
privacy.py — Privacy scanner module
--------------------------------------
Scans browser data, cookies, and cached credentials.
Read-only by default — only reports findings, never deletes.
"""

import os
import sqlite3
import logging
import shutil
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

BROWSER_PROFILES = {
    "chrome": os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        r"Google\Chrome\User Data\Default",
    ),
    "edge": os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        r"Microsoft\Edge\User Data\Default",
    ),
    "firefox": os.path.join(
        os.environ.get("APPDATA", ""),
        r"Mozilla\Firefox\Profiles",
    ),
}


class PrivacyScanner:
    def __init__(self, read_only: bool = True):
        self.read_only = read_only

    def scan_browser_data(self) -> dict:
        results = {}
        for browser, profile_path in BROWSER_PROFILES.items():
            if not os.path.isdir(profile_path):
                continue
            results[browser] = self._scan_chromium_profile(profile_path) if browser != "firefox" else self._scan_firefox_profile(profile_path)
        return results

    def _scan_chromium_profile(self, profile_path: str) -> dict:
        data = {"cookies": 0, "history": 0, "cacheSize": "unknown"}

        # Cookies count (copy DB first — Chrome locks it)
        cookies_db = os.path.join(profile_path, "Network", "Cookies")
        if not os.path.isfile(cookies_db):
            cookies_db = os.path.join(profile_path, "Cookies")

        if os.path.isfile(cookies_db):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
                    tmp_path = tmp.name
                shutil.copy2(cookies_db, tmp_path)
                conn = sqlite3.connect(tmp_path)
                cursor = conn.execute("SELECT COUNT(*) FROM cookies")
                data["cookies"] = cursor.fetchone()[0]
                conn.close()
                os.unlink(tmp_path)
            except Exception as e:
                log.debug(f"Cookies scan error ({profile_path}): {e}")

        # History count
        history_db = os.path.join(profile_path, "History")
        if os.path.isfile(history_db):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
                    tmp_path = tmp.name
                shutil.copy2(history_db, tmp_path)
                conn = sqlite3.connect(tmp_path)
                cursor = conn.execute("SELECT COUNT(*) FROM urls")
                data["history"] = cursor.fetchone()[0]
                conn.close()
                os.unlink(tmp_path)
            except Exception as e:
                log.debug(f"History scan error ({profile_path}): {e}")

        # Cache size
        cache_path = os.path.join(profile_path, "Cache", "Cache_Data")
        if os.path.isdir(cache_path):
            try:
                total = sum(
                    f.stat().st_size
                    for f in Path(cache_path).rglob("*")
                    if f.is_file()
                )
                data["cacheSize"] = _format_size(total)
                data["cacheSizeBytes"] = total
            except Exception as e:
                log.debug(f"Cache size error: {e}")

        return data

    def _scan_firefox_profile(self, profiles_root: str) -> dict:
        data = {"cookies": 0, "history": 0}
        try:
            for entry in os.scandir(profiles_root):
                if not entry.is_dir():
                    continue
                # Cookies
                cookies_db = os.path.join(entry.path, "cookies.sqlite")
                if os.path.isfile(cookies_db):
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
                            tmp_path = tmp.name
                        shutil.copy2(cookies_db, tmp_path)
                        conn = sqlite3.connect(tmp_path)
                        cursor = conn.execute("SELECT COUNT(*) FROM moz_cookies")
                        data["cookies"] += cursor.fetchone()[0]
                        conn.close()
                        os.unlink(tmp_path)
                    except Exception as e:
                        log.debug(f"Firefox cookies error: {e}")

                # History
                places_db = os.path.join(entry.path, "places.sqlite")
                if os.path.isfile(places_db):
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
                            tmp_path = tmp.name
                        shutil.copy2(places_db, tmp_path)
                        conn = sqlite3.connect(tmp_path)
                        cursor = conn.execute("SELECT COUNT(*) FROM moz_places")
                        data["history"] += cursor.fetchone()[0]
                        conn.close()
                        os.unlink(tmp_path)
                    except Exception as e:
                        log.debug(f"Firefox history error: {e}")
        except Exception as e:
            log.debug(f"Firefox profile scan error: {e}")
        return data


def _format_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
