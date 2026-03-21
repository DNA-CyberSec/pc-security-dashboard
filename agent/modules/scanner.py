"""
scanner.py — Read-only system scanner
Collects information about the PC without making any changes.
"""

import os
import hashlib
import logging
from pathlib import Path
from collections import defaultdict

import psutil

log = logging.getLogger(__name__)

# Common temp file patterns
TEMP_DIRS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    r"C:\Windows\Temp",
    r"C:\Windows\Prefetch",
]

TEMP_EXTENSIONS = {".tmp", ".temp", ".log", ".old", ".bak", ".chk", ".gid"}
LARGE_FILE_THRESHOLD_MB = 500


class Scanner:
    def __init__(self, read_only: bool = True):
        self.read_only = read_only

    # ── Storage ───────────────────────────────────────────────────────────────

    def scan_storage(self) -> dict:
        try:
            disk = psutil.disk_usage("C:\\")
            return {
                "totalGB": round(disk.total / 1e9, 1),
                "usedGB": round(disk.used / 1e9, 1),
                "freeGB": round(disk.free / 1e9, 1),
                "usedPercent": disk.percent,
            }
        except Exception as e:
            log.error(f"scan_storage error: {e}")
            return {}

    # ── Temp files ────────────────────────────────────────────────────────────

    def scan_temp_files(self) -> list:
        found = []
        for temp_dir in TEMP_DIRS:
            if not temp_dir or not os.path.isdir(temp_dir):
                continue
            try:
                for entry in os.scandir(temp_dir):
                    if entry.is_file(follow_symlinks=False):
                        try:
                            size = entry.stat().st_size
                            found.append({
                                "path": entry.path,
                                "size": _format_size(size),
                                "sizeBytes": size,
                            })
                        except PermissionError:
                            pass
            except PermissionError:
                pass
        # Also check by extension in common locations
        for root_dir in [os.path.expanduser("~")]:
            for dirpath, _, filenames in os.walk(root_dir):
                for fname in filenames:
                    if Path(fname).suffix.lower() in TEMP_EXTENSIONS:
                        fpath = os.path.join(dirpath, fname)
                        try:
                            size = os.path.getsize(fpath)
                            found.append({"path": fpath, "size": _format_size(size), "sizeBytes": size})
                        except (PermissionError, FileNotFoundError):
                            pass
                break  # only top level of home dir for safety
        return found[:200]  # cap results

    # ── Large files ───────────────────────────────────────────────────────────

    def scan_large_files(self, root: str = None) -> list:
        root = root or os.path.expanduser("~")
        found = []
        threshold = LARGE_FILE_THRESHOLD_MB * 1024 * 1024
        try:
            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        size = os.path.getsize(fpath)
                        if size >= threshold:
                            found.append({
                                "path": fpath,
                                "size": _format_size(size),
                                "sizeBytes": size,
                            })
                    except (PermissionError, FileNotFoundError):
                        pass
        except Exception as e:
            log.error(f"scan_large_files error: {e}")
        found.sort(key=lambda x: x["sizeBytes"], reverse=True)
        return found[:50]

    # ── Duplicates ────────────────────────────────────────────────────────────

    def scan_duplicates(self, root: str = None) -> list:
        root = root or os.path.expanduser("~\\Documents")
        hash_map = defaultdict(list)
        try:
            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        h = _fast_hash(fpath)
                        hash_map[h].append(fpath)
                    except (PermissionError, FileNotFoundError, OSError):
                        pass
        except Exception as e:
            log.error(f"scan_duplicates error: {e}")

        duplicates = []
        for h, paths in hash_map.items():
            if len(paths) > 1:
                try:
                    size = os.path.getsize(paths[0])
                    duplicates.append({
                        "paths": paths,
                        "hash": h,
                        "size": _format_size(size),
                        "sizeBytes": size,
                        "wastedBytes": size * (len(paths) - 1),
                    })
                except (FileNotFoundError, OSError):
                    pass
        duplicates.sort(key=lambda x: x["wastedBytes"], reverse=True)
        return duplicates[:30]

    # ── Startup items ─────────────────────────────────────────────────────────

    def scan_startup_items(self) -> list:
        items = []
        startup_folders = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for folder in startup_folders:
            if os.path.isdir(folder):
                for entry in os.scandir(folder):
                    items.append({"name": entry.name, "path": entry.path, "source": "startup_folder"})

        # Registry-based startup (read-only query via reg query)
        try:
            import subprocess
            for key in [
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            ]:
                result = subprocess.run(
                    ["reg", "query", key],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("HKEY"):
                        parts = line.split(None, 2)
                        if len(parts) >= 3:
                            items.append({
                                "name": parts[0],
                                "type": parts[1],
                                "value": parts[2],
                                "source": "registry",
                                "key": key,
                            })
        except Exception as e:
            log.debug(f"Registry scan error: {e}")
        return items

    # ── Vulnerabilities ───────────────────────────────────────────────────────

    def scan_vulnerabilities(self) -> list:
        issues = []
        # Check Windows Defender status
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                import json
                status = json.loads(result.stdout)
                if not status.get("AntivirusEnabled"):
                    issues.append({"type": "antivirus_disabled", "severity": "critical", "description": "Windows Defender antivirus is disabled"})
                if not status.get("RealTimeProtectionEnabled"):
                    issues.append({"type": "realtime_protection_disabled", "severity": "high", "description": "Real-time protection is disabled"})
        except Exception as e:
            log.debug(f"Defender check error: {e}")

        # Check firewall
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5
            )
            if "OFF" in result.stdout.upper():
                issues.append({"type": "firewall_disabled", "severity": "high", "description": "Windows Firewall is disabled on one or more profiles"})
        except Exception as e:
            log.debug(f"Firewall check error: {e}")

        return issues

    # ── Outdated software ─────────────────────────────────────────────────────

    def scan_outdated_software(self) -> list:
        outdated = []
        try:
            import subprocess
            # Check for Windows Updates pending
            result = subprocess.run(
                ["powershell", "-Command",
                 "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates | Select-Object Title | ConvertTo-Json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                updates = json.loads(result.stdout)
                if isinstance(updates, dict):
                    updates = [updates]
                for u in (updates or []):
                    outdated.append({"name": u.get("Title", "Unknown"), "type": "windows_update"})
        except Exception as e:
            log.debug(f"Outdated software check: {e}")
        return outdated[:20]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fast_hash(path: str, chunk_size: int = 65536) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        h.update(f.read(chunk_size))   # hash first 64KB only for speed
    return h.hexdigest()

def _format_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
