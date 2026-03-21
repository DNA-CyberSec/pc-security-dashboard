"""
scanner.py — Read-only system scanner
Covers: disk drives, temp files, large files, startup items,
        installed software, and security vulnerabilities.
Never modifies any file or registry key.
"""

import os
import json
import logging
import subprocess
import winreg
from datetime import datetime
from pathlib import Path

import psutil

log = logging.getLogger(__name__)

TEMP_EXTENSIONS = {".tmp", ".temp", ".log", ".old", ".bak", ".chk", ".dmp", ".etl"}
LARGE_FILE_MB   = 500   # flag files above this size

# Registry paths for installed software
_SW_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


class Scanner:

    # ── All drives ────────────────────────────────────────────────────────────

    def scan_all_drives(self) -> list:
        """Returns disk usage for every fixed/removable drive on the system."""
        drives = []
        for part in psutil.disk_partitions(all=False):
            if "cdrom" in part.opts or part.fstype == "":
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                drives.append({
                    "drive":        part.mountpoint,
                    "fstype":       part.fstype,
                    "totalGB":      round(usage.total  / 1e9, 1),
                    "usedGB":       round(usage.used   / 1e9, 1),
                    "freeGB":       round(usage.free   / 1e9, 1),
                    "usedPercent":  usage.percent,
                })
            except (PermissionError, OSError):
                pass
        return drives

    # ── Temp files summary ────────────────────────────────────────────────────

    def scan_temp_summary(self) -> dict:
        """
        Returns a summary of temp/cache file sizes — not a full file list.
        Much faster than enumerating every file; safe for frequent polling.
        """
        locations = {
            "userTemp":     os.environ.get("TEMP", ""),
            "systemTemp":   r"C:\Windows\Temp",
            "prefetch":     r"C:\Windows\Prefetch",
            "windowsLogs":  r"C:\Windows\Logs",
        }
        result = {}
        total_bytes = 0

        for label, path in locations.items():
            if not path or not os.path.isdir(path):
                result[label] = {"sizeBytes": 0, "fileCount": 0}
                continue
            size, count = _dir_size(path)
            result[label] = {"sizeBytes": size, "fileCount": count, "size": _fmt(size)}
            total_bytes += size

        result["totalBytes"] = total_bytes
        result["total"]      = _fmt(total_bytes)
        return result

    # ── Large files ───────────────────────────────────────────────────────────

    def scan_large_files(self, root: str = None) -> list:
        """Finds files > LARGE_FILE_MB inside the user's home folder."""
        root      = root or os.path.expanduser("~")
        threshold = LARGE_FILE_MB * 1024 * 1024
        found     = []

        for dirpath, dirnames, filenames in os.walk(root):
            # Skip hidden / system dirs
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    size = os.path.getsize(fpath)
                    if size >= threshold:
                        found.append({
                            "path":      fpath,
                            "size":      _fmt(size),
                            "sizeBytes": size,
                            "extension": Path(fpath).suffix.lower(),
                        })
                except (PermissionError, FileNotFoundError, OSError):
                    pass

        found.sort(key=lambda x: x["sizeBytes"], reverse=True)
        return found[:50]

    # ── Startup items ─────────────────────────────────────────────────────────

    def scan_startup_items(self) -> list:
        """
        Returns startup programs from:
          - Startup folders (APPDATA + ProgramData)
          - Registry Run keys (HKCU + HKLM)
        """
        items = []

        # Startup folders
        folders = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for folder in folders:
            if not os.path.isdir(folder):
                continue
            for entry in os.scandir(folder):
                if entry.is_file():
                    items.append({
                        "name":   entry.name,
                        "path":   entry.path,
                        "source": "startup_folder",
                        "enabled": True,
                    })

        # Registry Run keys (read-only)
        run_keys = [
            (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM32"),
        ]
        for hive, key_path, hive_label in run_keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        items.append({
                            "name":    name,
                            "command": value,
                            "source":  f"registry_{hive_label}",
                            "key":     key_path,
                            "enabled": True,
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        return items

    # ── Installed software ────────────────────────────────────────────────────

    def scan_installed_software(self) -> list:
        """
        Reads installed programs from the Windows registry uninstall keys.
        Returns name, version, publisher, install date, estimated size.
        """
        software = {}   # keyed by display name to deduplicate

        for hive, key_path in _SW_KEYS:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        try:
                            subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                            entry  = _read_sw_entry(subkey)
                            winreg.CloseKey(subkey)

                            name = entry.get("name", "").strip()
                            if not name or entry.get("systemComponent"):
                                continue
                            # Deduplicate — keep entry with more info
                            if name not in software or entry.get("version"):
                                software[name] = entry
                        except (PermissionError, OSError):
                            pass
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, PermissionError, OSError):
                pass

        result = sorted(software.values(), key=lambda x: x.get("name", "").lower())
        return result[:300]

    # ── Security vulnerabilities ──────────────────────────────────────────────

    def scan_vulnerabilities(self) -> list:
        issues = []
        # CREATE_NO_WINDOW prevents black console popups when running as a windowed .exe
        _NO_WIN = subprocess.CREATE_NO_WINDOW

        # Windows Defender status
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
                 "AntivirusSignatureAge,NISSignatureAge | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15,
                creationflags=_NO_WIN,
            )
            if r.returncode == 0 and r.stdout.strip():
                s = json.loads(r.stdout)
                if not s.get("AntivirusEnabled"):
                    issues.append({"type": "antivirus_disabled",         "severity": "critical",
                                   "description": "Windows Defender antivirus is disabled"})
                if not s.get("RealTimeProtectionEnabled"):
                    issues.append({"type": "realtime_protection_off",    "severity": "critical",
                                   "description": "Real-time protection is disabled"})
                sig_age = s.get("AntivirusSignatureAge", 0) or 0
                if sig_age > 7:
                    issues.append({"type": "outdated_signatures",        "severity": "high",
                                   "description": f"Antivirus signatures are {sig_age} days old"})
        except Exception as e:
            log.debug(f"Defender check: {e}")

        # Firewall status
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10,
                creationflags=_NO_WIN,
            )
            if r.returncode == 0 and r.stdout.strip():
                profiles = json.loads(r.stdout)
                if isinstance(profiles, dict):
                    profiles = [profiles]
                for p in profiles:
                    if not p.get("Enabled"):
                        issues.append({"type": "firewall_disabled", "severity": "high",
                                       "description": f"Firewall disabled on {p.get('Name','?')} profile"})
        except Exception as e:
            log.debug(f"Firewall check: {e}")

        # UAC check
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                0, winreg.KEY_READ
            )
            uac, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            if not uac:
                issues.append({"type": "uac_disabled", "severity": "high",
                               "description": "User Account Control (UAC) is disabled"})
        except Exception as e:
            log.debug(f"UAC check: {e}")

        # Pending Windows Updates (quick check — counts only)
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(New-Object -ComObject Microsoft.Update.Session)"
                 ".CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count"],
                capture_output=True, text=True, timeout=30,
                creationflags=_NO_WIN,
            )
            if r.returncode == 0:
                count = int(r.stdout.strip())
                if count > 0:
                    issues.append({"type": "pending_updates", "severity": "medium",
                                   "description": f"{count} Windows update(s) pending installation",
                                   "count": count})
        except Exception as e:
            log.debug(f"Windows update check: {e}")

        return issues


# ── Registry helpers ──────────────────────────────────────────────────────────

def _read_sw_entry(key) -> dict:
    def _get(name):
        try:
            val, _ = winreg.QueryValueEx(key, name)
            return val
        except OSError:
            return None

    raw_date  = _get("InstallDate") or ""
    installed = None
    if len(raw_date) == 8:
        try:
            installed = datetime.strptime(raw_date, "%Y%m%d").strftime("%Y-%m-%d")
        except ValueError:
            pass

    size_kb = _get("EstimatedSize")

    return {
        "name":            _get("DisplayName"),
        "version":         _get("DisplayVersion"),
        "publisher":       _get("Publisher"),
        "installDate":     installed,
        "installLocation": _get("InstallLocation"),
        "sizeKB":          size_kb,
        "size":            _fmt(size_kb * 1024) if size_kb else None,
        "uninstallCmd":    _get("UninstallString"),
        "systemComponent": bool(_get("SystemComponent")),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dir_size(path: str):
    """Returns (total_bytes, file_count) for a directory tree."""
    total, count = 0, 0
    try:
        for dirpath, _, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(dirpath, f))
                    count += 1
                except (PermissionError, FileNotFoundError, OSError):
                    pass
    except (PermissionError, OSError):
        pass
    return total, count

def _fmt(size_bytes: int) -> str:
    if not size_bytes:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
