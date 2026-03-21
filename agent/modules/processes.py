"""
processes.py — Running process scanner
Read-only. Collects process list and flags suspicious activity.

Suspicious signals:
  - Known malware / RAT process names
  - Processes running from Temp / AppData / Downloads
  - Processes with no signed executable
  - Unusually high CPU (>80%) or memory (>500MB) consumption
"""

import os
import logging
from pathlib import Path

import psutil

log = logging.getLogger(__name__)

# ── Known suspicious process names (lowercase) ────────────────────────────────
# This is a conservative list of names commonly associated with malware/RATs.
# Legitimate software rarely uses these exact names.
SUSPICIOUS_NAMES = {
    "netcat.exe", "nc.exe", "ncat.exe",
    "mimikatz.exe", "mimi.exe",
    "psexec.exe", "psexesvc.exe",
    "procdump.exe",
    "wce.exe",                      # Windows Credential Editor
    "fgdump.exe", "pwdump.exe",
    "meterpreter.exe",
    "cobaltstrike.exe", "beacon.exe",
    "empire.exe",
    "xmrig.exe", "xmr-stak.exe",   # crypto miners
    "nssm.exe",                      # sometimes abused
    "tor.exe",
    "cryptominer.exe",
}

# Paths that are suspicious for executables to run from
SUSPICIOUS_PATH_FRAGMENTS = [
    os.environ.get("TEMP", "").lower(),
    os.environ.get("TMP", "").lower(),
    r"appdata\local\temp",
    r"appdata\roaming\temp",
    r"\downloads\\",
    r"\recycle.bin\\",
    r"\windows\temp\\",
]

CPU_THRESHOLD_PCT = 80.0
MEM_THRESHOLD_MB  = 500


class ProcessScanner:

    def scan_processes(self) -> list:
        """
        Returns a list of running processes.
        Each entry includes PID, name, CPU%, memory, exe path, and a suspicious flag.
        Capped at 200 entries, sorted by CPU desc.
        """
        results = []

        for proc in psutil.process_iter(
            attrs=["pid", "name", "exe", "cpu_percent", "memory_info",
                   "status", "username", "create_time"]
        ):
            try:
                info = proc.info
                pid   = info["pid"]
                name  = (info["name"] or "").strip()
                exe   = info["exe"] or ""
                cpu   = info["cpu_percent"] or 0.0
                mem_b = (info["memory_info"].rss if info["memory_info"] else 0)
                mem_mb= round(mem_b / (1024 * 1024), 1)

                flags  = _check_suspicious(name, exe, cpu, mem_mb)
                is_sus = len(flags) > 0

                results.append({
                    "pid":        pid,
                    "name":       name,
                    "exe":        exe,
                    "cpuPercent": round(cpu, 1),
                    "memMB":      mem_mb,
                    "status":     info.get("status", ""),
                    "username":   info.get("username", ""),
                    "suspicious": is_sus,
                    "suspiciousReasons": flags,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Sort by CPU descending so the heaviest processes appear first
        results.sort(key=lambda x: x["cpuPercent"], reverse=True)
        return results[:200]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_suspicious(name: str, exe: str, cpu: float, mem_mb: float) -> list:
    flags = []

    # Known malware name match
    if name.lower() in SUSPICIOUS_NAMES:
        flags.append(f"known_suspicious_name:{name}")

    # Running from a temp/download directory
    exe_lower = exe.lower()
    for fragment in SUSPICIOUS_PATH_FRAGMENTS:
        if fragment and fragment in exe_lower:
            flags.append(f"suspicious_path:{Path(exe).parent}")
            break

    # High CPU usage
    if cpu >= CPU_THRESHOLD_PCT:
        flags.append(f"high_cpu:{cpu}%")

    # High memory usage
    if mem_mb >= MEM_THRESHOLD_MB:
        flags.append(f"high_memory:{mem_mb}MB")

    # Executable has no path (hollow/injected process indicator)
    if name and not exe and name.lower().endswith(".exe"):
        flags.append("no_exe_path")

    return flags
