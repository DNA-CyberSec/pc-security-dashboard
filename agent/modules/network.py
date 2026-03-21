"""
network.py — Active network connection scanner
Read-only. Lists established TCP/UDP connections and flags suspicious ones.

Suspicious signals:
  - Connections to known bad port patterns
  - Connections from processes running in temp directories
  - Processes with unusually many open connections
  - Raw IP connections (no hostname) on non-standard ports
"""

import logging
import socket
from collections import Counter

import psutil

log = logging.getLogger(__name__)

# Ports commonly used by malware C2 / RATs (not exhaustive — just common signals)
SUSPICIOUS_PORTS = {
    1337, 31337, 4444, 4445, 5555, 6666, 6667, 6668, 6669,   # common RAT/shell ports
    8888, 9999, 12345, 54321,                                  # common reverse shell defaults
}

# Legitimate ports — reduce false positives
BENIGN_PORTS = {
    80, 443, 8080, 8443,        # HTTP/S
    22, 21, 25, 110, 143, 993,  # SSH, FTP, mail
    53,                          # DNS
    3389,                        # RDP (flag separately)
    5353,                        # mDNS
}

# Processes that should rarely make outbound connections
SUSPICIOUS_PROCESS_NAMES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
}

# Max connections per process before flagging
MAX_CONNS_PER_PROC = 50


class NetworkScanner:

    def scan_connections(self) -> list:
        """
        Returns active TCP/UDP connections (ESTABLISHED + LISTEN).
        Each entry includes local/remote address, process name, and a suspicious flag.
        Capped at 150 entries.
        """
        results    = []
        proc_cache = _build_proc_cache()
        conn_count = Counter()

        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            log.warning("net_connections: access denied — run agent as Administrator for full data")
            return []

        for conn in connections:
            if conn.status not in ("ESTABLISHED", "LISTEN", "CLOSE_WAIT"):
                continue

            pid  = conn.pid
            proc = proc_cache.get(pid, {})

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            rport = conn.raddr.port if conn.raddr else 0
            rip   = conn.raddr.ip   if conn.raddr else ""

            conn_count[pid] += 1

            flags  = _check_suspicious_conn(rport, rip, proc.get("name", ""), proc.get("exe", ""))
            is_sus = len(flags) > 0

            results.append({
                "pid":        pid,
                "processName": proc.get("name", "unknown"),
                "processExe":  proc.get("exe", ""),
                "localAddr":   laddr,
                "remoteAddr":  raddr,
                "remoteIp":    rip,
                "remotePort":  rport,
                "status":      conn.status,
                "family":      "IPv6" if "::" in (rip or laddr) else "IPv4",
                "suspicious":  is_sus,
                "suspiciousReasons": flags,
            })

        # Second pass — flag processes with too many connections
        for entry in results:
            pid = entry["pid"]
            if conn_count[pid] > MAX_CONNS_PER_PROC:
                reason = f"excessive_connections:{conn_count[pid]}"
                if reason not in entry["suspiciousReasons"]:
                    entry["suspiciousReasons"].append(reason)
                    entry["suspicious"] = True

        # Sort: suspicious first, then by remote port
        results.sort(key=lambda x: (not x["suspicious"], x["remotePort"]))
        return results[:150]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_proc_cache() -> dict:
    """Build {pid: {name, exe}} map once to avoid per-connection process lookups."""
    cache = {}
    for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            cache[proc.pid] = {"name": proc.info["name"] or "", "exe": proc.info["exe"] or ""}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return cache

def _check_suspicious_conn(rport: int, rip: str, proc_name: str, proc_exe: str) -> list:
    flags = []

    if not rip:                     # listening-only socket, skip
        return flags

    # Known RAT/shell port
    if rport in SUSPICIOUS_PORTS:
        flags.append(f"suspicious_port:{rport}")

    # Outbound RDP from unexpected process
    if rport == 3389 and proc_name.lower() not in ("mstsc.exe", "msrdc.exe"):
        flags.append("unexpected_rdp_outbound")

    # System process making unexpected outbound connection
    if proc_name.lower() in SUSPICIOUS_PROCESS_NAMES and rport not in BENIGN_PORTS:
        flags.append(f"unexpected_outbound:{proc_name}")

    # Process running from Temp making network connections
    exe_lower = proc_exe.lower()
    temp = ("\\temp\\", "\\tmp\\", "appdata\\local\\temp")
    if any(t in exe_lower for t in temp) and rport not in BENIGN_PORTS:
        flags.append("temp_process_network")

    # Try reverse DNS — if it fails and port is non-standard, mild flag
    if rip and rport not in BENIGN_PORTS and rport not in SUSPICIOUS_PORTS:
        try:
            hostname = socket.gethostbyaddr(rip)[0]
            if hostname == rip:            # no PTR record
                flags.append(f"no_reverse_dns:{rip}:{rport}")
        except (socket.herror, socket.gaierror, OSError):
            pass

    return flags
