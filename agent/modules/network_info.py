"""
network_info.py — Network status collector for PC Guard agent.

Collects:
  - Internet connectivity (TCP connect to 8.8.8.8:53) + latency
  - Local IP + public IP (ipify)
  - Network name / SSID (netsh wlan)
  - RDP status  (HKLM\\SYSTEM\\...\\Terminal Server\\fDenyTSConnections)
  - SSH status  (sc query sshd + port-22 listener check)
  - Open ports  (listening on non-loopback interfaces)
"""

import socket
import subprocess
import time
import winreg
import psutil

DANGEROUS_PORTS = {23, 4444, 1337, 5900, 5901, 4899, 9001, 6667, 31337}
_CREATE_NO_WINDOW = 0x08000000


class NetworkInfo:

    def check_internet(self):
        """TCP connect to 8.8.8.8:53 — returns (connected: bool, latency_ms: int|None)."""
        try:
            start = time.monotonic()
            s = socket.create_connection(("8.8.8.8", 53), timeout=2)
            s.close()
            return True, round((time.monotonic() - start) * 1000)
        except OSError:
            return False, None

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    def get_public_ip(self):
        try:
            import requests
            r = requests.get("https://api.ipify.org", timeout=5)
            if r.status_code == 200:
                return r.text.strip()
        except Exception:
            pass
        return None

    def get_network_name(self):
        """Returns WiFi SSID or Ethernet adapter name."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("SSID") and "BSSID" not in stripped:
                    parts = stripped.split(":", 1)
                    if len(parts) == 2 and parts[1].strip():
                        return parts[1].strip()
        except Exception:
            pass
        # Fallback: first non-loopback Ethernet adapter name
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and not a.address.startswith("127."):
                        return iface
        except Exception:
            pass
        return None

    def check_rdp(self):
        """Returns True if RDP is ENABLED (fDenyTSConnections == 0)."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
            value, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            winreg.CloseKey(key)
            return value == 0
        except Exception:
            return False

    def check_ssh(self):
        """Returns True if OpenSSH service is running or port 22 is listening."""
        try:
            result = subprocess.run(
                ["sc", "query", "sshd"],
                capture_output=True, text=True, timeout=5,
                creationflags=_CREATE_NO_WINDOW,
            )
            if "RUNNING" in result.stdout:
                return True
        except Exception:
            pass
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr.port == 22 and conn.status == "LISTEN":
                    return True
        except Exception:
            pass
        return False

    def get_open_ports(self):
        """
        Returns list of listening TCP/UDP ports on non-loopback interfaces.
        Each entry: {port, protocol, pid, process, dangerous}
        """
        ports = []
        seen  = set()
        try:
            for kind in ("tcp", "tcp6", "udp", "udp6"):
                try:
                    conns = psutil.net_connections(kind=kind)
                except Exception:
                    continue
                for c in conns:
                    if not c.laddr:
                        continue
                    addr   = c.laddr.ip if hasattr(c.laddr, "ip") else ""
                    status = getattr(c, "status", "")
                    if kind.startswith("tcp") and status != "LISTEN":
                        continue
                    if addr in ("127.0.0.1", "::1"):
                        continue
                    port  = c.laddr.port
                    proto = "UDP" if kind.startswith("udp") else "TCP"
                    key   = (port, proto)
                    if key in seen:
                        continue
                    seen.add(key)
                    proc_name = ""
                    try:
                        if c.pid:
                            proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                    ports.append({
                        "port":      port,
                        "protocol":  proto,
                        "pid":       c.pid,
                        "process":   proc_name,
                        "dangerous": port in DANGEROUS_PORTS,
                    })
        except Exception:
            pass
        return sorted(ports, key=lambda x: x["port"])

    def collect_heartbeat(self):
        """
        Lightweight snapshot for periodic heartbeat (no public IP / SSID lookup).
        Returns dict.
        """
        connected, latency_ms = self.check_internet()
        return {
            "connected":    connected,
            "latency_ms":   latency_ms,
            "local_ip":     self.get_local_ip(),
            "rdp_enabled":  self.check_rdp(),
            "ssh_enabled":  self.check_ssh(),
            "open_ports":   self.get_open_ports(),
        }

    def collect_full(self):
        """Full collection including public IP and network name (slower)."""
        data = self.collect_heartbeat()
        data["public_ip"]    = self.get_public_ip()
        data["network_name"] = self.get_network_name()
        return data
