"""
PCGuard Setup Wizard — Entry point for the bundled Windows .exe

Two modes depending on command-line argument:
  (no args)  →  Show GUI installer wizard (for first-time setup)
  --run      →  Run silently as a background agent

PyInstaller bundles this file + all modules into a single PCGuard-Setup.exe
"""

import sys
import os
import uuid

# ── Constants shared by both modes ────────────────────────────────────────────

def _read_version() -> str:
    try:
        _dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(_dir, "VERSION")) as _f:
            return _f.read().strip()
    except Exception:
        return "1.0.0"

AGENT_VERSION   = _read_version()
INSTALL_DIR     = r"C:\pc-security-agent"
EXE_NAME        = "pc-guard-agent.exe"
CONFIG_FILE     = os.path.join(INSTALL_DIR, "config.json")
LOG_FILE        = os.path.join(INSTALL_DIR, "agent.log")
APP_REG_KEY     = "PCGuardAgent"
IS_BUNDLED      = getattr(sys, "frozen", False)
BACKGROUND_MODE = "--run" in sys.argv

FUNCTIONS_BASE     = "https://us-central1-pc-security-dashboard.cloudfunctions.net"
HEARTBEAT_URL      = f"{FUNCTIONS_BASE}/agentHeartbeat"
SUBMIT_SCAN_URL    = f"{FUNCTIONS_BASE}/submitScan"
REALTIME_URL       = f"{FUNCTIONS_BASE}/realtimeHeartbeat"

# ── Route to correct mode ─────────────────────────────────────────────────────

if BACKGROUND_MODE:
    # ── BACKGROUND AGENT MODE ─────────────────────────────────────────────────
    import json
    import time
    import socket
    import logging
    import threading
    import webbrowser
    import winreg
    import requests
    import schedule
    import pystray
    from PIL import Image, ImageDraw

    from modules.scanner      import Scanner
    from modules.processes    import ProcessScanner
    from modules.network      import NetworkScanner
    from modules.privacy      import PrivacyScanner
    from modules.network_info import NetworkInfo

    # Set up logging to file only — no console in background mode
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")],
    )
    log = logging.getLogger("pcguard")

    def _load_config():
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception as e:
            log.error(f"Cannot read config.json: {e}")
            sys.exit(1)

    CONFIG          = _load_config()
    AGENT_TOKEN     = CONFIG.get("agent_token", "")
    SCAN_INTERVAL   = int(CONFIG.get("scan_interval",    300))
    HEARTBEAT_SECS  = int(CONFIG.get("heartbeat_interval", 60))

    def _resolve_device_id():
        """
        Returns a permanent, hardware-based device ID for this Windows PC.
        Priority: MachineGuid (survives reinstalls) → MAC-UUID → saved ID → new UUID
        """
        # 1. Windows MachineGuid — immutable per-machine GUID set during Windows install
        try:
            k = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
            guid, _ = winreg.QueryValueEx(k, "MachineGuid")
            winreg.CloseKey(k)
            if guid and guid.strip():
                return guid.strip().lower()
        except Exception:
            pass

        # 2. Primary NIC MAC address → deterministic UUID (no registry needed)
        try:
            mac = uuid.getnode()
            if not (mac >> 40) & 1:  # skip multicast / random MACs
                return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(mac)))
        except Exception:
            pass

        # 3. Previously saved ID (backward compat — keeps existing installs stable)
        saved = CONFIG.get("device_id", "").strip()
        if saved:
            return saved

        # 4. Last resort: new random UUID
        return str(uuid.uuid4())

    DEVICE_NAME = os.environ.get("COMPUTERNAME", socket.gethostname())
    DEVICE_ID   = _resolve_device_id()

    # Persist resolved ID so future runs are instant (even if registry is inaccessible)
    if CONFIG.get("device_id") != DEVICE_ID:
        CONFIG["device_id"] = DEVICE_ID
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(CONFIG, f, indent=2)
        except Exception as e:
            log.warning(f"Could not save device ID: {e}")
    log.info(f"Device ID: {DEVICE_ID}  Name: {DEVICE_NAME}")

    # Events for inter-thread signalling
    _scan_now  = threading.Event()   # set by "Run Scan Now" tray menu item
    _stop      = threading.Event()   # set by "Exit" to stop the agent loop

    def _post(url, payload, timeout=30):
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            return r.status_code, r.json() if r.content else {}
        except requests.RequestException as e:
            log.warning(f"Network error → {url}: {e}")
            return 0, {}

    def send_heartbeat():
        status, _ = _post(HEARTBEAT_URL, {
            "token":        AGENT_TOKEN,
            "deviceId":     DEVICE_ID,
            "deviceName":   DEVICE_NAME,
            "hostname":     socket.gethostname(),
            "username":     os.environ.get("USERNAME", "unknown"),
            "agentVersion": AGENT_VERSION,
            "readOnlyMode": True,
            "os":           "Windows",
        })
        if status == 401:
            log.error("Invalid AgentToken — reinstall PCGuard from pcguard-rami.web.app")

    def _safe(name, fn):
        try:
            return fn()
        except Exception as e:
            log.error(f"[{name}] failed: {e}")
            return {} if name in ("temp_summary",) else []

    def _health_score(scan):
        score = 100
        for d in scan.get("storage", []):
            p = d.get("usedPercent", 0)
            if p >= 90: score -= 20
            elif p >= 80: score -= 10
        if scan.get("tempSummary", {}).get("totalBytes", 0) > 1_073_741_824:
            score -= 10
        for v in scan.get("vulnerabilities", []):
            score -= {"critical": 15, "high": 8, "medium": 3}.get(v.get("severity", ""), 0)
        sus_p = sum(1 for p in scan.get("processes", []) if p.get("suspicious"))
        score -= 15 if sus_p >= 3 else (8 if sus_p >= 1 else 0)
        score -= min(sum(5 for c in scan.get("networkConnections", []) if c.get("suspicious")), 20)
        net = scan.get("networkInfo", {})
        if net.get("rdp_enabled"):
            score -= 5
        score -= min(sum(15 for pp in net.get("open_ports", []) if pp.get("dangerous")), 30)
        admin_count = sum(1 for u in scan.get("localUsers", []) if u.get("is_admin"))
        if admin_count > 2:
            score -= 5
        return max(0, min(100, score))

    def run_scan():
        log.info("Scan started")
        sc = Scanner()
        scan = {
            "agentVersion":       AGENT_VERSION,
            "hostname":           socket.gethostname(),
            "storage":            _safe("storage",       sc.scan_all_drives),
            "tempSummary":        _safe("temp",          sc.scan_temp_summary),
            "largeFiles":         _safe("large_files",   sc.scan_large_files),
            "startupItems":       _safe("startup",       sc.scan_startup_items),
            "installedSoftware":  _safe("software",      sc.scan_installed_software),
            "vulnerabilities":    _safe("vulns",         sc.scan_vulnerabilities),
            "malwareSuspects":    _safe("malware",       sc.scan_malware_suspects),
            "startupSecurity":    _safe("startup_sec",   sc.scan_startup_security),
            "firewallStatus":     _safe("firewall",      sc.scan_firewall_status),
            "localUsers":         _safe("local_users",   sc.get_local_users),
            "processes":          _safe("processes",     ProcessScanner().scan_processes),
            "networkConnections": _safe("network",       NetworkScanner().scan_connections),
            "browserData":        _safe("browser",       PrivacyScanner().scan_browser_data),
            "networkInfo":        _safe("network_info",  NetworkInfo().collect_full),
        }
        scan["healthScore"] = _health_score(scan)
        status, resp = _post(SUBMIT_SCAN_URL, {"token": AGENT_TOKEN, "deviceId": DEVICE_ID, "scan": scan})
        if status == 200:
            log.info(f"Scan uploaded → {resp.get('scanId', '?')}  score={scan['healthScore']}")
        elif status == 401:
            log.error("Scan rejected — invalid token")
        else:
            log.error(f"Scan upload failed: HTTP {status}")

    _net_cache      = {}
    _net_last_time  = [0.0]   # list so inner function can mutate it
    _user_cache     = {}
    _user_last_time = [0.0]

    def send_realtime_heartbeat():
        """Lightweight 10-second heartbeat with CPU/RAM/processes/temps/network."""
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()

            procs = []
            for p in psutil.process_iter(["name", "cpu_percent", "memory_info"]):
                try:
                    procs.append({
                        "name":   p.info["name"] or "",
                        "cpu":    round(p.info["cpu_percent"] or 0, 1),
                        "ram_mb": round((p.info["memory_info"].rss if p.info["memory_info"] else 0) / 1e6, 1),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            top5 = sorted(procs, key=lambda x: x["cpu"], reverse=True)[:5]

            temps = []
            try:
                raw = psutil.sensors_temperatures()
                if raw:
                    for name, entries in raw.items():
                        for e in entries:
                            temps.append({"label": e.label or name, "current": round(e.current, 1)})
                    temps = temps[:8]
            except Exception:
                pass

            # Refresh network info every 30 seconds
            if time.time() - _net_last_time[0] >= 30:
                try:
                    _net_cache.clear()
                    _net_cache.update(NetworkInfo().collect_heartbeat())
                    _net_last_time[0] = time.time()
                except Exception as ne:
                    log.debug(f"Network info error: {ne}")

            # Refresh current user info every 60 seconds
            if time.time() - _user_last_time[0] >= 60:
                try:
                    _user_cache.clear()
                    _user_cache.update(Scanner().get_current_user())
                    _user_last_time[0] = time.time()
                except Exception as ue:
                    log.debug(f"User info error: {ue}")

            _post(REALTIME_URL, {
                "token":         AGENT_TOKEN,
                "deviceId":      DEVICE_ID,
                "cpu_percent":   round(cpu, 1),
                "ram_percent":   round(mem.percent, 1),
                "ram_used_gb":   round(mem.used  / 1e9, 2),
                "ram_total_gb":  round(mem.total / 1e9, 2),
                "top_processes": top5,
                "temperatures":  temps,
                "network":       dict(_net_cache) if _net_cache else None,
                "current_user":  dict(_user_cache) if _user_cache else None,
            })
        except Exception as e:
            log.debug(f"Realtime heartbeat error: {e}")

    def _agent_loop():
        """Runs in a background thread — heartbeat + scheduled scans."""
        send_heartbeat()
        run_scan()
        schedule.every(HEARTBEAT_SECS).seconds.do(send_heartbeat)
        schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
        schedule.every(10).seconds.do(send_realtime_heartbeat)
        log.info(f"PCGuard v{AGENT_VERSION} running (heartbeat={HEARTBEAT_SECS}s, scan={SCAN_INTERVAL}s)")
        while not _stop.is_set():
            if _scan_now.is_set():
                _scan_now.clear()
                run_scan()
            schedule.run_pending()
            time.sleep(1)

    # ── System tray icon ──────────────────────────────────────────────────────

    def _make_icon_image():
        """Draw a simple shield icon using PIL."""
        size = 64
        img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d    = ImageDraw.Draw(img)
        # Outer shield (blue)
        shield = [(8, 4), (56, 4), (56, 40), (32, 60), (8, 40)]
        d.polygon(shield, fill=(30, 110, 235, 255))
        # Inner highlight (lighter blue)
        inner = [(14, 10), (50, 10), (50, 38), (32, 54), (14, 38)]
        d.polygon(inner, fill=(80, 160, 255, 255))
        # Small white checkmark
        d.line([(22, 32), (29, 40), (42, 24)], fill=(255, 255, 255, 255), width=4)
        return img

    def _on_open_dashboard(icon, item):
        webbrowser.open("https://pcguard-rami.web.app")

    def _on_run_scan(icon, item):
        _scan_now.set()

    def _on_exit(icon, item):
        _stop.set()
        icon.stop()

    # Start agent loop in background thread (pystray must own the main thread)
    threading.Thread(target=_agent_loop, daemon=True).start()

    tray_menu = pystray.Menu(
        pystray.MenuItem("PC Guard is running", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Dashboard", _on_open_dashboard),
        pystray.MenuItem("Run Scan Now",   _on_run_scan),
        pystray.MenuItem("Exit PC Guard",  _on_exit),
    )
    tray = pystray.Icon("PCGuard", _make_icon_image(), "PC Guard", tray_menu)
    tray.run()   # blocks main thread until exit

else:
    # ── GUI INSTALLER MODE ────────────────────────────────────────────────────
    import json
    import time
    import shutil
    import socket
    import winreg
    import threading
    import subprocess
    import tkinter as tk
    from tkinter import ttk
    import requests

    # ── Color palette ──────────────────────────────────────────────────────────
    C_BG      = "#ffffff"
    C_HEADER  = "#1d4ed8"       # blue
    C_ACCENT  = "#2563eb"
    C_TEXT    = "#111827"
    C_MUTED   = "#6b7280"
    C_SUCCESS = "#059669"       # green
    C_ERROR   = "#dc2626"       # red
    C_BORDER  = "#e5e7eb"
    C_LIGHT   = "#f3f4f6"

    F_TITLE   = ("Segoe UI", 18, "bold")
    F_HEAD    = ("Segoe UI", 13, "bold")
    F_BODY    = ("Segoe UI", 10)
    F_MONO    = ("Consolas", 11)
    F_BTN     = ("Segoe UI", 12, "bold")
    F_BTN_SM  = ("Segoe UI", 10)

    class PCGuardSetup:
        def __init__(self):
            self.root = tk.Tk()
            self.root.title("PC Guard — Setup")
            self.root.resizable(False, False)
            self.root.configure(bg=C_BG)
            self._center(520, 500)

            self.token_var   = tk.StringVar()
            self.status_var  = tk.StringVar(value="")
            self.progress_var= tk.DoubleVar(value=0)

            # Configure ttk progress bar style
            style = ttk.Style()
            style.theme_use("default")
            style.configure("Blue.Horizontal.TProgressbar",
                            troughcolor=C_BORDER, background=C_ACCENT,
                            thickness=12)

            self._show_step1()
            self.root.mainloop()

        def _center(self, w, h):
            self.root.update_idletasks()
            x = (self.root.winfo_screenwidth()  - w) // 2
            y = (self.root.winfo_screenheight() - h) // 2
            self.root.geometry(f"{w}x{h}+{x}+{y}")

        def _clear(self):
            for widget in self.root.winfo_children():
                widget.destroy()

        def _header(self, title="PC Guard", bg=C_HEADER, fg="white"):
            hf = tk.Frame(self.root, bg=bg, height=76)
            hf.pack(fill="x")
            hf.pack_propagate(False)
            tk.Label(hf, text=f"🛡️  {title}", font=F_TITLE,
                     bg=bg, fg=fg).pack(expand=True)

        # ── STEP 1: Token input ────────────────────────────────────────────────

        def _show_step1(self):
            self._clear()
            self._header()

            body = tk.Frame(self.root, bg=C_BG, padx=44, pady=32)
            body.pack(fill="both", expand=True)

            tk.Label(body, text="Welcome! Let's get started.", font=F_HEAD,
                     bg=C_BG, fg=C_TEXT).pack(anchor="w")
            tk.Label(body,
                     text="Paste your personal token below. You'll find it on\n"
                          "the Setup page at pcguard-rami.web.app.",
                     font=F_BODY, bg=C_BG, fg=C_MUTED, justify="left"
                    ).pack(anchor="w", pady=(4, 24))

            tk.Label(body, text="Your Personal Token", font=("Segoe UI", 10, "bold"),
                     bg=C_BG, fg=C_TEXT).pack(anchor="w")

            row = tk.Frame(body, bg=C_BG)
            row.pack(fill="x", pady=(6, 4))

            self.token_entry = tk.Entry(
                row, textvariable=self.token_var, font=F_MONO,
                relief="solid", bd=1, fg=C_ACCENT, insertbackground=C_ACCENT
            )
            self.token_entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=8)
            self.token_entry.focus()

            tk.Button(row, text="Paste", font=F_BTN_SM, bg=C_LIGHT, fg=C_TEXT,
                      relief="flat", padx=14, pady=8, cursor="hand2",
                      command=self._paste).pack(side="left", padx=(8, 0))

            self.err_label = tk.Label(body, text="", font=F_BODY, bg=C_BG, fg=C_ERROR)
            self.err_label.pack(anchor="w", pady=(2, 0))

            # Bottom button bar
            bar = tk.Frame(self.root, bg=C_LIGHT, padx=44, pady=18)
            bar.pack(fill="x", side="bottom")

            self.install_btn = tk.Button(
                bar, text="Install  →", font=F_BTN,
                bg=C_ACCENT, fg="white", relief="flat",
                padx=32, pady=12, cursor="hand2",
                command=self._start_install,
                activebackground="#1d4ed8", activeforeground="white"
            )
            self.install_btn.pack(side="right")

        def _paste(self):
            try:
                text = self.root.clipboard_get().strip()
                self.token_var.set(text)
            except Exception:
                pass

        def _start_install(self):
            token = self.token_var.get().strip()
            if not token.startswith("pcg-") or len(token) < 20:
                self.err_label.config(text="⚠  Please paste a valid token (it starts with  pcg-)")
                return
            self.err_label.config(text="")
            self.install_btn.config(state="disabled")
            self._show_step2(token)

        # ── STEP 2: Installing ─────────────────────────────────────────────────

        def _show_step2(self, token):
            self._clear()
            self._header("Installing…")

            body = tk.Frame(self.root, bg=C_BG, padx=44, pady=36)
            body.pack(fill="both", expand=True)

            tk.Label(body, text="Setting up PC Guard on this computer.",
                     font=F_HEAD, bg=C_BG, fg=C_TEXT).pack(anchor="w")

            self.status_label = tk.Label(
                body, text="Starting…", font=F_BODY, bg=C_BG, fg=C_MUTED
            )
            self.status_label.pack(anchor="w", pady=(8, 20))

            self.progress_bar = ttk.Progressbar(
                body, variable=self.progress_var, maximum=100, length=420,
                style="Blue.Horizontal.TProgressbar"
            )
            self.progress_bar.pack(fill="x")

            # Start install thread
            threading.Thread(
                target=self._do_install, args=(token,), daemon=True
            ).start()

        def _set_status(self, msg, pct):
            self.root.after(0, lambda: [
                self.status_label.config(text=msg),
                self.progress_var.set(pct),
            ])

        def _do_install(self, token):
            steps = [
                ("Validating your token…",          15, lambda: self._validate(token)),
                ("Creating installation folder…",   30, lambda: os.makedirs(INSTALL_DIR, exist_ok=True)),
                ("Copying files…",                  50, lambda: self._copy_exe()),
                ("Saving configuration…",           65, lambda: self._write_config(token)),
                ("Setting up auto-start…",          80, lambda: self._add_startup()),
                ("Starting PC Guard…",              93, lambda: self._launch()),
            ]
            for msg, pct, action in steps:
                self._set_status(msg, pct)
                time.sleep(0.35)
                try:
                    result = action()
                    if result is False:
                        self.root.after(0, lambda: self._show_error(
                            "Token not recognised.\n"
                            "Go back to pcguard-rami.web.app and copy your token again."
                        ))
                        return
                except Exception as exc:
                    self.root.after(0, lambda e=exc: self._show_error(str(e)))
                    return

            self.progress_var.set(100)
            time.sleep(0.4)
            self.root.after(0, self._show_step3)

        def _validate(self, token):
            try:
                r = requests.post(HEARTBEAT_URL, json={
                    "token":        token,
                    "hostname":     socket.gethostname(),
                    "agentVersion": AGENT_VERSION,
                }, timeout=15)
                return r.status_code == 200
            except requests.RequestException:
                raise RuntimeError(
                    "Could not connect to the server.\n"
                    "Check your internet connection and try again."
                )

        def _copy_exe(self):
            if not IS_BUNDLED:
                return   # dev mode — nothing to copy
            src = sys.executable
            dst = os.path.join(INSTALL_DIR, EXE_NAME)
            if os.path.abspath(src) != os.path.abspath(dst):
                shutil.copy2(src, dst)

        def _write_config(self, token):
            cfg = {
                "agent_token":       token,
                "scan_interval":     300,
                "heartbeat_interval": 60,
            }
            with open(CONFIG_FILE, "w") as f:
                json.dump(cfg, f, indent=2)

        def _add_startup(self):
            exe_path = os.path.join(INSTALL_DIR, EXE_NAME)
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(key, APP_REG_KEY, 0, winreg.REG_SZ,
                              f'"{exe_path}" --run')
            winreg.CloseKey(key)

        def _launch(self):
            exe_path = os.path.join(INSTALL_DIR, EXE_NAME)
            if os.path.exists(exe_path):
                subprocess.Popen(
                    [exe_path, "--run"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    close_fds=True,
                )

        def _show_error(self, msg):
            self._show_step1()
            self.err_label.config(text=f"⚠  {msg}")

        # ── STEP 3: Done ──────────────────────────────────────────────────────

        def _show_step3(self):
            self._clear()
            self._header("All Done! ✓", bg=C_SUCCESS)

            body = tk.Frame(self.root, bg=C_BG, padx=44, pady=36)
            body.pack(fill="both", expand=True)

            tk.Label(body, text="PC Guard is now protecting your computer.",
                     font=F_HEAD, bg=C_BG, fg=C_TEXT).pack(anchor="w")

            tk.Label(body,
                     text="It's running quietly in the background.\n"
                          "It will start automatically every time you turn on your computer.",
                     font=F_BODY, bg=C_BG, fg=C_MUTED, justify="left"
                    ).pack(anchor="w", pady=(8, 28))

            tk.Label(body,
                     text="🌐   Your dashboard will update within 1 minute.",
                     font=("Segoe UI", 11, "bold"), bg=C_BG, fg=C_ACCENT
                    ).pack(anchor="w")

            bar = tk.Frame(self.root, bg=C_LIGHT, padx=44, pady=18)
            bar.pack(fill="x", side="bottom")

            tk.Button(
                bar, text="Close", font=F_BTN,
                bg=C_LIGHT, fg=C_TEXT, relief="flat",
                padx=32, pady=12, cursor="hand2",
                command=self.root.destroy,
            ).pack(side="right")

    PCGuardSetup()
