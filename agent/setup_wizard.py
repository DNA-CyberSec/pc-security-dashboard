"""
PCGuard Setup Wizard — Entry point for the bundled Windows .exe

Two modes depending on command-line argument:
  (no args)  →  Show GUI installer wizard (for first-time setup)
  --run      →  Run silently as a background agent

PyInstaller bundles this file + all modules into a single PCGuard-Setup.exe
"""

import sys
import os

# ── Constants shared by both modes ────────────────────────────────────────────

AGENT_VERSION   = "0.6.0"
INSTALL_DIR     = r"C:\pc-security-agent"
EXE_NAME        = "pc-guard-agent.exe"
CONFIG_FILE     = os.path.join(INSTALL_DIR, "config.json")
LOG_FILE        = os.path.join(INSTALL_DIR, "agent.log")
APP_REG_KEY     = "PCGuardAgent"
IS_BUNDLED      = getattr(sys, "frozen", False)
BACKGROUND_MODE = "--run" in sys.argv

FUNCTIONS_BASE  = "https://us-central1-pc-security-dashboard.cloudfunctions.net"
HEARTBEAT_URL   = f"{FUNCTIONS_BASE}/agentHeartbeat"
SUBMIT_SCAN_URL = f"{FUNCTIONS_BASE}/submitScan"

# ── Route to correct mode ─────────────────────────────────────────────────────

if BACKGROUND_MODE:
    # ── BACKGROUND AGENT MODE ─────────────────────────────────────────────────
    import json
    import time
    import socket
    import logging
    import requests
    import schedule

    from modules.scanner   import Scanner
    from modules.processes import ProcessScanner
    from modules.network   import NetworkScanner
    from modules.privacy   import PrivacyScanner

    # Set up logging to file (no console window in background mode)
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
            "hostname":     socket.gethostname(),
            "username":     os.environ.get("USERNAME", "unknown"),
            "agentVersion": AGENT_VERSION,
            "readOnlyMode": True,
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
        return max(0, min(100, score))

    def run_scan():
        log.info("Scan started")
        scan = {
            "agentVersion":       AGENT_VERSION,
            "hostname":           socket.gethostname(),
            "storage":            _safe("storage",       Scanner().scan_all_drives),
            "tempSummary":        _safe("temp",          Scanner().scan_temp_summary),
            "largeFiles":         _safe("large_files",   Scanner().scan_large_files),
            "startupItems":       _safe("startup",       Scanner().scan_startup_items),
            "installedSoftware":  _safe("software",      Scanner().scan_installed_software),
            "vulnerabilities":    _safe("vulns",         Scanner().scan_vulnerabilities),
            "processes":          _safe("processes",     ProcessScanner().scan_processes),
            "networkConnections": _safe("network",       NetworkScanner().scan_connections),
            "browserData":        _safe("browser",       PrivacyScanner().scan_browser_data),
        }
        scan["healthScore"] = _health_score(scan)
        status, resp = _post(SUBMIT_SCAN_URL, {"token": AGENT_TOKEN, "scan": scan})
        if status == 200:
            log.info(f"Scan uploaded → {resp.get('scanId', '?')}  score={scan['healthScore']}")
        elif status == 401:
            log.error("Scan rejected — invalid token")
        else:
            log.error(f"Scan upload failed: HTTP {status}")

    # Run immediately then schedule
    send_heartbeat()
    run_scan()
    schedule.every(HEARTBEAT_SECS).seconds.do(send_heartbeat)
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
    log.info(f"PCGuard v{AGENT_VERSION} running (heartbeat={HEARTBEAT_SECS}s, scan={SCAN_INTERVAL}s)")
    while True:
        schedule.run_pending()
        time.sleep(1)

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
