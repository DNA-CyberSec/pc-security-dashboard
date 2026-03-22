import React, { useEffect, useState, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { signOut } from "firebase/auth";
import { collection, doc, onSnapshot, setDoc } from "firebase/firestore";
import { auth, db } from "../firebase";
import { useResponsive } from "../hooks/useResponsive";

// ── Update Modal ───────────────────────────────────────────────────────────────

function UpdateModal({ device, latestVersion, onClose, t }) {
  const isLinux  = device.os === "Linux";
  const current  = device.agentVersion || "?";
  const latest   = isLinux ? latestVersion.linux_version : latestVersion.windows_version;
  const changelog = latestVersion.changelog || "";
  const dlUrl    = `https://github.com/DNA-CyberSec/pc-security-dashboard/releases/latest/download/PCGuard-Setup.exe`;
  const linuxCmd = "curl -sSL https://pcguard-rami.web.app/install.sh | bash";
  const [copied, setCopied] = useState(false);

  const copyCmd = () => {
    navigator.clipboard.writeText(linuxCmd).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };

  return (
    <div style={ms.overlay} onClick={onClose}>
      <div style={ms.modal} onClick={e => e.stopPropagation()}>
        <div style={ms.header}>
          <span style={{ fontSize: 20 }}>🔄</span>
          <p style={ms.title}>{t("version.updateTitle")}</p>
          <button onClick={onClose} style={ms.closeBtn}>✕</button>
        </div>
        <p style={ms.desc}>{t("version.updateDesc")}</p>
        <div style={ms.versionRow}>
          <div style={ms.versionBox}>
            <p style={ms.versionLabel}>{t("version.current")}</p>
            <p style={{ ...ms.versionNum, color: "#fc8181" }}>{current}</p>
          </div>
          <span style={{ color: "#4a5568", fontSize: 20 }}>→</span>
          <div style={ms.versionBox}>
            <p style={ms.versionLabel}>{t("version.latest")}</p>
            <p style={{ ...ms.versionNum, color: "#56d364" }}>{latest || "?"}</p>
          </div>
        </div>
        {changelog && (
          <div style={ms.changelog}>
            <p style={ms.changelogTitle}>{t("version.changelog")}</p>
            <p style={ms.changelogText}>{changelog}</p>
          </div>
        )}
        <div style={ms.actions}>
          {isLinux ? (
            <>
              <p style={{ fontSize: 12, color: "#8b949e", marginBottom: 6 }}>{t("version.linuxUpdateCmd")}</p>
              <div style={{ display: "flex", gap: 8 }}>
                <code style={ms.cmd}>{linuxCmd}</code>
                <button onClick={copyCmd} style={ms.copyBtn}>
                  {copied ? "✓" : t("setup.copy")}
                </button>
              </div>
            </>
          ) : (
            <a href={dlUrl} target="_blank" rel="noreferrer" style={ms.dlBtn}>
              ⬇ {t("version.downloadWindows")}
            </a>
          )}
        </div>
      </div>
    </div>
  );
}

const ms = {
  overlay:  { position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 100,
               display: "flex", alignItems: "center", justifyContent: "center" },
  modal:    { background: "#161b22", border: "1px solid #30363d", borderRadius: 14,
               padding: "28px 32px", width: 440, maxWidth: "90vw" },
  header:   { display: "flex", alignItems: "center", gap: 10, marginBottom: 12 },
  title:    { flex: 1, fontSize: 16, fontWeight: 700, color: "#e2e8f0", margin: 0 },
  closeBtn: { background: "transparent", border: "none", color: "#8b949e",
               cursor: "pointer", fontSize: 18, padding: 0 },
  desc:     { color: "#8b949e", fontSize: 13, marginBottom: 20, margin: "0 0 20px" },
  versionRow: { display: "flex", alignItems: "center", gap: 20, marginBottom: 20 },
  versionBox: { flex: 1, background: "#0d1117", border: "1px solid #21262d",
                 borderRadius: 8, padding: "10px 14px", textAlign: "center" },
  versionLabel: { fontSize: 11, color: "#8b949e", textTransform: "uppercase",
                   letterSpacing: 1, margin: "0 0 4px" },
  versionNum:   { fontSize: 18, fontWeight: 700, margin: 0, fontFamily: "monospace" },
  changelog: { background: "#0d1117", border: "1px solid #21262d", borderRadius: 8,
                padding: "10px 14px", marginBottom: 20 },
  changelogTitle: { fontSize: 11, color: "#8b949e", textTransform: "uppercase",
                     letterSpacing: 1, margin: "0 0 6px" },
  changelogText:  { fontSize: 13, color: "#c9d1d9", margin: 0, lineHeight: 1.6 },
  actions: { display: "flex", flexDirection: "column" },
  cmd:  { flex: 1, background: "#0d1117", border: "1px solid #21262d", borderRadius: 6,
           padding: "6px 10px", fontSize: 11, color: "#58a6ff", fontFamily: "monospace",
           overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  copyBtn: { background: "#238636", color: "#fff", border: "none",
              borderRadius: 6, padding: "6px 14px", cursor: "pointer", fontSize: 12 },
  dlBtn: { display: "block", background: "#1f6feb", color: "#fff", border: "none",
            borderRadius: 8, padding: "10px 20px", cursor: "pointer",
            fontSize: 14, fontWeight: 600, textAlign: "center", textDecoration: "none" },
};

// ── Mini Circular Gauge ───────────────────────────────────────────────────────

function MiniGauge({ value, size = 52, color }) {
  const cx = size / 2, cy = size / 2, r = size * 0.36;
  const strokeW       = size * 0.1;
  const circumference = 2 * Math.PI * r;
  const pct    = value != null ? Math.min(Math.max(value / 100, 0), 1) : 0;
  const offset = circumference * (1 - pct);

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#21262d" strokeWidth={strokeW} />
      {value != null && (
        <circle cx={cx} cy={cy} r={r} fill="none"
          stroke={color} strokeWidth={strokeW}
          strokeDasharray={circumference} strokeDashoffset={offset}
          strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: "stroke-dashoffset 0.5s ease" }}
        />
      )}
      <text x={cx} y={cy + 4.5}
        textAnchor="middle" fill="#e2e8f0"
        fontSize={size * 0.22} fontWeight="700" fontFamily="system-ui, sans-serif">
        {value != null ? `${Math.round(value)}%` : "—"}
      </text>
    </svg>
  );
}

// ── Health Bar ────────────────────────────────────────────────────────────────

function HealthBar({ score }) {
  if (score == null) return <span style={{ color: "#4a5568" }}>—</span>;
  const color = score >= 80 ? "#f6ad55" : score >= 50 ? "#ed8936" : "#fc8181";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 6, background: "#21262d", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color, borderRadius: 3,
                      transition: "width 0.5s ease" }} />
      </div>
      <span style={{ fontSize: 12, fontWeight: 700, color, minWidth: 28 }}>{score}%</span>
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function gaugeColor(pct) {
  if (pct == null) return "#4a5568";
  if (pct >= 80) return "#fc8181";
  if (pct >= 60) return "#ed8936";
  return "#48bb78";
}

function healthColor(score) {
  if (score == null) return "#4a5568";
  if (score >= 80) return "#f6ad55";
  if (score >= 50) return "#ed8936";
  return "#fc8181";
}

function formatAgo(ts, t) {
  if (!ts) return null;
  const date = ts.toDate ? ts.toDate() : new Date(ts);
  const diff  = Math.floor((Date.now() - date.getTime()) / 1000);
  if (diff < 60)    return t("devices.justNow");
  if (diff < 3600)  return t("devices.minutesAgo", { n: Math.floor(diff / 60) });
  if (diff < 86400) return t("devices.hoursAgo",   { n: Math.floor(diff / 3600) });
  return t("devices.daysAgo", { n: Math.floor(diff / 86400) });
}

function isDeviceOnline(device) {
  const ls = device.last_seen?.toDate?.() || device.lastHeartbeat?.toDate?.();
  return ls && Date.now() - ls.getTime() < 90_000;
}

function hasAlerts(device) {
  return (device.threatCount || 0) > 0 || (device.vulnerabilityCount || 0) > 0;
}

// ── Device Card (Grid Mode) ───────────────────────────────────────────────────

function DeviceCard({ device, rt, online, onView, onEditNickname, latestVersion, onUpdateClick, t, isRTL }) {
  const { isMobile, isTablet } = useResponsive();
  const [flash, setFlash] = useState(false);

  useEffect(() => {
    if (!rt) return;
    setFlash(true);
    const id = setTimeout(() => setFlash(false), 700);
    return () => clearTimeout(id);
  }, [rt?.updatedAt]); // eslint-disable-line react-hooks/exhaustive-deps

  const fw = device.firewallGrade;
  const alerts = hasAlerts(device);
  const displayName = device.nickname || device.name || device.deviceId || "Unknown";

  return (
    <div
      onClick={onView}
      style={{
        ...s.deviceCard,
        opacity: online ? 1 : 0.6,
        cursor: "pointer",
        outline: flash ? "2px solid #238636" : "none",
        transition: "outline 0.3s ease",
        borderColor: alerts ? "#742a2a" : "#21262d",
      }}
    >
      {/* Header */}
      <div style={s.cardHeader}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <span style={{ ...s.statusDot, background: online ? "#56d364" : "#6e7681" }} />
          <span style={{ fontSize: 16, flexShrink: 0 }}>
            {device.os === "Linux" ? "🐧" : "🪟"}
          </span>
          <div style={{ minWidth: 0 }}>
            <p style={s.deviceName}>{displayName}</p>
            {device.nickname && device.name && (
              <p style={s.deviceSub}>{device.name}</p>
            )}
          </div>
        </div>
        <button
          onClick={e => { e.stopPropagation(); onEditNickname(); }}
          style={s.pencilBtn}
          title={t("devices.editNickname")}
        >
          ✏️
        </button>
      </div>

      {/* Last seen */}
      <p style={{ ...s.lastSeen, color: online ? "#56d364" : "#8b949e" }}>
        {online ? `🟢 ${t("devices.online")}` : `⚫ ${t("devices.lastSeen")}: ${formatAgo(device.last_seen, t) || "—"}`}
      </p>

      {/* Mini gauges row */}
      <div style={s.miniGaugeRow}>
        {[
          { label: t("dashboard.cpu"),    value: rt?.cpu_percent,  color: gaugeColor(rt?.cpu_percent) },
          { label: t("dashboard.ram"),    value: rt?.ram_percent,  color: gaugeColor(rt?.ram_percent) },
          { label: t("dashboard.disk"),   value: device.storage?.length
              ? (device.storage.reduce((a, d) => a + d.usedGB, 0) / Math.max(device.storage.reduce((a, d) => a + d.totalGB, 0), 1)) * 100
              : null,
            color: "#ed8936" },
          { label: t("dashboard.healthScore"), value: device.healthScore, color: healthColor(device.healthScore) },
        ].map(({ label, value, color }) => (
          <div key={label} style={s.miniGaugeWrap}>
            <MiniGauge value={value != null ? Math.round(value) : null} size={isMobile ? 60 : isTablet ? 64 : 72} color={color} />
            <span style={s.miniGaugeLabel}>{label}</span>
          </div>
        ))}
      </div>

      {/* Security row */}
      <div style={s.cardSection}>
        {(device.threatCount || 0) > 0 ? (
          <span style={{ color: "#fc8181", fontSize: 12 }}>🔴 {t("dashboard.security.threats", { count: device.threatCount })}</span>
        ) : (device.suspiciousCount || 0) > 0 ? (
          <span style={{ color: "#ed8936", fontSize: 12 }}>🟡 {t("dashboard.security.suspicious", { count: device.suspiciousCount })}</span>
        ) : (
          <span style={{ color: "#56d364", fontSize: 12 }}>✅ {t("dashboard.allClear")}</span>
        )}
        {fw && (
          <span style={{
            ...s.gradePill,
            color:       fw === "A" ? "#56d364" : fw === "F" ? "#fc8181" : "#f6ad55",
            borderColor: fw === "A" ? "#238636" : fw === "F" ? "#742a2a" : "#7d4f00",
            background:  fw === "A" ? "#0d2818" : fw === "F" ? "#2d1b1b" : "#2d2008",
          }}>
            🔥 {fw}
          </span>
        )}
      </div>

      {/* Temps */}
      {rt?.temperatures?.length > 0 && (
        <div style={s.cardSection}>
          <span style={{ fontSize: 12, color: "#8b949e" }}>🌡️ </span>
          {rt.temperatures.slice(0, 2).map((temp, i) => {
            const color = temp.current >= 80 ? "#fc8181" : temp.current >= 65 ? "#ed8936" : "#56d364";
            return (
              <span key={i} style={{ fontSize: 12, color, marginRight: 8 }}>
                {temp.label}: {temp.current}°C
              </span>
            );
          })}
        </div>
      )}

      {/* Network section */}
      {device.network_connected !== undefined && device.network_connected !== null && (
        <div style={{ ...s.cardSection, flexWrap: "wrap", gap: 4 }}>
          <span style={{ fontSize: 12, color: device.network_connected ? "#56d364" : "#fc8181" }}>
            {device.network_connected ? "🌐" : "🔌"}{" "}
            {device.network_connected ? t("network.connected") : t("network.disconnected")}
            {device.network_latency_ms != null && ` · ${device.network_latency_ms}${t("network.ms")}`}
          </span>
          {device.network_local_ip && (
            <span style={{ fontSize: 11, color: "#8b949e" }}>{device.network_local_ip}</span>
          )}
          {device.network_rdp_enabled && (
            <span style={{ fontSize: 11, color: "#ed8936", background: "#2d2008",
                           border: "1px solid #7d4f00", borderRadius: 4, padding: "1px 5px" }}>
              RDP
            </span>
          )}
          {device.network_ssh_enabled && (
            <span style={{ fontSize: 11, color: "#f6ad55", background: "#2d2008",
                           border: "1px solid #7d4f00", borderRadius: 4, padding: "1px 5px" }}>
              SSH
            </span>
          )}
          {(device.network_dangerous_ports || 0) > 0 && (
            <span style={{ fontSize: 11, color: "#fc8181" }}>
              ⚠️ {device.network_dangerous_ports} {t("network.dangerousPorts")}
            </span>
          )}
        </div>
      )}

      {/* Linux-specific row */}
      {device.os === "Linux" && (
        <div style={{ ...s.cardSection, flexWrap: "wrap", gap: 4 }}>
          {device.uptime_seconds != null && (() => {
            const d = Math.floor(device.uptime_seconds / 86400);
            const h = Math.floor((device.uptime_seconds % 86400) / 3600);
            return <span style={{ fontSize: 12, color: "#8b949e" }}>⏱ {d > 0 ? `${d}d ${h}h` : `${h}h`}</span>;
          })()}
          {device.ssh_failed_logins > 0 && (
            <span style={{ fontSize: 12, color: "#ed8936" }}>
              ⚠️ {device.ssh_failed_logins} {t("linux.failedLogins")}
            </span>
          )}
          {device.firewall_active === false && (
            <span style={{ fontSize: 12, color: "#fc8181" }}>🔴 UFW off</span>
          )}
          {device.firewall_active === true && (
            <span style={{ fontSize: 12, color: "#56d364" }}>🛡️ UFW on</span>
          )}
        </div>
      )}

      {/* Logged-in user row */}
      {device.current_username && (
        <div style={{ ...s.cardSection, flexWrap: "wrap", gap: 4 }}>
          <span style={{ fontSize: 12, color: "#8b949e" }}>👤</span>
          <span style={{ fontSize: 12, color: "#c9d1d9" }}>{device.current_username}</span>
          {device.current_user_is_admin && (
            <span style={{ fontSize: 10, background: "#2d2008", border: "1px solid #7d4f00",
                           color: "#f6ad55", borderRadius: 4, padding: "1px 5px" }}>
              {t("users.admin")}
            </span>
          )}
          {device.current_user_session_type && (
            <span style={{ fontSize: 10, color: "#6e7681" }}>
              ({t(`users.${device.current_user_session_type}`) || device.current_user_session_type})
            </span>
          )}
          {device.active_session_count > 1 && (
            <span style={{ fontSize: 10, color: "#8b949e" }}>+{device.active_session_count - 1}</span>
          )}
        </div>
      )}

      {/* Version badge */}
      {device.agentVersion && latestVersion && (() => {
        const expected = device.os === "Linux" ? latestVersion.linux_version : latestVersion.windows_version;
        const isUpToDate = !expected || device.agentVersion === expected;
        return (
          <div style={{ ...s.cardSection }}>
            <span
              onClick={e => { e.stopPropagation(); if (!isUpToDate) onUpdateClick(); }}
              style={{
                fontSize: 10, padding: "2px 7px", borderRadius: 10,
                cursor: isUpToDate ? "default" : "pointer",
                background: isUpToDate ? "#0d2818" : "#2d2008",
                color:      isUpToDate ? "#56d364" : "#f6ad55",
                border:     `1px solid ${isUpToDate ? "#238636" : "#7d4f00"}`,
              }}
            >
              v{device.agentVersion} {isUpToDate ? `✓ ${t("version.upToDate")}` : `⬆ ${t("version.updateAvailable")}`}
            </span>
          </div>
        );
      })()}

      {/* View button */}
      <button
        onClick={e => { e.stopPropagation(); onView(); }}
        style={s.viewBtn}
      >
        {t("devices.viewDetails")}
      </button>
    </div>
  );
}

// ── Dashboard (multi-device) ──────────────────────────────────────────────────

export default function Dashboard({ user }) {
  const { t, i18n } = useTranslation();
  const navigate    = useNavigate();
  const isRTL       = i18n.language === "he";
  const { isMobile, isTablet } = useResponsive();

  const [devices,        setDevices]        = useState([]);
  const [realtimeMap,    setRealtimeMap]     = useState({});     // deviceId → rt data
  const [loading,        setLoading]         = useState(true);
  const [viewMode,       setViewMode]        = useState(null);   // null=auto, "grid", "table"
  const [filter,         setFilter]          = useState("all");
  const [search,         setSearch]          = useState("");
  const [sortBy,         setSortBy]          = useState("name");
  const [sortDir,        setSortDir]         = useState("asc");
  const [editingDevice,  setEditingDevice]   = useState(null);   // deviceId being renamed
  const [nicknameInput,  setNicknameInput]   = useState("");
  const [latestVersion,  setLatestVersion]   = useState(null);   // /config/latestAgentVersion
  const [updateModal,    setUpdateModal]     = useState(null);   // device object or null

  const realtimeUnsubsRef = useRef({});

  // ── Subscribe to latest agent version ─────────────────────────────────────
  useEffect(() => {
    const unsub = onSnapshot(
      doc(db, "config", "latestAgentVersion"),
      snap => { if (snap.exists()) setLatestVersion(snap.data()); },
      () => {},
    );
    return () => unsub();
  }, []);

  // ── Subscribe to all devices ──────────────────────────────────────────────
  useEffect(() => {
    const unsub = onSnapshot(
      collection(db, "users", user.uid, "devices"),
      snap => {
        setDevices(snap.docs.map(d => ({ id: d.id, ...d.data() })));
        setLoading(false);
      },
      () => setLoading(false),
    );
    return () => unsub();
  }, [user.uid]);

  // ── Subscribe to realtime data for visible devices (visibility-aware) ─────
  const subscribeAllRealtime = useCallback(() => {
    if (document.hidden) return;
    devices.forEach(device => {
      if (realtimeUnsubsRef.current[device.id]) return;
      realtimeUnsubsRef.current[device.id] = onSnapshot(
        doc(db, "users", user.uid, "devices", device.id, "realtime", "current"),
        snap => {
          if (snap.exists()) {
            setRealtimeMap(prev => ({ ...prev, [device.id]: snap.data() }));
          }
        },
      );
    });
  }, [devices, user.uid]);

  const unsubscribeAllRealtime = useCallback(() => {
    Object.values(realtimeUnsubsRef.current).forEach(unsub => unsub());
    realtimeUnsubsRef.current = {};
  }, []);

  useEffect(() => {
    subscribeAllRealtime();
    const onVisibility = () =>
      document.hidden ? unsubscribeAllRealtime() : subscribeAllRealtime();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      unsubscribeAllRealtime();
    };
  }, [subscribeAllRealtime, unsubscribeAllRealtime]);

  // ── Nickname save ─────────────────────────────────────────────────────────
  const saveNickname = async (deviceId) => {
    const nickname = nicknameInput.trim();
    await setDoc(doc(db, "users", user.uid, "devices", deviceId), { nickname }, { merge: true });
    setEditingDevice(null);
  };

  // ── Derived values ────────────────────────────────────────────────────────
  const totalDevices = devices.length;
  const onlineCount  = devices.filter(isDeviceOnline).length;
  const alertCount   = devices.filter(hasAlerts).length;
  const avgHealth    = devices.length > 0
    ? Math.round(devices.reduce((s, d) => s + (d.healthScore || 0), 0) / devices.length)
    : null;

  const effectiveMode = viewMode || (devices.length >= 6 ? "table" : "grid");

  const toggleLang = () => {
    const l = i18n.language === "en" ? "he" : "en";
    i18n.changeLanguage(l);
    localStorage.setItem("lang", l);
  };

  // ── Filter + search + sort ────────────────────────────────────────────────
  let filtered = [...devices];
  if (filter === "online")  filtered = filtered.filter(isDeviceOnline);
  if (filter === "offline") filtered = filtered.filter(d => !isDeviceOnline(d));
  if (filter === "alerts")  filtered = filtered.filter(hasAlerts);
  if (search) {
    const q = search.toLowerCase();
    filtered = filtered.filter(d =>
      (d.name || "").toLowerCase().includes(q) ||
      (d.nickname || "").toLowerCase().includes(q)
    );
  }

  const sortKey = sortBy;
  filtered.sort((a, b) => {
    let va, vb;
    if (sortKey === "name")    { va = (a.nickname || a.name || ""); vb = (b.nickname || b.name || ""); }
    else if (sortKey === "health") { va = a.healthScore ?? -1; vb = b.healthScore ?? -1; }
    else if (sortKey === "status") { va = isDeviceOnline(a) ? 1 : 0; vb = isDeviceOnline(b) ? 1 : 0; }
    else { va = ""; vb = ""; }

    if (typeof va === "string") {
      return sortDir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
    }
    return sortDir === "asc" ? va - vb : vb - va;
  });

  const toggleSort = (col) => {
    if (sortBy === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortBy(col); setSortDir("asc"); }
  };

  // ── Inline nickname editor (shared) ──────────────────────────────────────
  const NicknameEditor = ({ deviceId }) => (
    <div style={{ display: "flex", gap: 4, alignItems: "center" }} onClick={e => e.stopPropagation()}>
      <input
        value={nicknameInput}
        onChange={e => setNicknameInput(e.target.value)}
        onKeyDown={e => {
          if (e.key === "Enter") saveNickname(deviceId);
          if (e.key === "Escape") setEditingDevice(null);
        }}
        style={s.nicknameInput}
        autoFocus
        placeholder={t("devices.nicknamePlaceholder")}
      />
      <button onClick={() => saveNickname(deviceId)} style={s.nicknameSave}>{t("devices.saveNickname")}</button>
      <button onClick={() => setEditingDevice(null)} style={s.ghostBtnSm}>✕</button>
    </div>
  );

  if (loading) {
    return <div style={s.centered}><p style={{ color: "#a0aec0" }}>{t("common.loading")}</p></div>;
  }

  return (
    <div dir={isRTL ? "rtl" : "ltr"} style={s.page}>

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header style={{
        ...s.header,
        paddingTop: "max(14px, env(safe-area-inset-top))",
        paddingLeft: isMobile ? "max(16px, env(safe-area-inset-left))" : "max(28px, env(safe-area-inset-left))",
        paddingRight: isMobile ? "max(16px, env(safe-area-inset-right))" : "max(28px, env(safe-area-inset-right))",
      }}>
        <div style={s.headerLeft}>
          <span style={{ fontSize: 22 }}>🛡️</span>
          <span style={s.headerTitle}>
            <span className="hdr-full">{t("app.title")}</span>
            <span className="hdr-short">PC Guard</span>
          </span>
        </div>
        <div style={s.headerRight}>
          <button onClick={toggleLang} style={s.ghostBtn}>
            🌐 <span className="btn-lbl">{i18n.language === "en" ? "עברית" : "English"}</span>
          </button>
          <button onClick={() => navigate("/setup")} style={s.ghostBtn}>
            + <span className="btn-lbl">{t("devices.addDevice")}</span>
          </button>
          <button onClick={() => signOut(auth).then(() => navigate("/login"))} style={s.ghostBtn}>
            ⏻ <span className="btn-lbl">{t("nav.logout")}</span>
          </button>
        </div>
      </header>

      <main style={{ ...s.main, padding: isMobile ? "16px 14px" : "28px 24px", paddingBottom: "max(32px, env(safe-area-inset-bottom))" }}>

        {/* ── Welcome + title ─────────────────────────────────────────── */}
        <div style={s.pageHeader}>
          <h2 style={s.pageTitle}>{t("devices.title")}</h2>
          {devices.length > 0 && (
            <div style={s.modeToggle}>
              <button
                onClick={() => setViewMode("grid")}
                style={{ ...s.modeBtn, ...(effectiveMode === "grid" ? s.modeBtnActive : {}) }}
              >
                ⊞ {t("devices.gridView")}
              </button>
              <button
                onClick={() => setViewMode("table")}
                style={{ ...s.modeBtn, ...(effectiveMode === "table" ? s.modeBtnActive : {}) }}
              >
                ≡ {t("devices.tableView")}
              </button>
            </div>
          )}
        </div>

        {/* ── No devices state ────────────────────────────────────────── */}
        {devices.length === 0 && (
          <div style={s.emptyState}>
            <span style={{ fontSize: 56 }}>🖥️</span>
            <h3 style={{ color: "#c9d1d9", margin: "12px 0 8px" }}>{t("devices.noDevices")}</h3>
            <p style={{ color: "#8b949e", marginBottom: 24 }}>{t("devices.noDevicesDesc")}</p>
            <button onClick={() => navigate("/setup")} style={s.addDeviceBtn}>
              + {t("devices.addDevice")}
            </button>
          </div>
        )}

        {devices.length > 0 && (
          <>
            {/* ── Summary tiles ─────────────────────────────────────────── */}
            <div className="rg-summary">
              {[
                { label: t("devices.totalDevices"), value: totalDevices,       icon: "🖥️",  color: "#58a6ff" },
                { label: t("devices.onlineDevices"), value: `${onlineCount} / ${totalDevices}`, icon: "🟢", color: "#56d364" },
                { label: t("devices.alerts"),        value: alertCount,          icon: "🔴",  color: alertCount > 0 ? "#fc8181" : "#56d364" },
                { label: t("devices.avgHealth"),     value: avgHealth != null ? `${avgHealth}%` : "—", icon: "💪", color: healthColor(avgHealth) },
              ].map(tile => (
                <div key={tile.label} style={s.summaryTile}>
                  <span style={{ fontSize: 24 }}>{tile.icon}</span>
                  <p style={{ ...s.tileValue, color: tile.color }}>{tile.value}</p>
                  <p style={s.tileLabel}>{tile.label}</p>
                </div>
              ))}
            </div>

            {/* ── Filter + search bar ───────────────────────────────────── */}
            <div style={s.filterBar}>
              <div style={s.filterBtns}>
                {[
                  ["all",     t("devices.allDevices")],
                  ["online",  t("devices.onlineOnly")],
                  ["offline", t("devices.offlineOnly")],
                  ["alerts",  t("devices.hasAlerts")],
                ].map(([val, label]) => (
                  <button
                    key={val}
                    onClick={() => setFilter(val)}
                    style={{ ...s.filterBtn, ...(filter === val ? s.filterBtnActive : {}) }}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder={t("devices.searchPlaceholder")}
                style={s.searchInput}
              />
            </div>

            {/* ── GRID VIEW ─────────────────────────────────────────────── */}
            {effectiveMode === "grid" && (
              <div className="rg-devices">
                {filtered.map(device => {
                  const online = isDeviceOnline(device);
                  const rt     = realtimeMap[device.id];
                  return editingDevice === device.id ? (
                    <div key={device.id} style={{ ...s.deviceCard, opacity: 1 }}>
                      <div style={s.cardHeader}>
                        <span style={{ color: "#e2e8f0", fontWeight: 600 }}>
                          {device.name || device.deviceId}
                        </span>
                        <NicknameEditor deviceId={device.id} />
                      </div>
                    </div>
                  ) : (
                    <DeviceCard
                      key={device.id}
                      device={device}
                      rt={rt}
                      online={online}
                      onView={() => navigate(`/device/${device.id}`)}
                      onEditNickname={() => {
                        setNicknameInput(device.nickname || "");
                        setEditingDevice(device.id);
                      }}
                      latestVersion={latestVersion}
                      onUpdateClick={() => setUpdateModal(device)}
                      t={t}
                      isRTL={isRTL}
                    />
                  );
                })}
              </div>
            )}

            {/* ── TABLE VIEW ────────────────────────────────────────────── */}
            {effectiveMode === "table" && (
              <div style={s.tableWrapper}>
                <table style={s.table}>
                  <thead>
                    <tr>
                      {[
                        ["name",   t("devices.device")],
                        ["status", t("devices.status")],
                        ["cpu",    t("dashboard.cpu")],
                        ["ram",    t("dashboard.ram")],
                        ["disk",   t("dashboard.disk")],
                        ["health", t("devices.health")],
                        ["grade",  t("devices.securityGrade")],
                        ["actions", t("devices.actions")],
                      ].map(([col, label]) => (
                        <th
                          key={col}
                          onClick={["name", "status", "health"].includes(col) ? () => toggleSort(col) : undefined}
                          style={{
                            ...s.th,
                            cursor: ["name", "status", "health"].includes(col) ? "pointer" : "default",
                          }}
                        >
                          {label}
                          {sortBy === col && <span style={{ marginLeft: 4 }}>{sortDir === "asc" ? "↑" : "↓"}</span>}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map(device => {
                      const online  = isDeviceOnline(device);
                      const rt      = realtimeMap[device.id];
                      const alerts  = hasAlerts(device);
                      const fw      = device.firewallGrade;
                      const diskPct = device.storage?.length
                        ? Math.round((device.storage.reduce((a, d) => a + d.usedGB, 0) /
                                       Math.max(device.storage.reduce((a, d) => a + d.totalGB, 0), 1)) * 100)
                        : null;
                      const displayName = device.nickname || device.name || device.id;

                      return (
                        <tr
                          key={device.id}
                          onClick={() => navigate(`/device/${device.id}`)}
                          style={{
                            ...s.tr,
                            background: alerts ? "rgba(220,38,38,0.05)" : undefined,
                            cursor: "pointer",
                          }}
                        >
                          {/* Device name */}
                          <td style={s.td}>
                            {editingDevice === device.id ? (
                              <NicknameEditor deviceId={device.id} />
                            ) : (
                              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <span style={{ ...s.statusDot, background: online ? "#56d364" : "#6e7681" }} />
                                <span style={{ color: "#e2e8f0", fontWeight: 500 }}>{displayName}</span>
                                <button
                                  onClick={e => {
                                    e.stopPropagation();
                                    setNicknameInput(device.nickname || "");
                                    setEditingDevice(device.id);
                                  }}
                                  style={s.pencilBtnSm}
                                >
                                  ✏️
                                </button>
                              </div>
                            )}
                          </td>
                          {/* Status */}
                          <td style={s.td}>
                            {online ? (
                              <span style={{ color: "#56d364", fontSize: 12 }}>🟢 {t("devices.live")}</span>
                            ) : (
                              <span style={{ color: "#8b949e", fontSize: 12 }}>
                                ⚫ {formatAgo(device.last_seen, t) || t("devices.offline")}
                              </span>
                            )}
                          </td>
                          {/* CPU */}
                          <td style={{ ...s.td, color: gaugeColor(rt?.cpu_percent) }}>
                            {rt?.cpu_percent != null ? `${Math.round(rt.cpu_percent)}%` : "—"}
                          </td>
                          {/* RAM */}
                          <td style={{ ...s.td, color: gaugeColor(rt?.ram_percent) }}>
                            {rt?.ram_percent != null ? `${Math.round(rt.ram_percent)}%` : "—"}
                          </td>
                          {/* Disk */}
                          <td style={{ ...s.td, color: gaugeColor(diskPct) }}>
                            {diskPct != null ? `${diskPct}%` : "—"}
                          </td>
                          {/* Health bar */}
                          <td style={{ ...s.td, minWidth: 120 }}>
                            <HealthBar score={device.healthScore ?? null} />
                          </td>
                          {/* Security grade */}
                          <td style={s.td}>
                            {fw ? (
                              <span style={{
                                ...s.gradePill,
                                color:       fw === "A" ? "#56d364" : fw === "F" ? "#fc8181" : "#f6ad55",
                                borderColor: fw === "A" ? "#238636" : fw === "F" ? "#742a2a" : "#7d4f00",
                                background:  fw === "A" ? "#0d2818" : fw === "F" ? "#2d1b1b" : "#2d2008",
                              }}>
                                {fw}
                              </span>
                            ) : (
                              <span style={{ color: "#4a5568" }}>—</span>
                            )}
                            {(device.threatCount || 0) > 0 && (
                              <span style={{ color: "#fc8181", fontSize: 11, marginLeft: 6 }}>
                                ⚠️ {device.threatCount}
                              </span>
                            )}
                          </td>
                          {/* Actions */}
                          <td style={s.td} onClick={e => e.stopPropagation()}>
                            <button
                              onClick={() => navigate(`/device/${device.id}`)}
                              style={s.viewBtnSm}
                            >
                              {t("devices.viewDetails")}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </main>

      {/* Update modal */}
      {updateModal && latestVersion && (
        <UpdateModal
          device={updateModal}
          latestVersion={latestVersion}
          onClose={() => setUpdateModal(null)}
          t={t}
        />
      )}
    </div>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const s = {
  page:     { minHeight: "100vh", background: "#0d1117", color: "#e2e8f0" },
  centered: { minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" },

  header: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "14px 28px", background: "#161b22", borderBottom: "1px solid #21262d",
    position: "sticky", top: 0, zIndex: 10,
  },
  headerLeft:  { display: "flex", alignItems: "center", gap: 10 },
  headerTitle: { fontWeight: 700, fontSize: 16, color: "#e2e8f0" },
  headerRight: { display: "flex", alignItems: "center", gap: 8 },
  ghostBtn: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 6, padding: "5px 12px", cursor: "pointer", fontSize: 13,
  },
  ghostBtnSm: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 5, padding: "3px 7px", cursor: "pointer", fontSize: 11,
  },

  main: { maxWidth: 1200, margin: "0 auto", padding: "28px 24px" },

  pageHeader: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    marginBottom: 20,
  },
  pageTitle: { fontSize: 22, fontWeight: 700, color: "#c9d1d9", margin: 0 },
  modeToggle: { display: "flex", gap: 4 },
  modeBtn: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 6, padding: "6px 14px", cursor: "pointer", fontSize: 13,
  },
  modeBtnActive: { border: "1px solid #58a6ff", color: "#58a6ff", background: "rgba(88,166,255,0.08)" },

  // Empty state
  emptyState: {
    display: "flex", flexDirection: "column", alignItems: "center",
    padding: "80px 24px", textAlign: "center",
  },
  addDeviceBtn: {
    background: "#238636", color: "#fff", border: "none",
    borderRadius: 8, padding: "12px 28px", cursor: "pointer",
    fontSize: 15, fontWeight: 600,
  },

  // Summary tiles
  summaryRow: {
    display: "grid", gridTemplateColumns: "repeat(4, 1fr)",
    gap: 14, marginBottom: 20,
  },
  summaryTile: {
    background: "#161b22", border: "1px solid #21262d",
    borderRadius: 12, padding: "16px 20px",
    display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
  },
  tileValue: { fontSize: 26, fontWeight: 800, margin: 0 },
  tileLabel: { fontSize: 11, color: "#8b949e", margin: 0, textTransform: "uppercase", letterSpacing: 0.8 },

  // Filter bar
  filterBar: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    gap: 12, marginBottom: 16, flexWrap: "wrap",
  },
  filterBtns: { display: "flex", gap: 4 },
  filterBtn: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 20, padding: "5px 14px", cursor: "pointer", fontSize: 12,
  },
  filterBtnActive: { border: "1px solid #58a6ff", color: "#58a6ff", background: "rgba(88,166,255,0.08)" },
  searchInput: {
    background: "#21262d", border: "1px solid #30363d", color: "#e2e8f0",
    borderRadius: 8, padding: "7px 14px", fontSize: 13, outline: "none",
    minWidth: 200,
  },

  // Grid
  gridContainer: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
    gap: 16,
  },
  deviceCard: {
    background: "#161b22", border: "1px solid",
    borderRadius: 14, padding: "18px 20px",
    display: "flex", flexDirection: "column", gap: 10,
    transition: "border-color 0.2s ease",
  },
  cardHeader: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
  },
  statusDot: { width: 8, height: 8, borderRadius: "50%", flexShrink: 0 },
  deviceName: { color: "#e2e8f0", fontWeight: 700, fontSize: 15, margin: 0,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  deviceSub:  { color: "#8b949e", fontSize: 11, margin: "2px 0 0" },
  pencilBtn:  { background: "transparent", border: "none", cursor: "pointer", fontSize: 14, flexShrink: 0 },
  pencilBtnSm: { background: "transparent", border: "none", cursor: "pointer", fontSize: 12, padding: "0 2px" },
  lastSeen:   { fontSize: 12, margin: 0 },

  miniGaugeRow: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 4 },
  miniGaugeWrap: { display: "flex", flexDirection: "column", alignItems: "center", gap: 3 },
  miniGaugeLabel: { fontSize: 9, color: "#8b949e", textTransform: "uppercase", letterSpacing: 0.5 },

  cardSection: { display: "flex", alignItems: "center", justifyContent: "space-between" },

  gradePill: {
    fontSize: 11, fontWeight: 700, padding: "2px 8px",
    borderRadius: 10, border: "1px solid",
  },

  viewBtn: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 7, padding: "7px 0", cursor: "pointer", fontSize: 13,
    width: "100%", marginTop: 4,
  },
  viewBtnSm: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 6, padding: "4px 10px", cursor: "pointer", fontSize: 12,
    whiteSpace: "nowrap",
  },

  // Table
  tableWrapper: { overflowX: "auto" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 13 },
  th: {
    padding: "10px 14px", textAlign: "left", fontSize: 11, fontWeight: 600,
    color: "#8b949e", textTransform: "uppercase", letterSpacing: 0.5,
    borderBottom: "1px solid #21262d", whiteSpace: "nowrap",
    userSelect: "none",
  },
  tr: {
    borderBottom: "1px solid #21262d",
    transition: "background 0.15s ease",
  },
  td: { padding: "10px 14px", color: "#c9d1d9", verticalAlign: "middle" },

  // Nickname editor (shared)
  nicknameInput: {
    background: "#21262d", border: "1px solid #58a6ff", borderRadius: 6,
    color: "#e2e8f0", fontSize: 13, padding: "4px 10px", outline: "none",
    maxWidth: 160,
  },
  nicknameSave: {
    background: "#238636", color: "#fff", border: "none",
    borderRadius: 6, padding: "4px 10px", cursor: "pointer", fontSize: 12,
    whiteSpace: "nowrap",
  },
};
