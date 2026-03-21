import React, { useEffect, useState, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { signOut } from "firebase/auth";
import { doc, getDoc, onSnapshot } from "firebase/firestore";
import { auth, db } from "../firebase";

// ── Circular SVG Gauge ────────────────────────────────────────────────────────

function CircularGauge({ value, max = 100, label, sublabel, color, size = 136 }) {
  const cx = size / 2;
  const cy = size / 2;
  const r  = size * 0.37;
  const strokeW    = size * 0.08;
  const circumference = 2 * Math.PI * r;
  const pct    = value != null ? Math.min(Math.max(value / max, 0), 1) : 0;
  const offset = circumference * (1 - pct);

  return (
    <div style={g.wrap}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Track */}
        <circle cx={cx} cy={cy} r={r} fill="none"
          stroke="#21262d" strokeWidth={strokeW} />
        {/* Progress */}
        {value != null && (
          <circle cx={cx} cy={cy} r={r} fill="none"
            stroke={color} strokeWidth={strokeW}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform={`rotate(-90 ${cx} ${cy})`}
            style={{ transition: "stroke-dashoffset 0.7s cubic-bezier(0.4,0,0.2,1)" }}
          />
        )}
        {/* Value */}
        <text x={cx} y={sublabel ? cy - 4 : cy + 6}
          textAnchor="middle" fill="#e2e8f0"
          fontSize={size * 0.155} fontWeight="700" fontFamily="system-ui, sans-serif">
          {value != null ? `${Math.round(value)}${max === 100 ? "%" : ""}` : "—"}
        </text>
        {/* Sublabel inside gauge */}
        {sublabel && (
          <text x={cx} y={cy + size * 0.13}
            textAnchor="middle" fill="#8b949e"
            fontSize={size * 0.082} fontFamily="system-ui, sans-serif">
            {sublabel}
          </text>
        )}
      </svg>
      <p style={g.label}>{label}</p>
    </div>
  );
}

const g = {
  wrap:  { display: "flex", flexDirection: "column", alignItems: "center", gap: 6 },
  label: { fontSize: 12, color: "#8b949e", margin: 0, textAlign: "center",
           textTransform: "uppercase", letterSpacing: 1 },
};

// ── Helpers ────────────────────────────────────────────────────────────────────

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

function getDiskInfo(storage) {
  if (!Array.isArray(storage) || storage.length === 0) return null;
  const total = storage.reduce((s, d) => s + (d.totalGB || 0), 0);
  const used  = storage.reduce((s, d) => s + (d.usedGB  || 0), 0);
  return { used: Math.round(used), total: Math.round(total),
           pct: total > 0 ? (used / total) * 100 : 0 };
}

function useCountdown(lastScanAt, intervalSecs = 300) {
  const [ms, setMs] = useState(null);
  useEffect(() => {
    const tick = () => {
      if (!lastScanAt) { setMs(null); return; }
      const elapsed   = Date.now() - lastScanAt.getTime();
      const remaining = Math.max(0, intervalSecs * 1000 - elapsed);
      setMs(remaining);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [lastScanAt, intervalSecs]);
  return ms;
}

function formatCountdown(ms, t) {
  if (ms === null) return "—";
  if (ms === 0) return t("dashboard.scanning");
  const secs = Math.floor(ms / 1000);
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function formatAgo(ts, t) {
  if (!ts) return t("dashboard.neverScanned");
  const date = ts.toDate ? ts.toDate() : new Date(ts);
  const diff  = Math.floor((Date.now() - date.getTime()) / 1000);
  if (diff < 60)  return t("dashboard.justNow");
  if (diff < 3600) return t("dashboard.minutesAgo", { n: Math.floor(diff / 60) });
  if (diff < 86400) return t("dashboard.hoursAgo", { n: Math.floor(diff / 3600) });
  return date.toLocaleDateString();
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export default function Dashboard({ user }) {
  const { t, i18n } = useTranslation();
  const navigate    = useNavigate();
  const isRTL       = i18n.language === "he";

  const [realtimeData,  setRealtimeData]  = useState(null);
  const [agentConnected, setAgentConnected] = useState(false);
  const [latestScan,    setLatestScan]    = useState(null);
  const [agentStatus,   setAgentStatus]   = useState(null);
  const [loading,       setLoading]       = useState(true);

  const realtimeUnsubRef = useRef(null);
  const lastScanIdRef    = useRef(null);

  // Load scan by ID
  const loadScan = useCallback(async (scanId) => {
    if (!scanId || scanId === lastScanIdRef.current) return;
    lastScanIdRef.current = scanId;
    const snap = await getDoc(doc(db, "users", user.uid, "scans", scanId));
    if (snap.exists()) setLatestScan(snap.data());
  }, [user.uid]);

  // Agent status — always subscribed
  useEffect(() => {
    const unsub = onSnapshot(
      doc(db, "users", user.uid, "agent", "status"),
      (snap) => {
        if (snap.exists()) {
          const data = snap.data();
          setAgentStatus(data);
          const hb = data.lastHeartbeat?.toDate();
          setAgentConnected(hb && Date.now() - hb.getTime() < 90_000);
          if (data.lastScanId) loadScan(data.lastScanId);
        }
        setLoading(false);
      },
      () => setLoading(false),
    );
    return () => unsub();
  }, [user.uid, loadScan]);

  // Realtime heartbeat — visibility-aware
  const subscribeRealtime = useCallback(() => {
    if (realtimeUnsubRef.current || document.hidden) return;
    realtimeUnsubRef.current = onSnapshot(
      doc(db, "users", user.uid, "realtime", "status"),
      (snap) => { if (snap.exists()) setRealtimeData(snap.data()); },
    );
  }, [user.uid]);

  const unsubscribeRealtime = useCallback(() => {
    realtimeUnsubRef.current?.();
    realtimeUnsubRef.current = null;
  }, []);

  useEffect(() => {
    subscribeRealtime();
    const onVisibility = () =>
      document.hidden ? unsubscribeRealtime() : subscribeRealtime();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      unsubscribeRealtime();
    };
  }, [subscribeRealtime, unsubscribeRealtime]);

  // Derived values
  const cpuPct     = realtimeData?.cpu_percent ?? null;
  const ramPct     = realtimeData?.ram_percent ?? null;
  const ramUsedGB  = realtimeData?.ram_used_gb;
  const ramTotalGB = realtimeData?.ram_total_gb;
  const disk       = getDiskInfo(latestScan?.storage);
  const health     = latestScan?.healthScore ?? agentStatus?.healthScore ?? null;
  const vulnCount  = Array.isArray(latestScan?.vulnerabilities) ? latestScan.vulnerabilities.length : null;
  const topProcs   = realtimeData?.top_processes ?? [];
  const temps      = realtimeData?.temperatures  ?? [];
  const isLive     = realtimeData?.updatedAt &&
    (Date.now() - (realtimeData.updatedAt.toDate?.()?.getTime?.() ?? 0)) < 30_000;
  const lastScanAt = agentStatus?.lastScanAt?.toDate?.() ?? null;
  const countdown  = useCountdown(lastScanAt, 300);

  const toggleLang = () => {
    const l = i18n.language === "en" ? "he" : "en";
    i18n.changeLanguage(l);
    localStorage.setItem("lang", l);
  };

  if (loading) {
    return (
      <div style={s.centered}>
        <p style={{ color: "#a0aec0" }}>{t("common.loading")}</p>
      </div>
    );
  }

  return (
    <div dir={isRTL ? "rtl" : "ltr"} style={s.page}>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <header style={s.header}>
        <div style={s.headerLeft}>
          <span style={{ fontSize: 22 }}>🛡️</span>
          <span style={s.headerTitle}>{t("app.title")}</span>
        </div>
        <div style={s.headerRight}>
          {isLive && (
            <span style={s.liveBadge}>
              <span style={s.liveDot} />
              {t("dashboard.live")}
            </span>
          )}
          <button onClick={toggleLang} style={s.ghostBtn}>
            {i18n.language === "en" ? "עברית" : "English"}
          </button>
          <button onClick={() => navigate("/report")} style={s.ghostBtn}>
            {t("nav.reports")}
          </button>
          <button onClick={() => signOut(auth).then(() => navigate("/login"))} style={s.ghostBtn}>
            {t("nav.logout")}
          </button>
        </div>
      </header>

      <main style={s.main}>
        <h2 style={s.welcome}>
          {t("dashboard.welcome", { name: user.displayName?.split(" ")[0] })}
        </h2>

        {/* ── Agent status banner ──────────────────────────────────────────── */}
        <div style={{
          ...s.agentBanner,
          background:   agentConnected ? "#0d2818" : "#2d1b1b",
          borderColor:  agentConnected ? "#238636" : "#742a2a",
        }}>
          <span style={{ fontSize: 18 }}>{agentConnected ? "🟢" : "🔴"}</span>
          <div style={{ flex: 1 }}>
            <p style={s.agentTitle}>
              {agentConnected ? t("dashboard.agentConnected") : t("dashboard.agentDisconnected")}
            </p>
            {agentConnected && agentStatus?.hostname && (
              <p style={s.agentSub}>{agentStatus.hostname}</p>
            )}
            {!agentConnected && (
              <p style={s.agentSub}>{t("dashboard.agentInstructions")}</p>
            )}
          </div>
          {!agentConnected && (
            <button onClick={() => navigate("/setup")} style={s.setupBtn}>
              {t("setup.setupAgent")}
            </button>
          )}
        </div>

        {/* ── ROW 1: Gauges ───────────────────────────────────────────────── */}
        <div style={s.gaugeRow}>
          <div style={s.gaugeCard}>
            <CircularGauge
              value={cpuPct}
              label={t("dashboard.cpu")}
              color={gaugeColor(cpuPct)}
            />
          </div>
          <div style={s.gaugeCard}>
            <CircularGauge
              value={ramPct}
              label={t("dashboard.ram")}
              sublabel={ramUsedGB != null ? `${ramUsedGB} / ${ramTotalGB} GB` : undefined}
              color={gaugeColor(ramPct)}
            />
          </div>
          <div style={s.gaugeCard}>
            <CircularGauge
              value={disk?.pct ?? null}
              label={t("dashboard.disk")}
              sublabel={disk ? `${disk.used} / ${disk.total} GB` : undefined}
              color={gaugeColor(disk?.pct)}
            />
          </div>
          <div style={s.gaugeCard}>
            <CircularGauge
              value={health}
              label={t("dashboard.healthScore")}
              color={healthColor(health)}
            />
          </div>
        </div>

        {/* ── ROW 2: Info cards ────────────────────────────────────────────── */}
        <div style={s.cardRow}>

          {/* Top Processes */}
          <div style={s.infoCard}>
            <p style={s.cardTitle}>{t("dashboard.topProcesses")}</p>
            {topProcs.length === 0 ? (
              <p style={s.muted}>{t("dashboard.noAgentData")}</p>
            ) : (
              <table style={s.procTable}>
                <thead>
                  <tr>
                    <th style={s.th}>{t("dashboard.process")}</th>
                    <th style={{ ...s.th, textAlign: "right" }}>{t("dashboard.cpu")}</th>
                    <th style={{ ...s.th, textAlign: "right" }}>MB</th>
                  </tr>
                </thead>
                <tbody>
                  {topProcs.map((p, i) => (
                    <tr key={i}>
                      <td style={s.td}>{p.name?.replace(".exe", "")}</td>
                      <td style={{ ...s.td, textAlign: "right", color: gaugeColor(p.cpu) }}>
                        {p.cpu}%
                      </td>
                      <td style={{ ...s.td, textAlign: "right", color: "#8b949e" }}>
                        {p.ram_mb}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Temperature */}
          <div style={s.infoCard}>
            <p style={s.cardTitle}>{t("dashboard.temperature")}</p>
            {temps.length === 0 ? (
              <p style={s.muted}>{realtimeData ? t("dashboard.tempNA") : t("dashboard.noAgentData")}</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {temps.map((temp, i) => {
                  const hot = temp.current >= 80;
                  const warm = temp.current >= 65;
                  const color = hot ? "#fc8181" : warm ? "#ed8936" : "#48bb78";
                  return (
                    <div key={i} style={s.tempRow}>
                      <span style={s.tempLabel}>{temp.label}</span>
                      <span style={{ ...s.tempVal, color }}>{temp.current}°C</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Security */}
          <div style={s.infoCard}>
            <p style={s.cardTitle}>{t("dashboard.sections.security")}</p>
            {vulnCount === null ? (
              <p style={s.muted}>{t("dashboard.noAgentData")}</p>
            ) : vulnCount === 0 ? (
              <p style={{ ...s.bigVal, color: "#48bb78" }}>{t("dashboard.allClear")}</p>
            ) : (
              <>
                <p style={{ ...s.bigVal, color: "#fc8181" }}>
                  {t("dashboard.issues", { count: vulnCount })}
                </p>
                <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 8 }}>
                  {(latestScan?.vulnerabilities ?? []).slice(0, 3).map((v, i) => (
                    <p key={i} style={s.vulnItem}>
                      {v.severity === "critical" ? "🔴" : v.severity === "high" ? "🟠" : "🟡"}
                      {" "}{v.description}
                    </p>
                  ))}
                </div>
              </>
            )}
          </div>

          {/* Last scan + countdown */}
          <div style={s.infoCard}>
            <p style={s.cardTitle}>{t("dashboard.lastScan")}</p>
            <p style={s.bigVal}>
              {agentStatus?.lastScanAt ? formatAgo(agentStatus.lastScanAt, t) : t("dashboard.neverScanned")}
            </p>
            {countdown !== null && (
              <div style={s.countdownBox}>
                <p style={s.muted}>{t("dashboard.nextScan")}</p>
                <p style={{ ...s.bigVal, fontSize: 20, color: "#58a6ff" }}>
                  {formatCountdown(countdown, t)}
                </p>
              </div>
            )}
            <button
              onClick={() => navigate("/report")}
              style={{ ...s.setupBtn, marginTop: 16, width: "100%" }}
              disabled={!latestScan}
            >
              {t("dashboard.viewReport")}
            </button>
          </div>

        </div>
      </main>
    </div>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const s = {
  page:    { minHeight: "100vh", background: "#0d1117", color: "#e2e8f0" },
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
  liveBadge: {
    display: "flex", alignItems: "center", gap: 6,
    background: "#0d2818", border: "1px solid #238636",
    borderRadius: 20, padding: "3px 10px",
    fontSize: 12, fontWeight: 600, color: "#56d364",
  },
  liveDot: {
    width: 7, height: 7, borderRadius: "50%", background: "#56d364",
    animation: "pulse 1.5s infinite",
    boxShadow: "0 0 0 0 rgba(86,211,100,0.6)",
  },

  main:    { maxWidth: 1100, margin: "0 auto", padding: "32px 24px" },
  welcome: { fontSize: 22, fontWeight: 700, marginBottom: 20, color: "#c9d1d9" },

  agentBanner: {
    display: "flex", alignItems: "center", gap: 14,
    padding: "14px 18px", borderRadius: 10, border: "1px solid",
    marginBottom: 28,
  },
  agentTitle: { fontWeight: 600, color: "#e2e8f0", margin: 0, fontSize: 14 },
  agentSub:   { color: "#8b949e", fontSize: 12, margin: "3px 0 0" },
  setupBtn: {
    background: "#238636", color: "#fff", border: "none",
    borderRadius: 6, padding: "8px 16px", cursor: "pointer",
    fontSize: 13, fontWeight: 600, whiteSpace: "nowrap",
  },

  // Gauge row
  gaugeRow: {
    display: "grid",
    gridTemplateColumns: "repeat(4, 1fr)",
    gap: 16, marginBottom: 16,
  },
  gaugeCard: {
    background: "#161b22", border: "1px solid #21262d",
    borderRadius: 14, padding: "24px 16px",
    display: "flex", alignItems: "center", justifyContent: "center",
  },

  // Info card row
  cardRow: {
    display: "grid",
    gridTemplateColumns: "repeat(4, 1fr)",
    gap: 16,
  },
  infoCard: {
    background: "#161b22", border: "1px solid #21262d",
    borderRadius: 14, padding: "20px",
  },
  cardTitle: {
    fontSize: 11, fontWeight: 600, color: "#8b949e", margin: "0 0 14px",
    textTransform: "uppercase", letterSpacing: 1,
  },
  bigVal: { fontSize: 17, fontWeight: 700, color: "#e2e8f0", margin: "0 0 4px" },
  muted:  { fontSize: 13, color: "#4a5568", margin: 0 },

  // Process table
  procTable: { width: "100%", borderCollapse: "collapse" },
  th: { fontSize: 10, color: "#4a5568", fontWeight: 500, padding: "0 0 6px",
        textAlign: "left", textTransform: "uppercase", letterSpacing: 0.5 },
  td: { fontSize: 12, color: "#c9d1d9", padding: "4px 0",
        whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
        maxWidth: 100 },

  // Temperature
  tempRow:  { display: "flex", justifyContent: "space-between", alignItems: "center" },
  tempLabel: { fontSize: 12, color: "#8b949e" },
  tempVal:   { fontSize: 14, fontWeight: 700 },

  // Vuln
  vulnItem: { fontSize: 11, color: "#8b949e", margin: 0, lineHeight: 1.4 },

  // Countdown
  countdownBox: { marginTop: 12, paddingTop: 12, borderTop: "1px solid #21262d" },
};
