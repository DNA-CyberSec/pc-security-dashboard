import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { httpsCallable } from "firebase/functions";
import { functions } from "../firebase";

// ── Styles ────────────────────────────────────────────────────────────────────

const s = {
  page:     { minHeight: "100vh", background: "#0d1117", color: "#e2e8f0", padding: "32px 24px", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" },
  header:   { display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 32 },
  title:    { fontSize: 22, fontWeight: 700, color: "#f0f6fc", margin: 0 },
  back:     { fontSize: 14, color: "#58a6ff", background: "none", border: "none", cursor: "pointer", padding: "8px 0" },
  grid:     { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: 20 },
  card:     { background: "#161b22", border: "1px solid #30363d", borderRadius: 10, padding: 24 },
  cardTitle:{ fontSize: 13, fontWeight: 600, color: "#8b949e", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 16 },
  stat:     { fontSize: 36, fontWeight: 700, color: "#f0f6fc", lineHeight: 1 },
  sub:      { fontSize: 13, color: "#8b949e", marginTop: 4 },
  barWrap:  { background: "#21262d", borderRadius: 4, height: 8, marginTop: 12 },
  barFill:  (pct, warn) => ({ height: "100%", borderRadius: 4, width: `${Math.min(pct, 100)}%`, background: pct >= 90 ? "#f85149" : pct >= 70 ? "#d29922" : warn ? "#d29922" : "#3fb950", transition: "width 0.3s" }),
  row:      { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 },
  label:    { fontSize: 14, color: "#c9d1d9" },
  toggle:   (on) => ({ position: "relative", width: 44, height: 24, background: on ? "#f85149" : "#21262d", border: `1px solid ${on ? "#f85149" : "#30363d"}`, borderRadius: 12, cursor: "pointer", transition: "background 0.2s", flexShrink: 0 }),
  knob:     (on) => ({ position: "absolute", top: 2, left: on ? 22 : 2, width: 18, height: 18, borderRadius: "50%", background: "#f0f6fc", transition: "left 0.2s" }),
  badge:    (color) => ({ display: "inline-block", padding: "2px 10px", borderRadius: 12, fontSize: 12, fontWeight: 600, background: `${color}22`, color, border: `1px solid ${color}44` }),
  warn:     { background: "#161b22", border: "1px solid #f85149", borderRadius: 10, padding: "12px 18px", marginBottom: 20, fontSize: 13, color: "#f85149" },
  refresh:  { fontSize: 12, color: "#8b949e", marginTop: 4 },
  loading:  { color: "#8b949e", padding: 60, textAlign: "center" },
  denied:   { color: "#f85149", padding: 60, textAlign: "center" },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function ProgressBar({ value, limit, warn = false }) {
  const pct = limit > 0 ? Math.round((value / limit) * 100) : 0;
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, color: "#8b949e", marginBottom: 4 }}>
        <span>{value.toLocaleString()} / {limit.toLocaleString()}</span>
        <span style={{ color: pct >= 90 ? "#f85149" : pct >= 70 ? "#d29922" : "#3fb950" }}>{pct}%</span>
      </div>
      <div style={s.barWrap}><div style={s.barFill(pct, warn)} /></div>
    </div>
  );
}

function Toggle({ on, onChange, loading }) {
  return (
    <button style={s.toggle(on)} onClick={() => !loading && onChange(!on)} disabled={loading} title={on ? "Click to disable" : "Click to enable"}>
      <div style={s.knob(on)} />
    </button>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function Admin({ user }) {
  const navigate  = useNavigate();
  const [data,    setData]    = useState(null);
  const [error,   setError]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState({});
  const [lastRefresh, setLastRefresh] = useState(null);

  const getAdminStats    = httpsCallable(functions, "getAdminStats");
  const setAdminOverride = httpsCallable(functions, "setAdminOverride");

  const fetchStats = useCallback(async () => {
    try {
      const result = await getAdminStats();
      setData(result.data);
      setLastRefresh(new Date());
      setError(null);
    } catch (e) {
      setError(e.message || "Access denied");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    fetchStats();
    const interval = setInterval(fetchStats, 30_000);
    return () => clearInterval(interval);
  }, [user, fetchStats]);

  const toggle = async (field, value) => {
    setToggling(t => ({ ...t, [field]: true }));
    try {
      await setAdminOverride({ [field]: value });
      setData(prev => ({
        ...prev,
        status: { ...prev.status, [field]: value },
      }));
    } catch (e) {
      alert(`Failed: ${e.message}`);
    } finally {
      setToggling(t => ({ ...t, [field]: false }));
    }
  };

  if (!user) return <div style={s.loading}>Loading…</div>;
  if (loading) return <div style={s.loading}>Loading admin data…</div>;
  if (error)   return (
    <div style={s.page}>
      <div style={s.denied}>⛔ {error}</div>
      <p style={{ color: "#8b949e", fontSize: 13 }}>
        To gain access, add your Firebase UID to{" "}
        <code style={{ color: "#58a6ff" }}>/config/system → adminUids</code>{" "}
        in the Firebase console.
      </p>
    </div>
  );

  const { usage = {}, status = {}, limits = {} } = data;
  const claudeCalls  = usage.claude_calls_this_month ?? 0;
  const claudeLimit  = limits.claude_monthly_limit   ?? 500;
  const writesToday  = usage.firestore_writes_today  ?? 0;
  const writeLimit   = limits.daily_write_limit      ?? 15_000;
  const monthKey     = usage.month      ?? "—";
  const dateKey      = usage.writes_date ?? "—";

  const heartbeatPaused = Boolean(status.heartbeat_paused);
  const aiDisabled      = Boolean(status.ai_disabled);
  const anyAlert        = heartbeatPaused || aiDisabled || claudeCalls >= claudeLimit || writesToday >= writeLimit;

  return (
    <div style={s.page}>
      {/* Header */}
      <div style={s.header}>
        <div>
          <h1 style={s.title}>🛡 Admin Dashboard</h1>
          <div style={s.refresh}>
            {lastRefresh ? `Last updated ${lastRefresh.toLocaleTimeString()} · auto-refreshes every 30s` : ""}
          </div>
        </div>
        <button style={s.back} onClick={() => navigate("/dashboard")}>← Dashboard</button>
      </div>

      {anyAlert && (
        <div style={s.warn}>
          ⚠ Active alert:{" "}
          {heartbeatPaused && <span>Agent heartbeats are <b>paused</b>. </span>}
          {aiDisabled      && <span>AI features are <b>disabled</b>. </span>}
          {!heartbeatPaused && !aiDisabled && writesToday >= writeLimit && <span>Daily write limit reached — heartbeats auto-paused. </span>}
          {!heartbeatPaused && !aiDisabled && claudeCalls >= claudeLimit && <span>Monthly Claude limit reached — AI disabled. </span>}
        </div>
      )}

      <div style={s.grid}>

        {/* Claude API usage */}
        <div style={s.card}>
          <div style={s.cardTitle}>Claude API · {monthKey}</div>
          <div style={s.stat}>{claudeCalls.toLocaleString()}</div>
          <div style={s.sub}>calls this month</div>
          <div style={{ marginTop: 16 }}>
            <ProgressBar value={claudeCalls} limit={claudeLimit} />
          </div>
          <div style={{ marginTop: 16, display: "flex", justifyContent: "space-between", fontSize: 13, color: "#8b949e" }}>
            <span>Remaining</span>
            <span style={{ color: "#f0f6fc", fontWeight: 600 }}>
              {Math.max(0, claudeLimit - claudeCalls).toLocaleString()} calls
            </span>
          </div>
        </div>

        {/* Firestore writes */}
        <div style={s.card}>
          <div style={s.cardTitle}>Firestore Writes · {dateKey}</div>
          <div style={s.stat}>{writesToday.toLocaleString()}</div>
          <div style={s.sub}>estimated writes today</div>
          <div style={{ marginTop: 16 }}>
            <ProgressBar value={writesToday} limit={writeLimit} warn />
          </div>
          <div style={{ marginTop: 16, display: "flex", justifyContent: "space-between", fontSize: 13, color: "#8b949e" }}>
            <span>Remaining</span>
            <span style={{ color: "#f0f6fc", fontWeight: 600 }}>
              {Math.max(0, writeLimit - writesToday).toLocaleString()} writes
            </span>
          </div>
          <div style={{ marginTop: 8, fontSize: 12, color: "#8b949e" }}>
            ~4 writes per realtime heartbeat · max 1/8s per device
          </div>
        </div>

        {/* System controls */}
        <div style={s.card}>
          <div style={s.cardTitle}>System Controls</div>

          <div style={s.row}>
            <div>
              <div style={s.label}>Agent Heartbeats</div>
              <div style={{ fontSize: 12, color: "#8b949e", marginTop: 2 }}>
                {heartbeatPaused
                  ? `Paused${status.paused_reason ? ` (${status.paused_reason})` : ""}`
                  : "Running normally"}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={s.badge(heartbeatPaused ? "#f85149" : "#3fb950")}>
                {heartbeatPaused ? "PAUSED" : "ACTIVE"}
              </span>
              <Toggle
                on={heartbeatPaused}
                onChange={v => toggle("heartbeat_paused", v)}
                loading={toggling.heartbeat_paused}
              />
            </div>
          </div>

          <div style={{ borderTop: "1px solid #21262d", margin: "12px 0" }} />

          <div style={s.row}>
            <div>
              <div style={s.label}>AI Features (Claude)</div>
              <div style={{ fontSize: 12, color: "#8b949e", marginTop: 2 }}>
                {aiDisabled ? "Disabled by admin" : "Enabled"}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={s.badge(aiDisabled ? "#f85149" : "#3fb950")}>
                {aiDisabled ? "OFF" : "ON"}
              </span>
              <Toggle
                on={aiDisabled}
                onChange={v => toggle("ai_disabled", v)}
                loading={toggling.ai_disabled}
              />
            </div>
          </div>

          <div style={{ borderTop: "1px solid #21262d", margin: "12px 0" }} />

          <div style={{ fontSize: 12, color: "#8b949e", lineHeight: 1.6 }}>
            Toggling <b>Pause Heartbeats</b> stops all agent write traffic instantly.
            Agents will retry every 5 min for up to 1 hour, then re-check hourly.
            <br /><br />
            Toggling <b>AI Off</b> blocks all new Claude API calls. Cached
            recommendations are still shown.
          </div>
        </div>

        {/* Spending caps info */}
        <div style={s.card}>
          <div style={s.cardTitle}>Automatic Spending Caps</div>
          <div style={{ fontSize: 13, color: "#c9d1d9", lineHeight: 1.7 }}>
            <div style={{ marginBottom: 12 }}>
              <span style={{ color: "#58a6ff", fontWeight: 600 }}>Claude API</span>
              <br />
              At <b>{claudeLimit} calls/month</b> → AI features auto-disabled.
              Resets on the 1st of each month.
            </div>
            <div>
              <span style={{ color: "#58a6ff", fontWeight: 600 }}>Firestore Writes</span>
              <br />
              At <b>{writeLimit.toLocaleString()} writes/day</b> → agent heartbeats
              auto-paused. Resets at midnight UTC.
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
