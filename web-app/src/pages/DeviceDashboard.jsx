import React, { useEffect, useState, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useParams } from "react-router-dom";
import { signOut } from "firebase/auth";
import { collection, doc, getDoc, onSnapshot, setDoc } from "firebase/firestore";
import { httpsCallable } from "firebase/functions";
import { auth, db, functions } from "../firebase";
import { useResponsive } from "../hooks/useResponsive";

// ── Circular SVG Gauge ────────────────────────────────────────────────────────

function CircularGauge({ value, max = 100, label, sublabel, color, size = 136 }) {
  const cx = size / 2, cy = size / 2, r = size * 0.37;
  const strokeW       = size * 0.08;
  const circumference = 2 * Math.PI * r;
  const pct    = value != null ? Math.min(Math.max(value / max, 0), 1) : 0;
  const offset = circumference * (1 - pct);

  return (
    <div style={g.wrap}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#21262d" strokeWidth={strokeW} />
        {value != null && (
          <circle cx={cx} cy={cy} r={r} fill="none"
            stroke={color} strokeWidth={strokeW}
            strokeDasharray={circumference} strokeDashoffset={offset}
            strokeLinecap="round"
            transform={`rotate(-90 ${cx} ${cy})`}
            style={{ transition: "stroke-dashoffset 0.7s cubic-bezier(0.4,0,0.2,1)" }}
          />
        )}
        <text x={cx} y={sublabel ? cy - 4 : cy + 6}
          textAnchor="middle" fill="#e2e8f0"
          fontSize={size * 0.155} fontWeight="700" fontFamily="system-ui, sans-serif">
          {value != null ? `${Math.round(value)}${max === 100 ? "%" : ""}` : "—"}
        </text>
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
  if (diff < 60)   return t("dashboard.justNow");
  if (diff < 3600) return t("dashboard.minutesAgo", { n: Math.floor(diff / 60) });
  if (diff < 86400) return t("dashboard.hoursAgo",  { n: Math.floor(diff / 3600) });
  return date.toLocaleDateString();
}

// ── Mac Security Tab ──────────────────────────────────────────────────────────

function MacSecurityTab({ scan }) {
  if (!scan) {
    return (
      <div style={{ padding: "40px 0", textAlign: "center", color: "#4a5568" }}>
        No scan data yet. The agent will send a full scan within 5 minutes.
      </div>
    );
  }

  const fv       = scan.filevault    || {};
  const gk       = scan.gatekeeper   || {};
  const sip      = scan.sip          || {};
  const fw       = scan.macFirewall  || {};
  const admins   = scan.adminUsers   || [];
  const installs = scan.recentInstalls || [];
  const sshFails = scan.sshFailedLogins || {};

  const SecurityRow = ({ label, enabled, goodLabel, badLabel, desc }) => (
    <div style={{
      padding: "14px 16px", borderRadius: 8, marginBottom: 10,
      background: enabled ? "#0a1f13" : "#1e1010",
      border: `1px solid ${enabled ? "#238636" : "#742a2a"}`,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontWeight: 700, fontSize: 14, color: enabled ? "#56d364" : "#fc8181" }}>
          {enabled ? "🔒" : "⚠️"} {label}
        </span>
        <span style={{
          fontSize: 12, fontWeight: 700, padding: "2px 10px", borderRadius: 10,
          background: enabled ? "#0d2818" : "#2d1b1b",
          color: enabled ? "#56d364" : "#fc8181",
          border: `1px solid ${enabled ? "#238636" : "#742a2a"}`,
        }}>
          {enabled ? (goodLabel || "ON") : (badLabel || "OFF")}
        </span>
      </div>
      {desc && (
        <p style={{ fontSize: 12, color: "#8b949e", margin: "6px 0 0", lineHeight: 1.5 }}>{desc}</p>
      )}
    </div>
  );

  return (
    <div className="rg-linux">

      {/* macOS Security Features */}
      <div style={s.infoCard}>
        <p style={s.cardTitle}>macOS Security</p>

        <SecurityRow
          label="FileVault"
          enabled={fv.enabled}
          goodLabel="ENCRYPTED"
          badLabel="UNENCRYPTED"
          desc={fv.enabled
            ? "Disk encryption is active. Your data is protected if the Mac is lost or stolen."
            : "FileVault is OFF. Enable it in System Settings → Privacy & Security → FileVault."}
        />
        <SecurityRow
          label="Gatekeeper"
          enabled={gk.enabled}
          goodLabel="ENABLED"
          badLabel="DISABLED"
          desc={gk.enabled
            ? "Only signed and notarised apps can run. Protects against malicious software."
            : "Gatekeeper is disabled — unsigned apps can run freely. Re-enable via: sudo spctl --master-enable"}
        />
        <SecurityRow
          label="System Integrity Protection (SIP)"
          enabled={sip.enabled}
          goodLabel="ENABLED"
          badLabel="DISABLED"
          desc={sip.enabled
            ? "SIP protects critical system files from modification, even by root."
            : "SIP is disabled. System files can be modified. Re-enable from macOS Recovery."}
        />
        <SecurityRow
          label="Application Firewall"
          enabled={fw.enabled}
          goodLabel="ENABLED"
          badLabel="DISABLED"
          desc={fw.enabled
            ? "Firewall is active — incoming connections to unsigned apps are blocked."
            : "Firewall is off. Enable in System Settings → Network → Firewall."}
        />
      </div>

      {/* Admin Users + SSH Attempts */}
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

        {/* Admin users */}
        <div style={s.infoCard}>
          <p style={s.cardTitle}>Admin Users</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
            {admins.length === 0 ? (
              <span style={s.muted}>—</span>
            ) : admins.map((u, i) => (
              <span key={i} style={{ fontSize: 11, background: "#0d2818", border: "1px solid #238636",
                                     color: "#56d364", borderRadius: 4, padding: "2px 8px" }}>
                {u}
              </span>
            ))}
          </div>
          {admins.length > 2 && (
            <p style={{ fontSize: 12, color: "#f6ad55", marginTop: 8 }}>
              ⚠️ {admins.length} admin accounts — consider reducing to one.
            </p>
          )}
        </div>

        {/* SSH failed logins */}
        <div style={s.infoCard}>
          <p style={s.cardTitle}>SSH Brute Force (24h)</p>
          <div style={{ display: "flex", gap: 24, marginBottom: 8 }}>
            <div>
              <p style={{ ...s.bigVal, color: sshFails.total > 50 ? "#fc8181" : sshFails.total > 10 ? "#f6ad55" : "#e2e8f0" }}>
                {sshFails.total ?? 0}
              </p>
              <p style={s.muted}>Failed logins</p>
            </div>
            <div>
              <p style={{ ...s.bigVal, color: "#f6ad55" }}>{sshFails.unique_ips ?? 0}</p>
              <p style={s.muted}>Unique IPs</p>
            </div>
          </div>
          {(sshFails.top_ips || []).slice(0, 5).map((item, i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between",
                                  padding: "4px 0", borderBottom: "1px solid #21262d" }}>
              <span style={{ fontFamily: "monospace", fontSize: 12, color: "#fc8181" }}>{item.ip}</span>
              <span style={{ fontSize: 11, color: "#8b949e" }}>×{item.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Installs — full width */}
      <div style={{ ...s.infoCard, gridColumn: "1 / -1" }}>
        <p style={s.cardTitle}>Recent Installs (last 7 days) · {installs.length} items</p>
        {installs.length === 0 ? (
          <p style={s.muted}>No software installed in the last 7 days.</p>
        ) : (
          <table style={s.procTable}>
            <thead>
              <tr>
                <th style={s.th}>Application</th>
                <th style={{ ...s.th, textAlign: "right" }}>Date</th>
              </tr>
            </thead>
            <tbody>
              {installs.map((item, i) => (
                <tr key={i}>
                  <td style={{ ...s.td, color: "#c9d1d9" }}>{item.name}</td>
                  <td style={{ ...s.td, textAlign: "right", color: "#8b949e", fontSize: 11 }}>{item.date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

    </div>
  );
}

// ── Linux Security Tab ────────────────────────────────────────────────────────

function LinuxSecurityTab({ scan, deviceId, commands, cmdLoading, sendCommand, t }) {
  const [blockInput, setBlockInput] = useState("");

  if (!scan) {
    return (
      <div style={{ padding: "40px 0", textAlign: "center", color: "#4a5568" }}>
        {t("linux.noScanData")}
      </div>
    );
  }

  const sshFails   = scan.sshFailedLogins  || {};
  const topIPs     = sshFails.top_ips      || [];
  const logins     = scan.recentLogins     || [];
  const sudoUsers  = scan.sudoUsers        || [];
  const suidFiles  = scan.suidSuspect      || [];
  const fw         = scan.firewallStatus   || {};

  const getCommandStatus = (type, ip = "") => {
    const match = commands.find(c =>
      c.type === type && (type === "block_ip" ? c.ip === ip : true) &&
      ["pending","in_progress","done"].includes(c.status)
    );
    return match?.status || null;
  };

  const isBlocked = (ip) => {
    const st = getCommandStatus("block_ip", ip);
    return st === "done";
  };

  const isPending = (ip) => {
    const st = getCommandStatus("block_ip", ip);
    return st === "pending" || st === "in_progress";
  };

  return (
    <div className="rg-linux">

      {/* Brute Force */}
      <div style={s.infoCard}>
        <p style={s.cardTitle}>{t("linux.bruteForce")}</p>
        <div style={{ display: "flex", gap: 24, marginBottom: 16 }}>
          <div>
            <p style={{ ...s.bigVal, color: sshFails.total > 50 ? "#fc8181" : sshFails.total > 10 ? "#f6ad55" : "#e2e8f0" }}>
              {sshFails.total ?? 0}
            </p>
            <p style={s.muted}>{t("linux.failedLogins")}</p>
          </div>
          <div>
            <p style={{ ...s.bigVal, color: "#f6ad55" }}>{sshFails.unique_ips ?? 0}</p>
            <p style={s.muted}>{t("linux.attackingIPs")}</p>
          </div>
        </div>

        {topIPs.length > 0 && (
          <>
            <p style={{ ...s.cardTitle, marginBottom: 8 }}>{t("linux.topAttackers")}</p>
            {topIPs.slice(0, 5).map((item, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
                                    padding: "6px 0", borderBottom: "1px solid #21262d" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontFamily: "monospace", fontSize: 13, color: "#fc8181" }}>{item.ip}</span>
                  <span style={{ fontSize: 11, color: "#8b949e" }}>×{item.count}</span>
                </div>
                <button
                  disabled={isBlocked(item.ip) || isPending(item.ip) || cmdLoading[`block_ip-${item.ip}`]}
                  onClick={() => sendCommand("block_ip", { ip: item.ip })}
                  style={{
                    fontSize: 11, padding: "3px 10px", borderRadius: 6, cursor: "pointer", border: "none",
                    background: isBlocked(item.ip) ? "#0d2818" : "#2d1b1b",
                    color:      isBlocked(item.ip) ? "#56d364"  : "#fc8181",
                    opacity:    isPending(item.ip) ? 0.6 : 1,
                  }}
                >
                  {isBlocked(item.ip)  ? t("linux.blocked")
                   : isPending(item.ip) ? t("linux.blocking")
                   : t("linux.blockIP")}
                </button>
              </div>
            ))}
          </>
        )}

        {/* Manual block */}
        <div style={{ marginTop: 14, display: "flex", gap: 8 }}>
          <input
            value={blockInput}
            onChange={e => setBlockInput(e.target.value)}
            placeholder="1.2.3.4"
            style={{ ...s.nicknameInput, flex: 1, fontSize: 12 }}
          />
          <button
            disabled={!blockInput.trim() || cmdLoading[`block_ip-${blockInput.trim()}`]}
            onClick={() => { sendCommand("block_ip", { ip: blockInput.trim() }); setBlockInput(""); }}
            style={{ background: "#742a2a", color: "#fc8181", border: "none",
                     borderRadius: 6, padding: "4px 12px", cursor: "pointer", fontSize: 12 }}
          >
            {t("linux.blockIP")}
          </button>
        </div>
      </div>

      {/* Access Log + Privilege */}
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

        {/* Recent Logins */}
        <div style={s.infoCard}>
          <p style={s.cardTitle}>{t("linux.recentLogins")}</p>
          {logins.length === 0 ? (
            <p style={s.muted}>{t("linux.noRecentLogins")}</p>
          ) : (
            logins.slice(0, 5).map((l, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between",
                                    padding: "5px 0", borderBottom: "1px solid #21262d" }}>
                <span style={{ fontSize: 12, color: "#c9d1d9", fontFamily: "monospace" }}>{l.user}</span>
                <span style={{ fontSize: 11, color: "#8b949e" }}>{l.ip_or_tty}</span>
                <span style={{ fontSize: 11, color: "#4a5568" }}>{l.time_str}</span>
              </div>
            ))
          )}
        </div>

        {/* Sudo Users */}
        <div style={s.infoCard}>
          <p style={s.cardTitle}>{t("linux.privilege")}</p>
          <p style={s.muted}>{t("linux.sudoUsers")}:</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, margin: "8px 0 12px" }}>
            {sudoUsers.length === 0 ? (
              <span style={s.muted}>—</span>
            ) : sudoUsers.map((u, i) => (
              <span key={i} style={{ fontSize: 11, background: "#0d2818", border: "1px solid #238636",
                                     color: "#56d364", borderRadius: 4, padding: "2px 8px" }}>
                {u}
              </span>
            ))}
          </div>
          <p style={s.muted}>{t("linux.suidFiles")}:</p>
          {suidFiles.length === 0 ? (
            <p style={{ fontSize: 12, color: "#48bb78" }}>{t("linux.noSuidFiles")}</p>
          ) : (
            suidFiles.map((f, i) => (
              <p key={i} style={{ fontSize: 11, color: "#fc8181", fontFamily: "monospace", margin: "2px 0" }}>{f}</p>
            ))
          )}
        </div>
      </div>

      {/* Firewall UFW — full width */}
      <div style={{ ...s.infoCard, gridColumn: "1 / -1" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <p style={s.cardTitle}>{t("linux.firewall")}</p>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 14, fontWeight: 700,
                           color: fw.active ? "#56d364" : "#fc8181" }}>
              {fw.active ? t("linux.firewallActive") : t("linux.firewallInactive")}
            </span>
            {!fw.active && (
              <button
                disabled={getCommandStatus("enable_ufw") === "pending" || getCommandStatus("enable_ufw") === "in_progress"
                          || cmdLoading["enable_ufw-"]}
                onClick={() => sendCommand("enable_ufw")}
                style={{ background: "#1f6feb", color: "#fff", border: "none",
                         borderRadius: 6, padding: "6px 14px", cursor: "pointer", fontSize: 12 }}
              >
                {(getCommandStatus("enable_ufw") === "pending" || getCommandStatus("enable_ufw") === "in_progress")
                  ? t("linux.enablingUFW") : t("linux.enableUFW")}
              </button>
            )}
          </div>
        </div>
        {fw.rules_count != null && (
          <p style={{ ...s.muted, marginTop: 8 }}>
            {t("linux.rulesCount", { n: fw.rules_count })}
          </p>
        )}
      </div>

    </div>
  );
}

// ── Latency Bar Chart ─────────────────────────────────────────────────────────

function LatencyChart({ history }) {
  if (!history || history.length === 0) return null;
  const max    = Math.max(...history.map(h => h.latency_ms || 0), 200);
  const W      = 260, H = 80, barW = 20, gap = 6;
  const total  = history.length;
  const startX = W - total * (barW + gap) + gap;

  return (
    <svg width={W} height={H} style={{ overflow: "visible" }}>
      {history.map((h, i) => {
        const x    = startX + i * (barW + gap);
        const pct  = h.connected && h.latency_ms != null ? Math.min(h.latency_ms / max, 1) : 1;
        const barH = Math.max(4, pct * (H - 16));
        const y    = H - barH;
        const color = !h.connected ? "#4a5568"
          : h.latency_ms < 50  ? "#48bb78"
          : h.latency_ms < 150 ? "#f6ad55"
          : "#fc8181";
        return (
          <g key={i}>
            <rect x={x} y={y} width={barW} height={barH} rx={3} fill={color} opacity={0.85} />
            {i === total - 1 && h.latency_ms != null && (
              <text x={x + barW / 2} y={y - 4} textAnchor="middle"
                fill={color} fontSize={9} fontWeight={700}>
                {h.latency_ms}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

// ── Network Tab ───────────────────────────────────────────────────────────────

function NetworkTab({ networkData, t }) {
  const net = networkData;

  if (!net) {
    return (
      <div style={{ padding: "40px 0", textAlign: "center", color: "#4a5568" }}>
        {t("network.noNetworkData")}
      </div>
    );
  }

  const openPorts = net.open_ports || [];

  return (
    <div className="rg-network">

      {/* Connection status + latency history */}
      <div style={s.infoCard}>
        <p style={s.cardTitle}>{t("network.title")}</p>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <span style={{ fontSize: 24 }}>{net.connected ? "🌐" : "🔌"}</span>
          <div>
            <p style={{ ...s.bigVal, color: net.connected ? "#48bb78" : "#fc8181", marginBottom: 2 }}>
              {net.connected ? t("network.connected") : t("network.disconnected")}
            </p>
            {net.latency_ms != null && (
              <p style={{ ...s.muted, fontSize: 14 }}>
                {net.latency_ms}{t("network.ms")} {t("network.latency")}
              </p>
            )}
          </div>
        </div>
        {net.network_name && (
          <p style={s.muted}>{t("network.networkName")}: <span style={{ color: "#c9d1d9" }}>{net.network_name}</span></p>
        )}
        <div style={{ marginTop: 14 }}>
          <p style={{ ...s.cardTitle, marginBottom: 8 }}>{t("network.latencyHistory")}</p>
          <LatencyChart history={net.latency_history} />
        </div>
      </div>

      {/* IP addresses */}
      <div style={s.infoCard}>
        <p style={s.cardTitle}>IP</p>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div>
            <p style={s.muted}>{t("network.localIP")}</p>
            <p style={{ ...s.bigVal, fontSize: 15, fontFamily: "monospace", color: "#58a6ff" }}>
              {net.local_ip || "—"}
            </p>
          </div>
          <div>
            <p style={s.muted}>{t("network.publicIP")}</p>
            <p style={{ ...s.bigVal, fontSize: 15, fontFamily: "monospace", color: "#58a6ff" }}>
              {net.public_ip || "—"}
            </p>
          </div>
        </div>

        {/* RDP / SSH */}
        <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{
            padding: "10px 14px", borderRadius: 8,
            background: net.rdp_enabled ? "#2d2008" : "#0d2818",
            border: `1px solid ${net.rdp_enabled ? "#7d4f00" : "#238636"}`,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ fontWeight: 700, fontSize: 13, color: net.rdp_enabled ? "#f6ad55" : "#56d364" }}>
                {t("network.rdp")}
              </span>
              <span style={{ fontSize: 12, fontWeight: 700, color: net.rdp_enabled ? "#ed8936" : "#48bb78" }}>
                {net.rdp_enabled ? "ON" : "OFF"}
              </span>
            </div>
            {net.rdp_enabled && (
              <p style={{ fontSize: 11, color: "#8b949e", margin: 0, lineHeight: 1.5 }}>
                {t("network.rdpWarning")}
              </p>
            )}
          </div>

          <div style={{
            padding: "10px 14px", borderRadius: 8,
            background: net.ssh_enabled ? "#2d2008" : "#0d1117",
            border: `1px solid ${net.ssh_enabled ? "#7d4f00" : "#21262d"}`,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ fontWeight: 700, fontSize: 13, color: net.ssh_enabled ? "#f6ad55" : "#8b949e" }}>
                {t("network.ssh")}
              </span>
              <span style={{ fontSize: 12, fontWeight: 700, color: net.ssh_enabled ? "#ed8936" : "#4a5568" }}>
                {net.ssh_enabled ? "ON" : "OFF"}
              </span>
            </div>
            {net.ssh_enabled && (
              <p style={{ fontSize: 11, color: "#8b949e", margin: 0, lineHeight: 1.5 }}>
                {t("network.sshInfo")}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Open ports */}
      <div style={s.infoCard}>
        <p style={s.cardTitle}>{t("network.openPorts")} ({openPorts.length})</p>
        {openPorts.length === 0 ? (
          <p style={s.muted}>{t("network.noOpenPorts")}</p>
        ) : (
          <table style={s.procTable}>
            <thead>
              <tr>
                <th style={s.th}>{t("network.port")}</th>
                <th style={s.th}>{t("network.protocol")}</th>
                <th style={s.th}>{t("network.process")}</th>
                <th style={{ ...s.th, textAlign: "right" }}>{t("network.risk")}</th>
              </tr>
            </thead>
            <tbody>
              {openPorts.map((p, i) => (
                <tr key={i} style={p.dangerous ? { background: "rgba(252,129,129,0.05)" } : {}}>
                  <td style={{ ...s.td, fontFamily: "monospace", color: p.dangerous ? "#fc8181" : "#c9d1d9" }}>
                    {p.port}
                  </td>
                  <td style={{ ...s.td, color: "#8b949e" }}>{p.protocol}</td>
                  <td style={{ ...s.td, color: "#8b949e", maxWidth: 80 }}>
                    {p.process?.replace(".exe", "") || "—"}
                  </td>
                  <td style={{ ...s.td, textAlign: "right" }}>
                    <span style={{
                      fontSize: 10, fontWeight: 700, padding: "1px 6px", borderRadius: 4,
                      background: p.dangerous ? "#2d1b1b" : "#0d2818",
                      color:      p.dangerous ? "#fc8181" : "#56d364",
                      border:     `1px solid ${p.dangerous ? "#742a2a" : "#238636"}`,
                    }}>
                      {p.dangerous ? t("network.riskDangerous") : t("network.riskNormal")}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

    </div>
  );
}

// ── DeviceDashboard ───────────────────────────────────────────────────────────

export default function DeviceDashboard({ user }) {
  const { t, i18n }   = useTranslation();
  const navigate       = useNavigate();
  const { deviceId }   = useParams();
  const isRTL          = i18n.language === "he";
  const { isMobile, isTablet } = useResponsive();

  const [deviceDoc,     setDeviceDoc]     = useState(null);
  const [realtimeData,  setRealtimeData]  = useState(null);
  const [networkData,   setNetworkData]   = useState(null);
  const [latestScan,    setLatestScan]    = useState(null);
  const [loading,       setLoading]       = useState(true);
  const [editingName,   setEditingName]   = useState(false);
  const [nicknameInput, setNicknameInput] = useState("");
  const [activeTab,     setActiveTab]     = useState("overview"); // "overview" | "network" | "security"
  const [commands,      setCommands]      = useState([]);
  const [cmdLoading,    setCmdLoading]    = useState({});   // commandId → bool
  const [latestVersion, setLatestVersion] = useState(null);

  const realtimeUnsubRef = useRef(null);
  const networkUnsubRef  = useRef(null);
  const commandsUnsubRef = useRef(null);
  const lastScanIdRef    = useRef(null);

  // Load scan by ID
  const loadScan = useCallback(async (scanId) => {
    if (!scanId || scanId === lastScanIdRef.current) return;
    lastScanIdRef.current = scanId;
    const snap = await getDoc(doc(db, "users", user.uid, "devices", deviceId, "scans", scanId));
    if (snap.exists()) setLatestScan(snap.data());
  }, [user.uid, deviceId]);

  // Device status — always subscribed
  useEffect(() => {
    const unsub = onSnapshot(
      doc(db, "users", user.uid, "devices", deviceId),
      (snap) => {
        if (snap.exists()) {
          const data = snap.data();
          setDeviceDoc(data);
          if (data.lastScanId) loadScan(data.lastScanId);
        }
        setLoading(false);
      },
      () => setLoading(false),
    );
    return () => unsub();
  }, [user.uid, deviceId, loadScan]);

  // Realtime heartbeat — visibility-aware
  const subscribeRealtime = useCallback(() => {
    if (realtimeUnsubRef.current || document.hidden) return;
    realtimeUnsubRef.current = onSnapshot(
      doc(db, "users", user.uid, "devices", deviceId, "realtime", "current"),
      (snap) => { if (snap.exists()) setRealtimeData(snap.data()); },
    );
  }, [user.uid, deviceId]);

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

  // Network subscription — visibility-aware
  const subscribeNetwork = useCallback(() => {
    if (networkUnsubRef.current || document.hidden) return;
    networkUnsubRef.current = onSnapshot(
      doc(db, "users", user.uid, "devices", deviceId, "network", "current"),
      (snap) => { if (snap.exists()) setNetworkData(snap.data()); },
    );
  }, [user.uid, deviceId]);

  const unsubscribeNetwork = useCallback(() => {
    networkUnsubRef.current?.();
    networkUnsubRef.current = null;
  }, []);

  useEffect(() => {
    subscribeNetwork();
    const onVisibility = () =>
      document.hidden ? unsubscribeNetwork() : subscribeNetwork();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      unsubscribeNetwork();
    };
  }, [subscribeNetwork, unsubscribeNetwork]);

  // Commands subscription (for Linux agent command queue)
  useEffect(() => {
    if (!deviceDoc || deviceDoc.os !== "Linux") return;
    if (commandsUnsubRef.current) return;
    commandsUnsubRef.current = onSnapshot(
      collection(db, "users", user.uid, "devices", deviceId, "commands"),
      (snap) => setCommands(snap.docs.map(d => ({ id: d.id, ...d.data() }))),
    );
    return () => {
      commandsUnsubRef.current?.();
      commandsUnsubRef.current = null;
    };
  }, [user.uid, deviceId, deviceDoc]);

  // Latest agent version — for update badge
  useEffect(() => {
    const unsub = onSnapshot(
      doc(db, "config", "latestAgentVersion"),
      snap => { if (snap.exists()) setLatestVersion(snap.data()); },
      () => {},
    );
    return () => unsub();
  }, []);

  const sendCommand = async (type, payload = {}) => {
    const key = `${type}-${payload.ip || ""}`;
    setCmdLoading(prev => ({ ...prev, [key]: true }));
    try {
      const fn = httpsCallable(functions, "sendLinuxCommand");
      await fn({ deviceId, type, ...payload });
    } catch (err) {
      console.error("sendCommand error:", err);
    } finally {
      setCmdLoading(prev => ({ ...prev, [key]: false }));
    }
  };

  const saveNickname = async () => {
    const nickname = nicknameInput.trim();
    await setDoc(doc(db, "users", user.uid, "devices", deviceId), { nickname }, { merge: true });
    setEditingName(false);
  };

  const toggleLang = () => {
    const l = i18n.language === "en" ? "he" : "en";
    i18n.changeLanguage(l);
    localStorage.setItem("lang", l);
  };

  // Derived values
  const cpuPct        = realtimeData?.cpu_percent ?? null;
  const ramPct        = realtimeData?.ram_percent ?? null;
  const ramUsedGB     = realtimeData?.ram_used_gb;
  const ramTotalGB    = realtimeData?.ram_total_gb;
  const disk          = getDiskInfo(latestScan?.storage ?? deviceDoc?.storage);
  const health        = latestScan?.healthScore ?? deviceDoc?.healthScore ?? null;
  const vulnCount     = Array.isArray(latestScan?.vulnerabilities) ? latestScan.vulnerabilities.length : null;
  const threatCount   = deviceDoc?.threatCount    ?? null;
  const suspiciousCount = deviceDoc?.suspiciousCount ?? null;
  const firewallGrade = deviceDoc?.firewallGrade  ?? null;
  const topProcs      = realtimeData?.top_processes ?? [];
  const temps         = realtimeData?.temperatures  ?? [];
  const isLive        = realtimeData?.updatedAt &&
    (Date.now() - (realtimeData.updatedAt.toDate?.()?.getTime?.() ?? 0)) < 30_000;
  const lastScanAt    = deviceDoc?.lastScanAt?.toDate?.() ?? null;
  const countdown     = useCountdown(lastScanAt, 300);

  const isOnline = () => {
    const ls = deviceDoc?.last_seen?.toDate?.() || deviceDoc?.lastHeartbeat?.toDate?.();
    return ls && Date.now() - ls.getTime() < 90_000;
  };

  const displayName   = deviceDoc?.nickname || deviceDoc?.name || deviceId;

  if (loading) {
    return (
      <div style={s.centered}>
        <p style={{ color: "#a0aec0" }}>{t("common.loading")}</p>
      </div>
    );
  }

  return (
    <div dir={isRTL ? "rtl" : "ltr"} style={s.page}>

      {/* ── Header ────────────────────────────────────────────────────────── */}
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
          {isLive && (
            <span style={s.liveBadge}>
              <span style={s.liveDot} />
              <span className="btn-lbl">{t("dashboard.live")}</span>
            </span>
          )}
          <button onClick={toggleLang} style={s.ghostBtn}>
            🌐 <span className="btn-lbl">{i18n.language === "en" ? "עברית" : "English"}</span>
          </button>
          <button
            onClick={() => navigate(`/device/${deviceId}/report`, { state: { deviceId } })}
            style={s.ghostBtn}
            disabled={!latestScan}
          >
            📋 <span className="btn-lbl">{t("nav.reports")}</span>
          </button>
          <button onClick={() => signOut(auth).then(() => navigate("/login"))} style={s.ghostBtn}>
            ⏻ <span className="btn-lbl">{t("nav.logout")}</span>
          </button>
        </div>
      </header>

      <main style={{ ...s.main, padding: isMobile ? "16px 14px" : "24px", paddingBottom: "max(32px, env(safe-area-inset-bottom))" }}>

        {/* ── Breadcrumb + device name ───────────────────────────────────── */}
        <div style={s.breadcrumb}>
          <button onClick={() => navigate("/dashboard")} style={s.breadcrumbLink}>
            ← {t("devices.title")}
          </button>
          <span style={s.breadcrumbSep}>/</span>
          <span style={s.breadcrumbCurrent}>
            <span style={{
              ...s.onlineDot,
              background: isOnline() ? "#56d364" : "#6e7681",
            }} />
            {editingName ? (
              <>
                <input
                  value={nicknameInput}
                  onChange={e => setNicknameInput(e.target.value)}
                  onKeyDown={e => { if (e.key === "Enter") saveNickname(); if (e.key === "Escape") setEditingName(false); }}
                  style={s.nicknameInput}
                  autoFocus
                  placeholder={t("devices.nicknamePlaceholder")}
                />
                <button onClick={saveNickname} style={s.nicknameSave}>{t("devices.saveNickname")}</button>
                <button onClick={() => setEditingName(false)} style={s.ghostBtnSm}>{t("common.cancel")}</button>
              </>
            ) : (
              <>
                <span style={{ color: "#e2e8f0", fontWeight: 600 }}>{displayName}</span>
                {deviceDoc?.name && deviceDoc?.nickname && (
                  <span style={{ color: "#8b949e", fontSize: 13, marginLeft: 6 }}>({deviceDoc.name})</span>
                )}
                <button
                  onClick={() => { setNicknameInput(deviceDoc?.nickname || ""); setEditingName(true); }}
                  style={s.pencilBtn}
                  title={t("devices.editNickname")}
                >
                  ✏️
                </button>
              </>
            )}
          </span>
        </div>

        {/* ── Agent offline banner ───────────────────────────────────────── */}
        {!isOnline() && (
          <div style={s.offlineBanner}>
            <span>🔴</span>
            <span style={{ color: "#fc8181" }}>
              {t("dashboard.agentDisconnected")}
              {deviceDoc?.last_seen && (
                <span style={{ color: "#8b949e", marginLeft: 8 }}>
                  ({formatAgo(deviceDoc.last_seen, t)})
                </span>
              )}
            </span>
          </div>
        )}

        {/* ── Tab bar ───────────────────────────────────────────────────── */}
        <div style={s.tabBar} className="tab-scroll">
          {[
            { id: "overview",  label: `📊 ${t("report.tabs.overview")}` },
            { id: "network",   label: `🌐 ${t("network.title")}` },
            ...((deviceDoc?.os === "Linux" || deviceDoc?.os === "macOS") ? [{ id: "security", label: `🛡️ ${t("dashboard.sections.security")}` }] : []),
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{ ...s.tabBtn, ...(activeTab === tab.id ? s.tabBtnActive : {}) }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── ROW 1: Gauges ─────────────────────────────────────────────── */}
        <div className="rg-gauges">
          {[
            { value: cpuPct,       label: t("dashboard.cpu"),         color: gaugeColor(cpuPct) },
            { value: ramPct,       label: t("dashboard.ram"),         color: gaugeColor(ramPct),
              sublabel: ramUsedGB != null ? `${ramUsedGB} / ${ramTotalGB} GB` : undefined },
            { value: disk?.pct ?? null, label: t("dashboard.disk"),  color: gaugeColor(disk?.pct),
              sublabel: disk ? `${disk.used} / ${disk.total} GB` : undefined },
            { value: health,       label: t("dashboard.healthScore"), color: healthColor(health) },
          ].map(({ value, label, color, sublabel }) => (
            <div key={label} style={{ ...s.gaugeCard, padding: isMobile ? "16px 8px" : "24px 16px" }}>
              <CircularGauge
                value={value} label={label} color={color} sublabel={sublabel}
                size={isMobile ? 100 : isTablet ? 120 : 136}
              />
            </div>
          ))}
        </div>

        {/* ── ROW 2: Info cards (Overview tab) ──────────────────────────── */}
        {activeTab === "network"  ? <NetworkTab networkData={networkData} t={t} /> : null}
        {activeTab === "security" && deviceDoc?.os === "Linux" ? (
          <LinuxSecurityTab
            scan={latestScan}
            deviceId={deviceId}
            commands={commands}
            cmdLoading={cmdLoading}
            sendCommand={sendCommand}
            t={t}
          />
        ) : activeTab === "security" && deviceDoc?.os === "macOS" ? (
          <MacSecurityTab scan={latestScan} />
        ) : null}
        <div className="rg-cards" style={{ display: activeTab === "overview" ? "grid" : "none" }}>

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
                      <td style={{ ...s.td, textAlign: "right", color: gaugeColor(p.cpu) }}>{p.cpu}%</td>
                      <td style={{ ...s.td, textAlign: "right", color: "#8b949e" }}>{p.ram_mb}</td>
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
                  const color = temp.current >= 80 ? "#fc8181" : temp.current >= 65 ? "#ed8936" : "#48bb78";
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
            {threatCount === null && vulnCount === null ? (
              <p style={s.muted}>{t("dashboard.noAgentData")}</p>
            ) : (
              <>
                {threatCount > 0 ? (
                  <p style={{ ...s.bigVal, color: "#fc8181", marginBottom: 4 }}>
                    🔴 {t("dashboard.security.threats", { count: threatCount })}
                  </p>
                ) : suspiciousCount > 0 ? (
                  <p style={{ ...s.bigVal, color: "#ed8936", marginBottom: 4 }}>
                    🟡 {t("dashboard.security.suspicious", { count: suspiciousCount })}
                  </p>
                ) : (
                  <p style={{ ...s.bigVal, color: "#48bb78", marginBottom: 4 }}>
                    {t("dashboard.allClear")}
                  </p>
                )}
                {firewallGrade && (
                  <div style={s.gradeRow}>
                    <span style={s.gradeLabel}>{t("dashboard.security.firewall")}</span>
                    <span style={{
                      ...s.gradeBadge,
                      background: firewallGrade === "A" ? "#0d2818" : firewallGrade === "F" ? "#2d1b1b" : "#2d2008",
                      color:      firewallGrade === "A" ? "#56d364" : firewallGrade === "F" ? "#fc8181" : "#f6ad55",
                      borderColor: firewallGrade === "A" ? "#238636" : firewallGrade === "F" ? "#742a2a" : "#7d4f00",
                    }}>
                      {t("dashboard.security.grade")} {firewallGrade}
                    </span>
                  </div>
                )}
                {vulnCount > 0 && (
                  <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 8 }}>
                    {(latestScan?.vulnerabilities ?? []).slice(0, 2).map((v, i) => (
                      <p key={i} style={s.vulnItem}>
                        {v.severity === "critical" ? "🔴" : v.severity === "high" ? "🟠" : "🟡"}{" "}{v.description}
                      </p>
                    ))}
                  </div>
                )}
              </>
            )}
            <button
              onClick={() => navigate(`/device/${deviceId}/report`, { state: { deviceId } })}
              style={{ ...s.viewReportBtn, marginTop: 12 }}
              disabled={!latestScan}
            >
              {t("dashboard.viewReport")}
            </button>
          </div>

          {/* Current Session */}
          <div style={s.infoCard}>
            <p style={s.cardTitle}>{t("users.currentSession")}</p>
            {deviceDoc?.current_username ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 22 }}>👤</span>
                  <div>
                    <p style={{ ...s.bigVal, fontSize: 16, marginBottom: 2 }}>{deviceDoc.current_username}</p>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {deviceDoc.current_user_is_admin && (
                        <span style={{ fontSize: 10, background: "#2d2008", border: "1px solid #7d4f00",
                                       color: "#f6ad55", borderRadius: 4, padding: "2px 7px" }}>
                          {t("users.admin")}
                        </span>
                      )}
                      {!deviceDoc.current_user_is_admin && (
                        <span style={{ fontSize: 10, background: "#0d1117", border: "1px solid #21262d",
                                       color: "#8b949e", borderRadius: 4, padding: "2px 7px" }}>
                          {t("users.standard")}
                        </span>
                      )}
                      {deviceDoc.current_user_session_type && (
                        <span style={{ fontSize: 10, background: "#0d1117", border: "1px solid #21262d",
                                       color: "#58a6ff", borderRadius: 4, padding: "2px 7px" }}>
                          {t(`users.${deviceDoc.current_user_session_type}`) || deviceDoc.current_user_session_type}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                {deviceDoc.active_session_count > 1 && (
                  <p style={s.muted}>{t("users.activeSessions", { n: deviceDoc.active_session_count })}</p>
                )}
              </div>
            ) : (
              <p style={s.muted}>{t("users.noActiveSession")}</p>
            )}

            {/* Local users table */}
            {(latestScan?.localUsers?.length > 0) && (
              <>
                <p style={{ ...s.cardTitle, marginTop: 16 }}>{t("users.localUsers")}</p>
                <table style={s.procTable}>
                  <thead>
                    <tr>
                      <th style={s.th}>{t("users.username")}</th>
                      <th style={s.th}>{t("users.role")}</th>
                      <th style={{ ...s.th, textAlign: "right" }}>{t("users.lastLogin")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {latestScan.localUsers.map((u, i) => (
                      <tr key={i}>
                        <td style={{ ...s.td, fontFamily: "monospace" }}>{u.username}</td>
                        <td style={s.td}>
                          {u.is_admin ? (
                            <span style={{ fontSize: 11, color: "#f6ad55" }}>⭐ {t("users.admin")}</span>
                          ) : (
                            <span style={{ fontSize: 11, color: "#8b949e" }}>{t("users.standard")}</span>
                          )}
                        </td>
                        <td style={{ ...s.td, textAlign: "right", color: "#8b949e", fontSize: 11 }}>
                          {u.last_login || t("users.never")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>

          {/* Agent Info */}
          <div style={s.infoCard}>
            <p style={s.cardTitle}>{t("version.agentVersion")}</p>
            {deviceDoc?.agentVersion ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 22 }}>🤖</span>
                  <p style={{ ...s.bigVal, fontSize: 20, fontFamily: "monospace" }}>
                    v{deviceDoc.agentVersion}
                  </p>
                </div>
                {(() => {
                  const expected = deviceDoc?.os === "Linux"
                    ? latestVersion?.linux_version
                    : deviceDoc?.os === "macOS"
                    ? latestVersion?.mac_version
                    : latestVersion?.windows_version;
                  const isUpToDate = !expected || deviceDoc.agentVersion === expected;
                  return isUpToDate ? (
                    <span style={{ fontSize: 12, color: "#48bb78" }}>✓ {t("version.upToDate")}</span>
                  ) : (
                    <div>
                      <span style={{ fontSize: 12, color: "#f6ad55" }}>
                        ⬆ {t("version.updateAvailable")} → v{expected}
                      </span>
                      <div style={{ marginTop: 10 }}>
                        {deviceDoc?.os === "Linux" ? (
                          <p style={{ fontSize: 11, color: "#8b949e", lineHeight: 1.6 }}>
                            {t("version.linuxUpdateCmd")}<br />
                            <code style={{ fontFamily: "monospace", color: "#58a6ff", fontSize: 11 }}>
                              curl -sSL https://pcguard-rami.web.app/install.sh | bash
                            </code>
                          </p>
                        ) : deviceDoc?.os === "macOS" ? (
                          <p style={{ fontSize: 11, color: "#8b949e", lineHeight: 1.6 }}>
                            Run in Terminal to update:<br />
                            <code style={{ fontFamily: "monospace", color: "#58a6ff", fontSize: 11 }}>
                              curl -sSL https://pcguard-rami.web.app/install-mac.sh | bash
                            </code>
                          </p>
                        ) : (
                          <a
                            href="https://github.com/DNA-CyberSec/pc-security-dashboard/releases/latest/download/PCGuard-Setup.exe"
                            target="_blank" rel="noreferrer"
                            style={{ fontSize: 12, color: "#1f6feb",
                                     background: "#1f6feb22", borderRadius: 6,
                                     padding: "6px 14px", textDecoration: "none",
                                     display: "inline-block" }}
                          >
                            ⬇ {t("version.downloadWindows")}
                          </a>
                        )}
                      </div>
                    </div>
                  );
                })()}
              </div>
            ) : (
              <p style={s.muted}>{t("dashboard.noAgentData")}</p>
            )}
          </div>

          {/* Last scan + countdown */}
          <div style={s.infoCard}>
            <p style={s.cardTitle}>{t("dashboard.lastScan")}</p>
            <p style={s.bigVal}>
              {deviceDoc?.lastScanAt ? formatAgo(deviceDoc.lastScanAt, t) : t("dashboard.neverScanned")}
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
              onClick={() => navigate(`/device/${deviceId}/report`, { state: { deviceId } })}
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
  ghostBtnSm: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 6, padding: "3px 8px", cursor: "pointer", fontSize: 12,
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
  },

  // Breadcrumb
  breadcrumb: {
    display: "flex", alignItems: "center", gap: 8,
    marginBottom: 20, flexWrap: "wrap",
  },
  breadcrumbLink: {
    background: "transparent", border: "none", color: "#58a6ff",
    cursor: "pointer", fontSize: 14, padding: "8px 4px",
    minHeight: 44, display: "inline-flex", alignItems: "center",
  },
  breadcrumbSep:     { color: "#4a5568", fontSize: 14 },
  breadcrumbCurrent: { display: "flex", alignItems: "center", gap: 6, fontSize: 15 },
  onlineDot:  { width: 8, height: 8, borderRadius: "50%", flexShrink: 0 },
  pencilBtn:  { background: "transparent", border: "none", cursor: "pointer", fontSize: 14, padding: "0 2px" },
  nicknameInput: {
    background: "#21262d", border: "1px solid #58a6ff", borderRadius: 6,
    color: "#e2e8f0", fontSize: 14, padding: "4px 10px", outline: "none",
  },
  nicknameSave: {
    background: "#238636", color: "#fff", border: "none",
    borderRadius: 6, padding: "4px 12px", cursor: "pointer", fontSize: 12,
  },

  offlineBanner: {
    display: "flex", alignItems: "center", gap: 10,
    padding: "12px 18px", borderRadius: 10, border: "1px solid #742a2a",
    background: "#2d1b1b", marginBottom: 20,
  },

  main:    { maxWidth: 1100, margin: "0 auto", padding: "24px 24px 32px" },

  // Gauge row
  gaugeRow: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 16 },
  gaugeCard: {
    background: "#161b22", border: "1px solid #21262d",
    borderRadius: 14, padding: "24px 16px",
    display: "flex", alignItems: "center", justifyContent: "center",
  },

  // Info card row
  cardRow: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 },
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

  procTable: { width: "100%", borderCollapse: "collapse" },
  th: { fontSize: 10, color: "#4a5568", fontWeight: 500, padding: "0 0 6px",
        textAlign: "left", textTransform: "uppercase", letterSpacing: 0.5 },
  td: { fontSize: 12, color: "#c9d1d9", padding: "4px 0",
        whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 100 },

  tempRow:  { display: "flex", justifyContent: "space-between", alignItems: "center" },
  tempLabel: { fontSize: 12, color: "#8b949e" },
  tempVal:   { fontSize: 14, fontWeight: 700 },

  vulnItem: { fontSize: 11, color: "#8b949e", margin: 0, lineHeight: 1.4 },

  gradeRow:   { display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 8 },
  gradeLabel: { fontSize: 12, color: "#8b949e" },
  gradeBadge: { fontSize: 12, fontWeight: 700, padding: "2px 10px", borderRadius: 20, border: "1px solid" },

  viewReportBtn: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 6, padding: "6px 12px", cursor: "pointer", fontSize: 12, width: "100%",
  },
  setupBtn: {
    background: "#238636", color: "#fff", border: "none",
    borderRadius: 6, padding: "8px 16px", cursor: "pointer",
    fontSize: 13, fontWeight: 600, whiteSpace: "nowrap",
  },
  countdownBox: { marginTop: 12, paddingTop: 12, borderTop: "1px solid #21262d" },

  // Tab bar
  tabBar: {
    display: "flex", gap: 4, marginBottom: 16,
    borderBottom: "1px solid #21262d", paddingBottom: 0,
  },
  tabBtn: {
    background: "transparent", border: "none", color: "#8b949e",
    padding: "8px 16px", cursor: "pointer", fontSize: 13, fontWeight: 500,
    borderBottom: "2px solid transparent", marginBottom: -1,
    borderRadius: "6px 6px 0 0",
  },
  tabBtnActive: {
    color: "#e2e8f0", borderBottomColor: "#58a6ff",
    background: "#161b22",
  },
};
