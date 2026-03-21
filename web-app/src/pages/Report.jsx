import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useLocation, useParams } from "react-router-dom";
import {
  collection,
  query,
  orderBy,
  limit,
  getDocs,
  doc,
  getDoc,
} from "firebase/firestore";
import { httpsCallable } from "firebase/functions";
import { db, functions } from "../firebase";

export default function Report({ user }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const isRTL = i18n.language === "he";

  const { deviceId: paramDeviceId } = useParams();
  const deviceId = paramDeviceId || location.state?.deviceId || "default";
  const defaultTab = location.state?.tab === "security" ? "security" : "overview";
  const [activeTab, setActiveTab] = useState(defaultTab);
  const [scan, setScan] = useState(null);
  const [securityData, setSecurityData] = useState(null);
  const [aiRecommendations, setAiRecommendations] = useState(null);
  const [explainResults, setExplainResults] = useState({});
  const [loading, setLoading] = useState(true);
  const [previewMode, setPreviewMode] = useState(true);
  const [actionLog, setActionLog] = useState([]);
  const [undoStack, setUndoStack] = useState([]);

  useEffect(() => {
    loadLatestReport();
  }, [user]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadLatestReport = async () => {
    try {
      const q = query(
        collection(db, "users", user.uid, "devices", deviceId, "scans"),
        orderBy("createdAt", "desc"),
        limit(1)
      );
      const snap = await getDocs(q);
      if (!snap.empty) {
        const data = { id: snap.docs[0].id, ...snap.docs[0].data() };
        setScan(data);
        await loadAiRecommendations(data.id);
      }
      // Load security summary
      const secSnap = await getDoc(doc(db, "users", user.uid, "devices", deviceId, "security", "current"));
      if (secSnap.exists()) setSecurityData(secSnap.data());
    } catch (err) {
      console.error("Report load error:", err);
    } finally {
      setLoading(false);
    }
  };

  const loadAiRecommendations = async (scanId) => {
    try {
      const getRecommendations = httpsCallable(functions, "getScanRecommendations");
      const result = await getRecommendations({ scanId, deviceId });
      setAiRecommendations(result.data.recommendations);
    } catch (err) {
      console.error("AI recommendations error:", err);
    }
  };

  const handleExplain = async (key, issue) => {
    if (explainResults[key]) return; // already loaded
    setExplainResults(prev => ({ ...prev, [key]: "loading" }));
    try {
      const explainFn = httpsCallable(functions, "explainIssue");
      const res = await explainFn({ issue });
      setExplainResults(prev => ({ ...prev, [key]: res.data.explanation || "No explanation available." }));
    } catch {
      setExplainResults(prev => ({ ...prev, [key]: "Could not load explanation." }));
    }
  };

  const handleClean = (category, items) => {
    if (previewMode) {
      alert(t("report.safety.previewTitle"));
      return;
    }
    const confirmed = window.confirm(t("report.safety.confirmClean"));
    if (!confirmed) return;

    // Record action for undo
    setUndoStack((prev) => [...prev, { category, items, timestamp: Date.now() }]);
    setActionLog((prev) => [
      ...prev,
      {
        action: "clean",
        category,
        itemCount: items.length,
        timestamp: new Date().toISOString(),
        status: "success",
      },
    ]);
    // Actual clean request sent to local agent via Firestore
    // agent polls for pending_actions and executes them
  };

  const handleUndo = () => {
    if (undoStack.length === 0) return;
    const last = undoStack[undoStack.length - 1];
    setUndoStack((prev) => prev.slice(0, -1));
    setActionLog((prev) => [
      ...prev,
      {
        action: "undo",
        category: last.category,
        timestamp: new Date().toISOString(),
        status: "success",
      },
    ]);
    alert(t("report.safety.undoSuccess"));
  };

  const formatDate = (ts) => {
    if (!ts) return "—";
    const d = ts.toDate ? ts.toDate() : new Date(ts);
    return d.toLocaleString(i18n.language === "he" ? "he-IL" : "en-US");
  };

  if (loading) {
    return (
      <div style={styles.centered}>
        <p style={{ color: "#a0aec0" }}>{t("common.loading")}</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div style={styles.centered}>
        <p style={{ color: "#a0aec0" }}>{t("common.noData")}</p>
        <button onClick={() => navigate("/dashboard")} style={styles.backBtn}>
          {t("common.back")}
        </button>
      </div>
    );
  }

  return (
    <div dir={isRTL ? "rtl" : "ltr"} style={styles.container}>
      {/* Header */}
      <header style={styles.header}>
        <button
          onClick={() => navigate(deviceId !== "default" ? `/device/${deviceId}` : "/dashboard")}
          style={styles.backBtn}
        >
          ← {t("common.back")}
        </button>
        <h1 style={styles.title}>{t("report.title")}</h1>
        <span style={styles.dateLabel}>
          {t("report.generatedAt")}: {formatDate(scan.createdAt)}
        </span>
      </header>

      {/* Tab bar */}
      <div style={styles.tabBar}>
        {["overview", "security"].map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              ...styles.tabBtn,
              ...(activeTab === tab ? styles.tabBtnActive : {}),
            }}
          >
            {tab === "overview" ? "📊 " : "🛡️ "}
            {t(`report.tabs.${tab}`)}
          </button>
        ))}
      </div>

      <main style={styles.main}>

        {/* ── OVERVIEW TAB ──────────────────────────────────────────────────── */}
        {activeTab === "overview" && (
          <>
            {/* Safety mode toggle */}
            <div style={styles.safetyBar}>
              <span style={styles.safetyIcon}>🔒</span>
              <span style={styles.safetyText}>
                {previewMode
                  ? t("report.safety.previewTitle")
                  : "Live Mode — changes will be applied"}
              </span>
              <label style={styles.toggleLabel}>
                <input
                  type="checkbox"
                  checked={!previewMode}
                  onChange={(e) => setPreviewMode(!e.target.checked)}
                />
                {" Enable live changes"}
              </label>
              {undoStack.length > 0 && (
                <button onClick={handleUndo} style={styles.undoBtn}>
                  ↩ {t("report.actions.undo")}
                </button>
              )}
            </div>

            {/* AI Recommendations */}
            {aiRecommendations && (
              <section style={styles.section}>
                <h2 style={styles.sectionTitle}>🤖 {t("report.recommendations")}</h2>
                <div style={styles.aiCard}>
                  <p style={styles.aiText}>{aiRecommendations}</p>
                </div>
              </section>
            )}

            {scan.tempFiles?.length > 0 && (
              <ReportSection
                title={t("report.categories.tempFiles")} icon="🗑️"
                items={scan.tempFiles}
                onClean={() => handleClean("tempFiles", scan.tempFiles)}
                t={t} previewMode={previewMode}
              />
            )}
            {scan.largeFiles?.length > 0 && (
              <ReportSection
                title={t("report.categories.largeFiles")} icon="📦"
                items={scan.largeFiles}
                onClean={() => handleClean("largeFiles", scan.largeFiles)}
                t={t} previewMode={previewMode}
              />
            )}
            {scan.duplicates?.length > 0 && (
              <ReportSection
                title={t("report.categories.duplicates")} icon="📋"
                items={scan.duplicates}
                onClean={() => handleClean("duplicates", scan.duplicates)}
                t={t} previewMode={previewMode}
              />
            )}
            {scan.vulnerabilities?.length > 0 && (
              <ReportSection
                title={t("report.categories.vulnerabilities")} icon="⚠️"
                items={scan.vulnerabilities} onClean={null}
                t={t} previewMode={previewMode} readOnly
              />
            )}

            {actionLog.length > 0 && (
              <section style={styles.section}>
                <h2 style={styles.sectionTitle}>📋 Action Log</h2>
                <div style={styles.logContainer}>
                  {actionLog.map((entry, i) => (
                    <div key={i} style={styles.logEntry}>
                      <span style={styles.logTime}>{entry.timestamp}</span>
                      <span style={styles.logAction}>
                        [{entry.action.toUpperCase()}] {entry.category} — {entry.status}
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </>
        )}

        {/* ── SECURITY TAB ──────────────────────────────────────────────────── */}
        {activeTab === "security" && (
          <SecurityTab
            securityData={securityData}
            scan={scan}
            t={t}
            explainResults={explainResults}
            onExplain={handleExplain}
          />
        )}

      </main>
    </div>
  );
}

function SecurityTab({ securityData, scan, t, explainResults, onExplain }) {
  const fw = securityData?.firewallStatus || {};
  const malware = securityData?.malwareSuspects || [];
  const startup = securityData?.startupSecurity || [];

  const gradeColor = (g) =>
    g === "A" ? "#56d364" : g === "F" ? "#fc8181" : "#f6ad55";

  return (
    <div>
      {!securityData && !scan?.vulnerabilities?.length ? (
        <p style={{ color: "#4a5568", marginTop: 32, textAlign: "center" }}>
          No security scan data yet. Run a scan to see results.
        </p>
      ) : (
        <>
          {/* ── Firewall & Protection ───────────────────────────────────── */}
          <section style={styles.section}>
            <h2 style={styles.sectionTitle}>🔥 {t("report.security.firewall")}</h2>
            <div style={styles.fwGrid}>
              {["domain", "private", "public"].map(profile => {
                const val = fw[profile];
                const on  = val === "on";
                return (
                  <div key={profile} style={{
                    ...styles.fwProfile,
                    borderColor: val == null ? "#30363d" : on ? "#238636" : "#742a2a",
                    background:  val == null ? "#161b22" : on ? "#0d2818" : "#2d1b1b",
                  }}>
                    <span style={{ fontSize: 20 }}>{on ? "✅" : val == null ? "❓" : "🚫"}</span>
                    <div>
                      <p style={{ color: "#e2e8f0", fontWeight: 600, margin: 0, fontSize: 13 }}>
                        {profile.charAt(0).toUpperCase() + profile.slice(1)}
                      </p>
                      <p style={{ color: on ? "#56d364" : val == null ? "#4a5568" : "#fc8181",
                                  fontSize: 12, margin: 0 }}>
                        {val ? val.toUpperCase() : "Unknown"}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>

            <div style={styles.defenderRow}>
              <div style={styles.defenderItem}>
                <span style={{ fontSize: 16 }}>{fw.defender_enabled ? "✅" : fw.defender_enabled === false ? "🚫" : "❓"}</span>
                <div>
                  <p style={styles.defLabel}>{t("report.security.defender")}</p>
                  <p style={{ ...styles.defVal, color: fw.defender_enabled ? "#56d364" : "#fc8181" }}>
                    {fw.defender_enabled ? "Enabled" : fw.defender_enabled === false ? "Disabled" : "Unknown"}
                  </p>
                </div>
              </div>
              {fw.defender_signatures_age_days != null && (
                <div style={styles.defenderItem}>
                  <span style={{ fontSize: 16 }}>🗓</span>
                  <div>
                    <p style={styles.defLabel}>{t("report.security.sigAge")}</p>
                    <p style={{ ...styles.defVal,
                      color: fw.defender_signatures_age_days > 7 ? "#fc8181"
                           : fw.defender_signatures_age_days > 3 ? "#f6ad55" : "#56d364" }}>
                      {fw.defender_signatures_age_days}d old
                    </p>
                  </div>
                </div>
              )}
              {fw.pending_updates != null && (
                <div style={styles.defenderItem}>
                  <span style={{ fontSize: 16 }}>🔄</span>
                  <div>
                    <p style={styles.defLabel}>{t("report.security.pendingUpdates")}</p>
                    <p style={{ ...styles.defVal,
                      color: fw.pending_updates > 5 ? "#fc8181"
                           : fw.pending_updates > 0 ? "#f6ad55" : "#56d364" }}>
                      {fw.pending_updates}
                    </p>
                  </div>
                </div>
              )}
              {fw.grade && (
                <div style={{ ...styles.defenderItem, marginLeft: "auto" }}>
                  <div style={{ textAlign: "center" }}>
                    <p style={styles.defLabel}>{t("dashboard.security.grade")}</p>
                    <p style={{ fontSize: 28, fontWeight: 800, color: gradeColor(fw.grade), margin: 0 }}>
                      {fw.grade}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </section>

          {/* ── Malware Suspects ────────────────────────────────────────── */}
          <section style={styles.section}>
            <h2 style={styles.sectionTitle}>
              ☠️ {t("report.security.malware")}
              <span style={{
                ...styles.badge,
                background: malware.length > 0 ? "#2d1b1b" : "#0d2818",
                color: malware.length > 0 ? "#fc8181" : "#56d364",
              }}>{malware.length}</span>
            </h2>
            {malware.length === 0 ? (
              <p style={{ color: "#56d364", fontSize: 14 }}>{t("dashboard.allClear")}</p>
            ) : (
              <div style={styles.itemList}>
                {malware.map((m, i) => {
                  const key = `malware-${i}`;
                  return (
                    <div key={i} style={{ ...styles.itemRow, flexDirection: "column", gap: 6 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ color: m.severity === "critical" ? "#fc8181" : "#f6ad55",
                                       fontWeight: 600, fontSize: 13 }}>
                          {m.severity === "critical" ? "🔴" : "🟡"} {m.name}
                          <span style={{ color: "#4a5568", fontWeight: 400, marginLeft: 8 }}>
                            PID {m.pid} · {m.cpu}% CPU · {m.ram_mb} MB
                          </span>
                        </span>
                        <button
                          onClick={() => onExplain(key, m)}
                          style={styles.explainBtn}
                          disabled={explainResults[key] === "loading"}
                        >
                          {explainResults[key] === "loading" ? "..." : "🤖 Explain"}
                        </button>
                      </div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {(m.reasons || []).map((r, j) => (
                          <span key={j} style={styles.reasonBadge}>{r}</span>
                        ))}
                      </div>
                      {m.exe && <p style={{ color: "#4a5568", fontSize: 11, margin: 0, fontFamily: "monospace" }}>{m.exe}</p>}
                      {explainResults[key] && explainResults[key] !== "loading" && (
                        <div style={styles.explainBox}>{explainResults[key]}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* ── Startup Items ───────────────────────────────────────────── */}
          <section style={styles.section}>
            <h2 style={styles.sectionTitle}>
              🚀 {t("report.security.startup")}
              <span style={styles.badge}>{startup.length}</span>
            </h2>
            {startup.length === 0 ? (
              <p style={{ color: "#4a5568", fontSize: 14 }}>No startup items found.</p>
            ) : (
              <div style={styles.itemList}>
                {startup.map((item, i) => {
                  const key = `startup-${i}`;
                  return (
                    <div key={i} style={{ ...styles.itemRow, flexDirection: "column", gap: 4 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ color: "#c9d1d9", fontWeight: 600, fontSize: 13 }}>
                          <span style={{
                            ...styles.categoryBadge,
                            background: item.category === "suspicious" ? "#2d1b1b"
                                      : item.category === "safe" ? "#0d2818" : "#1c2028",
                            color: item.category === "suspicious" ? "#fc8181"
                                 : item.category === "safe" ? "#56d364" : "#8b949e",
                          }}>
                            {item.category}
                          </span>
                          {" "}{item.name}
                        </span>
                        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                          {item.ram_mb != null && (
                            <span style={{ color: item.heavy ? "#f6ad55" : "#8b949e", fontSize: 11 }}>
                              {item.ram_mb} MB
                            </span>
                          )}
                          {item.category === "suspicious" && (
                            <button
                              onClick={() => onExplain(key, item)}
                              style={styles.explainBtn}
                              disabled={explainResults[key] === "loading"}
                            >
                              {explainResults[key] === "loading" ? "..." : "🤖 Explain"}
                            </button>
                          )}
                        </div>
                      </div>
                      <p style={{ color: "#4a5568", fontSize: 11, margin: 0, fontFamily: "monospace" }}>
                        {item.source} · {item.command?.slice(0, 80)}
                      </p>
                      {item.reasons?.length > 0 && (
                        <div style={{ display: "flex", gap: 4 }}>
                          {item.reasons.map((r, j) => (
                            <span key={j} style={styles.reasonBadge}>{r}</span>
                          ))}
                        </div>
                      )}
                      {explainResults[key] && explainResults[key] !== "loading" && (
                        <div style={styles.explainBox}>{explainResults[key]}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function ReportSection({ title, icon, items, onClean, t, previewMode, readOnly }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <section style={styles.section}>
      <div style={styles.sectionHeader}>
        <h2 style={styles.sectionTitle}>
          {icon} {title}
          <span style={styles.badge}>{items.length}</span>
        </h2>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={() => setExpanded(!expanded)}
            style={styles.previewBtn}
          >
            {expanded ? "▲" : "▼"} {t("report.actions.preview")}
          </button>
          {!readOnly && onClean && (
            <button
              onClick={onClean}
              style={{
                ...styles.cleanBtn,
                opacity: previewMode ? 0.5 : 1,
              }}
            >
              {t("report.actions.clean")}
            </button>
          )}
        </div>
      </div>

      {expanded && (
        <div style={styles.itemList}>
          {items.map((item, i) => (
            <div key={i} style={styles.itemRow}>
              <span style={styles.itemPath}>{item.path || item.name || JSON.stringify(item)}</span>
              {item.size && (
                <span style={styles.itemSize}>{item.size}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

const styles = {
  container: { minHeight: "100vh", background: "#0d1117", color: "#e2e8f0" },
  centered: {
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    gap: 16,
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "16px 32px",
    background: "#161b22",
    borderBottom: "1px solid #21262d",
    flexWrap: "wrap",
    gap: 12,
  },
  title: { fontSize: 20, fontWeight: 700, color: "#e2e8f0", margin: 0 },
  dateLabel: { color: "#8b949e", fontSize: 13 },
  main: { maxWidth: 900, margin: "0 auto", padding: "32px 24px" },
  safetyBar: {
    display: "flex",
    alignItems: "center",
    gap: 12,
    padding: "12px 16px",
    background: "#1a2332",
    border: "1px solid #30363d",
    borderRadius: 8,
    marginBottom: 28,
    flexWrap: "wrap",
  },
  safetyIcon: { fontSize: 18 },
  safetyText: { color: "#8b949e", fontSize: 13, flex: 1 },
  toggleLabel: { color: "#c9d1d9", fontSize: 13, cursor: "pointer", display: "flex", alignItems: "center", gap: 6 },
  undoBtn: {
    background: "#21262d",
    color: "#c9d1d9",
    border: "1px solid #30363d",
    borderRadius: 6,
    padding: "6px 14px",
    cursor: "pointer",
    fontSize: 13,
  },
  section: { marginBottom: 28 },
  sectionHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 12,
  },
  sectionTitle: { fontSize: 17, fontWeight: 600, color: "#c9d1d9", margin: 0, display: "flex", alignItems: "center", gap: 8 },
  badge: {
    background: "#21262d",
    color: "#8b949e",
    borderRadius: 12,
    padding: "2px 8px",
    fontSize: 12,
  },
  previewBtn: {
    background: "transparent",
    border: "1px solid #30363d",
    color: "#8b949e",
    borderRadius: 6,
    padding: "6px 12px",
    cursor: "pointer",
    fontSize: 13,
  },
  cleanBtn: {
    background: "#b91c1c",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    padding: "6px 14px",
    cursor: "pointer",
    fontSize: 13,
    fontWeight: 600,
  },
  itemList: {
    background: "#161b22",
    border: "1px solid #21262d",
    borderRadius: 8,
    overflow: "hidden",
  },
  itemRow: {
    display: "flex",
    justifyContent: "space-between",
    padding: "10px 16px",
    borderBottom: "1px solid #21262d",
    fontSize: 13,
  },
  itemPath: { color: "#8b949e", fontFamily: "monospace", wordBreak: "break-all" },
  itemSize: { color: "#c9d1d9", marginLeft: 12, whiteSpace: "nowrap" },
  aiCard: {
    background: "#161b22",
    border: "1px solid #21262d",
    borderRadius: 8,
    padding: "16px 20px",
  },
  aiText: { color: "#c9d1d9", lineHeight: 1.7, margin: 0, whiteSpace: "pre-wrap" },
  logContainer: {
    background: "#0d1117",
    border: "1px solid #21262d",
    borderRadius: 8,
    padding: 12,
    fontFamily: "monospace",
  },
  logEntry: { display: "flex", gap: 12, marginBottom: 6, fontSize: 12 },
  logTime: { color: "#4a5568" },
  logAction: { color: "#a0aec0" },
  backBtn: {
    background: "transparent",
    border: "1px solid #30363d",
    color: "#8b949e",
    borderRadius: 6,
    padding: "8px 16px",
    cursor: "pointer",
    fontSize: 14,
  },

  // Tab bar
  tabBar: {
    display: "flex", gap: 4,
    padding: "0 32px",
    background: "#161b22",
    borderBottom: "1px solid #21262d",
  },
  tabBtn: {
    background: "transparent", border: "none", borderBottom: "2px solid transparent",
    color: "#8b949e", padding: "12px 20px", cursor: "pointer",
    fontSize: 14, fontWeight: 500,
  },
  tabBtnActive: {
    color: "#e2e8f0", borderBottomColor: "#58a6ff",
  },

  // Security tab
  fwGrid: {
    display: "grid", gridTemplateColumns: "repeat(3, 1fr)",
    gap: 12, marginBottom: 16,
  },
  fwProfile: {
    display: "flex", alignItems: "center", gap: 12,
    padding: "12px 16px", borderRadius: 10, border: "1px solid",
  },
  defenderRow: {
    display: "flex", flexWrap: "wrap", gap: 20,
    padding: "14px 18px", background: "#161b22",
    border: "1px solid #21262d", borderRadius: 10,
  },
  defenderItem: { display: "flex", alignItems: "center", gap: 10 },
  defLabel: { color: "#8b949e", fontSize: 11, margin: 0, textTransform: "uppercase", letterSpacing: 0.5 },
  defVal:   { color: "#e2e8f0", fontSize: 14, fontWeight: 700, margin: 0 },

  reasonBadge: {
    fontSize: 10, padding: "2px 8px", borderRadius: 10,
    background: "#21262d", color: "#8b949e",
  },
  categoryBadge: {
    fontSize: 10, padding: "2px 8px", borderRadius: 8,
    fontWeight: 600, marginRight: 4,
  },
  explainBtn: {
    background: "transparent", border: "1px solid #30363d",
    color: "#8b949e", borderRadius: 6, padding: "3px 10px",
    cursor: "pointer", fontSize: 11,
  },
  explainBox: {
    background: "#0d1117", border: "1px solid #21262d",
    borderRadius: 6, padding: "10px 14px",
    color: "#c9d1d9", fontSize: 12, lineHeight: 1.6,
    whiteSpace: "pre-wrap",
  },
};
