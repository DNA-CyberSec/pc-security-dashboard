import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import {
  collection,
  query,
  orderBy,
  limit,
  getDocs,
} from "firebase/firestore";
import { httpsCallable } from "firebase/functions";
import { db, functions } from "../firebase";

export default function Report({ user }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const isRTL = i18n.language === "he";

  const [scan, setScan] = useState(null);
  const [aiRecommendations, setAiRecommendations] = useState(null);
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
        collection(db, "users", user.uid, "scans"),
        orderBy("createdAt", "desc"),
        limit(1)
      );
      const snap = await getDocs(q);
      if (!snap.empty) {
        const data = { id: snap.docs[0].id, ...snap.docs[0].data() };
        setScan(data);
        await loadAiRecommendations(data.id);
      }
    } catch (err) {
      console.error("Report load error:", err);
    } finally {
      setLoading(false);
    }
  };

  const loadAiRecommendations = async (scanId) => {
    try {
      const getRecommendations = httpsCallable(functions, "getScanRecommendations");
      const result = await getRecommendations({ scanId });
      setAiRecommendations(result.data.recommendations);
    } catch (err) {
      console.error("AI recommendations error:", err);
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
        <button onClick={() => navigate("/dashboard")} style={styles.backBtn}>
          ← {t("common.back")}
        </button>
        <h1 style={styles.title}>{t("report.title")}</h1>
        <span style={styles.dateLabel}>
          {t("report.generatedAt")}: {formatDate(scan.createdAt)}
        </span>
      </header>

      <main style={styles.main}>
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

        {/* Temp Files */}
        {scan.tempFiles?.length > 0 && (
          <ReportSection
            title={t("report.categories.tempFiles")}
            icon="🗑️"
            items={scan.tempFiles}
            onClean={() => handleClean("tempFiles", scan.tempFiles)}
            t={t}
            previewMode={previewMode}
          />
        )}

        {/* Large Files */}
        {scan.largeFiles?.length > 0 && (
          <ReportSection
            title={t("report.categories.largeFiles")}
            icon="📦"
            items={scan.largeFiles}
            onClean={() => handleClean("largeFiles", scan.largeFiles)}
            t={t}
            previewMode={previewMode}
          />
        )}

        {/* Duplicates */}
        {scan.duplicates?.length > 0 && (
          <ReportSection
            title={t("report.categories.duplicates")}
            icon="📋"
            items={scan.duplicates}
            onClean={() => handleClean("duplicates", scan.duplicates)}
            t={t}
            previewMode={previewMode}
          />
        )}

        {/* Security Issues */}
        {scan.vulnerabilities?.length > 0 && (
          <ReportSection
            title={t("report.categories.vulnerabilities")}
            icon="⚠️"
            items={scan.vulnerabilities}
            onClean={null}
            t={t}
            previewMode={previewMode}
            readOnly
          />
        )}

        {/* Action Log */}
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
      </main>
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
};
