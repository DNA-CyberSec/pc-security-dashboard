import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { signOut } from "firebase/auth";
import {
  collection,
  query,
  where,
  orderBy,
  limit,
  getDocs,
  doc,
  getDoc,
} from "firebase/firestore";
import { auth, db } from "../firebase";

export default function Dashboard({ user }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const isRTL = i18n.language === "he";

  const [lastScan, setLastScan] = useState(null);
  const [healthScore, setHealthScore] = useState(null);
  const [agentConnected, setAgentConnected] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, [user]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadDashboardData = async () => {
    try {
      // Load latest scan
      const scansRef = collection(db, "scans");
      const q = query(
        scansRef,
        where("userId", "==", user.uid),
        orderBy("createdAt", "desc"),
        limit(1)
      );
      const snap = await getDocs(q);
      if (!snap.empty) {
        const scanData = snap.docs[0].data();
        setLastScan(scanData);
        setHealthScore(scanData.healthScore || null);
      }

      // Check agent heartbeat (written by local agent to Firestore)
      const agentRef = doc(db, "agents", user.uid);
      const agentSnap = await getDoc(agentRef);
      if (agentSnap.exists()) {
        const heartbeat = agentSnap.data().lastHeartbeat?.toDate();
        const isAlive = heartbeat && Date.now() - heartbeat.getTime() < 60000; // 60s
        setAgentConnected(isAlive);
      }
    } catch (err) {
      console.error("Dashboard load error:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await signOut(auth);
    navigate("/login");
  };

  const toggleLanguage = () => {
    const newLang = i18n.language === "en" ? "he" : "en";
    i18n.changeLanguage(newLang);
    localStorage.setItem("lang", newLang);
  };

  const getScoreColor = (score) => {
    if (score >= 80) return "#48bb78";
    if (score >= 50) return "#ed8936";
    return "#fc8181";
  };

  const formatDate = (ts) => {
    if (!ts) return t("dashboard.neverScanned");
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

  return (
    <div dir={isRTL ? "rtl" : "ltr"} style={styles.container}>
      {/* Header */}
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <span style={{ fontSize: 24 }}>🛡️</span>
          <h1 style={styles.headerTitle}>{t("app.title")}</h1>
        </div>
        <div style={styles.headerRight}>
          <button onClick={toggleLanguage} style={styles.langToggle}>
            {i18n.language === "en" ? "עברית" : "English"}
          </button>
          <button onClick={() => navigate("/report")} style={styles.navBtn}>
            {t("nav.reports")}
          </button>
          <button onClick={handleLogout} style={styles.logoutBtn}>
            {t("nav.logout")}
          </button>
        </div>
      </header>

      {/* Main content */}
      <main style={styles.main}>
        <h2 style={styles.welcome}>
          {t("dashboard.welcome", { name: user.displayName?.split(" ")[0] })}
        </h2>

        {/* Agent status banner */}
        <div
          style={{
            ...styles.agentBanner,
            background: agentConnected ? "#1a3a2a" : "#2d1b1b",
            borderColor: agentConnected ? "#276749" : "#742a2a",
          }}
        >
          <span style={{ fontSize: 20 }}>{agentConnected ? "🟢" : "🔴"}</span>
          <div>
            <p style={styles.agentTitle}>
              {agentConnected
                ? t("dashboard.agentConnected")
                : t("dashboard.agentDisconnected")}
            </p>
            {!agentConnected && (
              <p style={styles.agentSub}>{t("dashboard.agentInstructions")}</p>
            )}
          </div>
          {!agentConnected && (
            <button style={styles.downloadBtn}>
              {t("dashboard.downloadAgent")}
            </button>
          )}
        </div>

        {/* Stats grid */}
        <div style={styles.grid}>
          {/* Health Score */}
          <div style={styles.card}>
            <p style={styles.cardLabel}>{t("dashboard.healthScore")}</p>
            <p
              style={{
                ...styles.cardValue,
                color: healthScore ? getScoreColor(healthScore) : "#4a5568",
              }}
            >
              {healthScore !== null ? `${healthScore}/100` : "—"}
            </p>
          </div>

          {/* Last Scan */}
          <div style={styles.card}>
            <p style={styles.cardLabel}>{t("dashboard.lastScan")}</p>
            <p style={styles.cardValueSm}>
              {formatDate(lastScan?.createdAt)}
            </p>
          </div>

          {/* Storage */}
          <div style={styles.card}>
            <p style={styles.cardLabel}>{t("dashboard.sections.storage")}</p>
            <p style={styles.cardValueSm}>
              {lastScan?.storage?.freeGB != null
                ? `${lastScan.storage.freeGB} GB free`
                : "—"}
            </p>
          </div>

          {/* Security */}
          <div style={styles.card}>
            <p style={styles.cardLabel}>{t("dashboard.sections.security")}</p>
            <p
              style={{
                ...styles.cardValueSm,
                color:
                  lastScan?.security?.status === "good" ? "#48bb78" : "#fc8181",
              }}
            >
              {lastScan?.security?.status
                ? t(`dashboard.status.${lastScan.security.status}`)
                : "—"}
            </p>
          </div>
        </div>

        {/* Actions */}
        <div style={styles.actions}>
          <button
            onClick={() => navigate("/report")}
            style={styles.primaryBtn}
            disabled={!lastScan}
          >
            {t("nav.reports")}
          </button>
        </div>
      </main>
    </div>
  );
}

const styles = {
  container: { minHeight: "100vh", background: "#0d1117", color: "#e2e8f0" },
  centered: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "16px 32px",
    background: "#161b22",
    borderBottom: "1px solid #21262d",
  },
  headerLeft: { display: "flex", alignItems: "center", gap: 12 },
  headerTitle: { fontSize: 18, fontWeight: 700, color: "#e2e8f0" },
  headerRight: { display: "flex", alignItems: "center", gap: 12 },
  langToggle: {
    background: "transparent",
    border: "1px solid #30363d",
    color: "#8b949e",
    borderRadius: 6,
    padding: "6px 12px",
    cursor: "pointer",
    fontSize: 13,
  },
  navBtn: {
    background: "transparent",
    border: "1px solid #30363d",
    color: "#c9d1d9",
    borderRadius: 6,
    padding: "6px 14px",
    cursor: "pointer",
    fontSize: 14,
  },
  logoutBtn: {
    background: "transparent",
    border: "1px solid #30363d",
    color: "#8b949e",
    borderRadius: 6,
    padding: "6px 14px",
    cursor: "pointer",
    fontSize: 14,
  },
  main: { maxWidth: 900, margin: "0 auto", padding: "40px 24px" },
  welcome: { fontSize: 26, fontWeight: 700, marginBottom: 24, color: "#c9d1d9" },
  agentBanner: {
    display: "flex",
    alignItems: "center",
    gap: 16,
    padding: "16px 20px",
    borderRadius: 10,
    border: "1px solid",
    marginBottom: 32,
  },
  agentTitle: { fontWeight: 600, color: "#e2e8f0", margin: 0 },
  agentSub: { color: "#8b949e", fontSize: 13, margin: "4px 0 0" },
  downloadBtn: {
    marginLeft: "auto",
    background: "#238636",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    padding: "8px 16px",
    cursor: "pointer",
    fontSize: 14,
    fontWeight: 600,
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
    gap: 16,
    marginBottom: 32,
  },
  card: {
    background: "#161b22",
    border: "1px solid #21262d",
    borderRadius: 10,
    padding: "20px 24px",
  },
  cardLabel: { color: "#8b949e", fontSize: 13, margin: "0 0 8px", textTransform: "uppercase", letterSpacing: 1 },
  cardValue: { fontSize: 36, fontWeight: 700, margin: 0 },
  cardValueSm: { fontSize: 18, fontWeight: 600, margin: 0, color: "#c9d1d9" },
  actions: { display: "flex", gap: 12 },
  primaryBtn: {
    background: "#238636",
    color: "#fff",
    border: "none",
    borderRadius: 8,
    padding: "12px 28px",
    fontSize: 15,
    fontWeight: 600,
    cursor: "pointer",
  },
};
