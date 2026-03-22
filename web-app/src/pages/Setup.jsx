import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { httpsCallable } from "firebase/functions";
import { functions } from "../firebase";

const AGENT_DOWNLOAD_URL =
  "https://github.com/DNA-CyberSec/pc-security-dashboard/releases/latest/download/PCGuard-Setup.exe";
const LINUX_INSTALL_CMD  = "curl -sSL https://pcguard-rami.web.app/install.sh | bash";

export default function Setup({ user }) {
  const { t, i18n } = useTranslation();
  const navigate     = useNavigate();
  const isRTL        = i18n.language === "he";

  const [token,         setToken]         = useState("");
  const [copied,        setCopied]        = useState(false);
  const [copiedLinux,   setCopiedLinux]   = useState(false);
  const [loading,       setLoading]       = useState(true);
  const [error,         setError]         = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const fn = httpsCallable(functions, "generateAgentToken");
        const result = await fn();
        setToken(result.data.token);
      } catch (err) {
        console.error(err);
        setError(t("setup.tokenError"));
      } finally {
        setLoading(false);
      }
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const copyText = async (text, setDone) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const el = document.createElement("textarea");
      el.value = text;
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
    }
    setDone(true);
    setTimeout(() => setDone(false), 3000);
  };

  const copyToken = () => copyText(token, setCopied);

  const toggleLang = () => {
    const l = i18n.language === "en" ? "he" : "en";
    i18n.changeLanguage(l);
    localStorage.setItem("lang", l);
  };

  return (
    <div dir={isRTL ? "rtl" : "ltr"} style={s.page}>

      {/* ── Top bar ─────────────────────────────────────────── */}
      <header style={s.topbar}>
        <div style={s.topbarLeft}>
          <span style={{ fontSize: 20 }}>🛡️</span>
          <span style={s.topbarTitle}>{t("app.title")}</span>
        </div>
        <div style={s.topbarRight}>
          <button onClick={toggleLang}  style={s.ghostBtn}>{i18n.language === "en" ? "עברית" : "English"}</button>
          <button onClick={() => navigate("/dashboard")} style={s.ghostBtn}>{t("setup.skipForNow")} →</button>
        </div>
      </header>

      <main style={s.main}>
        {/* Hero */}
        <div style={s.hero}>
          <div style={s.heroIcon}>🖥️</div>
          <h1 style={s.heroTitle}>{t("setup.heroTitle")}</h1>
          <p style={s.heroSub}>{t("setup.heroSub")}</p>
        </div>

        {/* Steps */}
        <div style={s.steps}>

          {/* Step 1 — Copy token */}
          <div style={s.stepCard}>
            <div style={s.stepBadge}>1</div>
            <div style={s.stepContent}>
              <h2 style={s.stepTitle}>{t("setup.step1Title")}</h2>
              <p style={s.stepDesc}>{t("setup.step1Desc")}</p>

              {loading && <div style={s.tokenSkeleton}>{t("common.loading")}</div>}
              {error   && <div style={s.errorBox}>{error}</div>}
              {!loading && !error && (
                <div style={s.tokenBlock}>
                  <code style={s.tokenCode}>{token}</code>
                  <button
                    onClick={copyToken}
                    style={{ ...s.copyBtn, ...(copied ? s.copyBtnDone : {}) }}
                  >
                    {copied ? "✓ " + t("setup.copied") : "📋 " + t("setup.copy")}
                  </button>
                </div>
              )}
              <p style={s.tokenNote}>{t("setup.tokenNote")}</p>
            </div>
          </div>

          {/* Download CTA */}
          <div style={s.downloadCard}>
            <p style={s.downloadLabel}>{t("setup.step2Desc")}</p>
            <a href={AGENT_DOWNLOAD_URL} style={s.downloadBigBtn} download>
              ⬇&nbsp;&nbsp;{t("setup.downloadBtn")}
            </a>
            <p style={s.downloadNote}>{t("setup.windowsOnly")}</p>
          </div>

          {/* Step 2 — Run installer */}
          <div style={s.stepCard}>
            <div style={s.stepBadge}>2</div>
            <div style={s.stepContent}>
              <h2 style={s.stepTitle}>{t("setup.step3Title")}</h2>
              <p style={s.stepDesc}>{t("setup.step3Desc")}</p>
              <div style={s.miniSteps}>
                <div style={s.miniStep}>▶&nbsp; {t("setup.step3a")}</div>
                <div style={s.miniStep}>📋&nbsp; {t("setup.step3b")}</div>
                <div style={s.miniStep}>✅&nbsp; {t("setup.step3c")}</div>
              </div>
            </div>
          </div>

          {/* Step 3 — Come back */}
          <div style={{ ...s.stepCard, borderColor: "#238636", background: "#0d2818" }}>
            <div style={{ ...s.stepBadge, background: "#238636" }}>3</div>
            <div style={s.stepContent}>
              <h2 style={{ ...s.stepTitle, color: "#56d364" }}>{t("setup.step4Title")}</h2>
              <p style={{ ...s.stepDesc, color: "#8b949e" }}>{t("setup.step4Desc")}</p>
              <button onClick={() => navigate("/dashboard")} style={s.dashBtn}>
                {t("setup.goToDashboard")} →
              </button>
            </div>
          </div>

          {/* ── Linux separator ───────────────────────────────────────── */}
          <div style={s.divider}>
            <span style={s.dividerText}>— {t("linux.linuxServer")} —</span>
          </div>

          {/* Linux hero */}
          <div style={{ ...s.downloadCard, borderColor: "#30363d", background: "#161b22" }}>
            <div style={{ fontSize: 48, marginBottom: 8 }}>🐧</div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#e2e8f0", margin: "0 0 8px" }}>
              {t("linux.installCmd")}
            </h2>
            <p style={{ fontSize: 14, color: "#8b949e", margin: "0 0 20px", maxWidth: 480 }}>
              {t("linux.installDesc")}
            </p>

            {/* Steps */}
            <div style={{ ...s.miniSteps, width: "100%", maxWidth: 520, marginBottom: 20 }}>
              <div style={s.miniStep}>1. {t("linux.installStep1")}</div>
              <div style={s.miniStep}>2. {t("linux.installStep2")}</div>
            </div>

            {/* Install command */}
            <div style={s.cmdBlock}>
              <code style={s.cmdCode}>{LINUX_INSTALL_CMD}</code>
              <button
                onClick={() => copyText(LINUX_INSTALL_CMD, setCopiedLinux)}
                style={{ ...s.copyBtn, ...(copiedLinux ? s.copyBtnDone : {}), flexShrink: 0 }}
              >
                {copiedLinux ? "✓ " + t("setup.copied") : "📋 " + t("setup.copy")}
              </button>
            </div>

            <div style={{ ...s.miniSteps, width: "100%", maxWidth: 520, marginTop: 8 }}>
              <div style={s.miniStep}>3. {t("linux.installStep3")}</div>
            </div>

            <p style={{ fontSize: 11, color: "#4a5568", marginTop: 12 }}>
              Ubuntu 18+ · Debian 10+ · Requires root (sudo)
            </p>
          </div>

        </div>
      </main>
    </div>
  );
}

const s = {
  page:    { minHeight: "100vh", background: "#0d1117", color: "#e2e8f0" },
  topbar:  {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "14px 32px", background: "#161b22", borderBottom: "1px solid #21262d",
  },
  topbarLeft:  { display: "flex", alignItems: "center", gap: 10 },
  topbarTitle: { fontWeight: 700, fontSize: 16, color: "#e2e8f0" },
  topbarRight: { display: "flex", gap: 10 },
  ghostBtn: {
    background: "transparent", border: "1px solid #30363d", color: "#8b949e",
    borderRadius: 6, padding: "6px 14px", cursor: "pointer", fontSize: 13,
  },
  main:  { maxWidth: 700, margin: "0 auto", padding: "40px 20px" },
  hero:  { textAlign: "center", marginBottom: 40 },
  heroIcon:  { fontSize: 56, marginBottom: 14 },
  heroTitle: { fontSize: 26, fontWeight: 700, margin: "0 0 10px", color: "#e2e8f0" },
  heroSub:   { fontSize: 15, color: "#8b949e", lineHeight: 1.6, margin: 0 },
  steps: { display: "flex", flexDirection: "column", gap: 16 },
  stepCard: {
    display: "flex", gap: 20,
    background: "#161b22", border: "1px solid #21262d",
    borderRadius: 14, padding: "24px 28px",
  },
  stepBadge: {
    width: 36, height: 36, borderRadius: "50%",
    background: "#1f6feb", color: "#fff",
    display: "flex", alignItems: "center", justifyContent: "center",
    fontWeight: 700, fontSize: 16, flexShrink: 0, marginTop: 2,
  },
  stepContent: { flex: 1 },
  stepTitle:   { fontSize: 17, fontWeight: 700, color: "#e2e8f0", margin: "0 0 6px" },
  stepDesc:    { fontSize: 13, color: "#8b949e", margin: "0 0 18px", lineHeight: 1.7 },
  tokenBlock:  { display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", marginBottom: 10 },
  tokenCode: {
    fontFamily: "monospace", fontSize: 14,
    background: "#0d1117", border: "1px solid #30363d",
    borderRadius: 8, padding: "10px 16px",
    color: "#58a6ff", letterSpacing: 1, wordBreak: "break-all", flex: 1,
  },
  copyBtn: {
    background: "#21262d", border: "1px solid #30363d",
    color: "#c9d1d9", borderRadius: 8,
    padding: "10px 20px", cursor: "pointer",
    fontSize: 13, fontWeight: 600, whiteSpace: "nowrap",
    transition: "all 0.2s",
  },
  copyBtnDone: { background: "#1a3a2a", borderColor: "#238636", color: "#56d364" },
  tokenNote:   { fontSize: 12, color: "#4a5568", margin: 0 },
  tokenSkeleton: {
    background: "#21262d", borderRadius: 8,
    padding: "10px 16px", color: "#4a5568", fontSize: 13,
    marginBottom: 10,
  },
  errorBox: {
    background: "#2d1b1b", border: "1px solid #742a2a",
    borderRadius: 8, padding: "12px 16px", color: "#fc8181",
    fontSize: 13, marginBottom: 10,
  },
  downloadCard: {
    background: "#0d2818", border: "2px solid #238636",
    borderRadius: 14, padding: "28px 32px",
    display: "flex", flexDirection: "column", alignItems: "center", gap: 12,
    textAlign: "center",
  },
  downloadLabel: { fontSize: 14, color: "#8b949e", margin: 0 },
  downloadBigBtn: {
    display: "inline-flex", alignItems: "center", justifyContent: "center",
    background: "#238636", color: "#fff",
    borderRadius: 12, padding: "16px 40px",
    textDecoration: "none", fontSize: 18, fontWeight: 700,
    width: "100%", maxWidth: 420, letterSpacing: 0.3,
    boxShadow: "0 4px 24px rgba(35,134,54,0.35)",
  },
  downloadNote: { fontSize: 12, color: "#4a5568", margin: 0 },
  downloadBtn: {
    display: "inline-flex", alignItems: "center",
    background: "#238636", color: "#fff",
    borderRadius: 10, padding: "13px 28px",
    textDecoration: "none", fontSize: 15, fontWeight: 700,
    marginBottom: 10,
  },
  miniSteps: { display: "flex", flexDirection: "column", gap: 8 },
  miniStep:  {
    background: "#0d1117", border: "1px solid #21262d",
    borderRadius: 8, padding: "10px 14px",
    fontSize: 13, color: "#c9d1d9",
  },
  dashBtn: {
    background: "#1f6feb", color: "#fff", border: "none",
    borderRadius: 8, padding: "13px 28px", cursor: "pointer",
    fontSize: 15, fontWeight: 700, marginTop: 4,
  },
  divider: {
    display: "flex", alignItems: "center", justifyContent: "center",
    margin: "8px 0",
  },
  dividerText: { fontSize: 13, color: "#4a5568" },
  cmdBlock: {
    display: "flex", alignItems: "center", gap: 12, width: "100%",
    maxWidth: 520, flexWrap: "wrap",
  },
  cmdCode: {
    fontFamily: "monospace", fontSize: 13,
    background: "#0d1117", border: "1px solid #30363d",
    borderRadius: 8, padding: "10px 14px",
    color: "#48bb78", wordBreak: "break-all", flex: 1,
  },
};
