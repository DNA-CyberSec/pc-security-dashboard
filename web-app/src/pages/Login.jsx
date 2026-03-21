import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { signInWithPopup } from "firebase/auth";
import { doc, setDoc, getDoc, serverTimestamp } from "firebase/firestore";
import { useNavigate } from "react-router-dom";
import { auth, db, googleProvider } from "../firebase";

export default function Login() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const isRTL = i18n.language === "he";

  const handleGoogleSignIn = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const user = result.user;

      // Create or update user document in Firestore
      const userRef = doc(db, "users", user.uid);
      const userSnap = await getDoc(userRef);
      if (!userSnap.exists()) {
        await setDoc(userRef, {
          uid: user.uid,
          email: user.email,
          displayName: user.displayName,
          photoURL: user.photoURL,
          plan: "free",          // future: "pro"
          planExpiresAt: null,
          createdAt: serverTimestamp(),
          lastLoginAt: serverTimestamp(),
          language: i18n.language,
        });
      } else {
        await setDoc(userRef, { lastLoginAt: serverTimestamp() }, { merge: true });
      }

      navigate("/dashboard");
    } catch (err) {
      console.error(err);
      setError(t("errors.signInFailed"));
    } finally {
      setLoading(false);
    }
  };

  const toggleLanguage = () => {
    const newLang = i18n.language === "en" ? "he" : "en";
    i18n.changeLanguage(newLang);
    localStorage.setItem("lang", newLang);
  };

  return (
    <div dir={isRTL ? "rtl" : "ltr"} style={styles.container}>
      <div style={styles.card}>
        <button onClick={toggleLanguage} style={styles.langToggle}>
          {i18n.language === "en" ? "עברית" : "English"}
        </button>

        <div style={styles.icon}>🛡️</div>
        <h1 style={styles.title}>{t("app.title")}</h1>
        <p style={styles.subtitle}>{t("login.subtitle")}</p>

        {error && <div style={styles.error}>{error}</div>}

        <button
          onClick={handleGoogleSignIn}
          disabled={loading}
          style={styles.googleButton}
        >
          <img
            src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg"
            alt="Google"
            style={styles.googleIcon}
          />
          {loading ? t("common.loading") : t("login.signInWithGoogle")}
        </button>

        <p style={styles.disclaimer}>{t("login.disclaimer")}</p>
      </div>
    </div>
  );
}

const styles = {
  container: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    background: "linear-gradient(135deg, #0f2027, #203a43, #2c5364)",
  },
  card: {
    background: "#1a2332",
    borderRadius: 16,
    padding: "48px 40px",
    width: "100%",
    maxWidth: 400,
    textAlign: "center",
    boxShadow: "0 20px 60px rgba(0,0,0,0.4)",
    position: "relative",
  },
  langToggle: {
    position: "absolute",
    top: 16,
    right: 16,
    background: "transparent",
    border: "1px solid #3a4a5c",
    color: "#a0aec0",
    borderRadius: 8,
    padding: "4px 12px",
    cursor: "pointer",
    fontSize: 13,
  },
  icon: { fontSize: 56, marginBottom: 16 },
  title: { color: "#e2e8f0", fontSize: 22, fontWeight: 700, marginBottom: 8 },
  subtitle: { color: "#718096", fontSize: 14, marginBottom: 32 },
  error: {
    background: "#742a2a",
    color: "#fed7d7",
    borderRadius: 8,
    padding: "10px 16px",
    marginBottom: 20,
    fontSize: 14,
  },
  googleButton: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 12,
    width: "100%",
    padding: "14px 20px",
    background: "#fff",
    color: "#1a202c",
    border: "none",
    borderRadius: 10,
    fontSize: 15,
    fontWeight: 600,
    cursor: "pointer",
    transition: "opacity 0.2s",
  },
  googleIcon: { width: 20, height: 20 },
  disclaimer: { color: "#4a5568", fontSize: 12, marginTop: 24 },
};
