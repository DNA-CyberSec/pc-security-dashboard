import React, { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { onAuthStateChanged } from "firebase/auth";
import { auth } from "./firebase";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import DeviceDashboard from "./pages/DeviceDashboard";
import Report from "./pages/Report";
import Setup from "./pages/Setup";
import Admin from "./pages/Admin";
import Footer from "./components/Footer";
import "./i18n";

function ProtectedRoute({ user, children }) {
  if (user === undefined) return <div style={{ color: "#e2e8f0", padding: 40 }}>Loading...</div>;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  const [user, setUser] = useState(undefined); // undefined = loading

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (u) => setUser(u || null));
    return unsubscribe;
  }, []);

  return (
    <BrowserRouter>
      <div style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
        <div style={{ flex: 1 }}>
          <Routes>
            <Route
              path="/login"
              element={user ? <Navigate to="/dashboard" replace /> : <Login />}
            />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute user={user}>
                  <Dashboard user={user} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/device/:deviceId"
              element={
                <ProtectedRoute user={user}>
                  <DeviceDashboard user={user} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/device/:deviceId/report"
              element={
                <ProtectedRoute user={user}>
                  <Report user={user} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/report"
              element={
                <ProtectedRoute user={user}>
                  <Report user={user} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/setup"
              element={
                <ProtectedRoute user={user}>
                  <Setup user={user} />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin"
              element={
                <ProtectedRoute user={user}>
                  <Admin user={user} />
                </ProtectedRoute>
              }
            />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </div>
        <Footer />
      </div>
    </BrowserRouter>
  );
}
