/**
 * Firebase Functions — PC Security Dashboard (public SaaS)
 *
 * Endpoints:
 *  generateAgentToken       — callable (auth required) — creates / returns user's AgentToken
 *  agentHeartbeat           — HTTP POST — agent sends liveness ping
 *  submitScan               — HTTP POST — agent submits full scan data
 *  realtimeHeartbeat        — HTTP POST — agent sends lightweight CPU/RAM every 10s
 *  getScanRecommendations   — callable (auth required) — Claude AI analysis
 *  explainIssue             — callable (auth required) — explain a single issue
 *  onScanCreated            — Firestore trigger — auto-generate AI recommendations
 *
 * Multi-device Firestore structure (per device):
 *  /users/{uid}/devices/{deviceId}               ← device status + summary
 *  /users/{uid}/devices/{deviceId}/scans/{id}    ← full scan data
 *  /users/{uid}/devices/{deviceId}/security/current ← security summary
 *  /users/{uid}/devices/{deviceId}/realtime/current ← live CPU/RAM
 */

const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const admin  = require("firebase-admin");
const crypto = require("crypto");
const { generateRecommendations, explainIssue: claudeExplain } = require("./claude");

admin.initializeApp();
const db = admin.firestore();

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeToken() {
  return "pcg-" + crypto.randomBytes(16).toString("hex");
}

async function resolveToken(token) {
  if (!token || typeof token !== "string") return null;
  const snap = await db.collection("agentTokens").doc(token).get();
  if (!snap.exists) return null;
  snap.ref.update({ lastUsedAt: admin.firestore.FieldValue.serverTimestamp() }).catch(() => {});
  return snap.data().uid;
}

/** Sanitise a device ID coming from the agent — only allow safe chars, max 128. */
function sanitizeDeviceId(raw) {
  if (!raw || typeof raw !== "string") return "default";
  return raw.replace(/[^a-zA-Z0-9_\-]/g, "_").slice(0, 128) || "default";
}

// ── generateAgentToken ────────────────────────────────────────────────────────

exports.generateAgentToken = onCall(async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Authentication required");
  }
  const uid = request.auth.uid;

  const userSnap = await db.collection("users").doc(uid).get();
  if (userSnap.exists && userSnap.data().agentToken) {
    return { token: userSnap.data().agentToken, isNew: false };
  }

  const token = makeToken();
  const batch = db.batch();

  batch.set(db.collection("agentTokens").doc(token), {
    uid,
    createdAt:  admin.firestore.FieldValue.serverTimestamp(),
    lastUsedAt: null,
  });

  batch.set(db.collection("users").doc(uid), {
    agentToken:            token,
    agentTokenCreatedAt:   admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });

  await batch.commit();
  return { token, isNew: true };
});

// ── agentHeartbeat ────────────────────────────────────────────────────────────
// Writes liveness + metadata to /users/{uid}/devices/{deviceId}

exports.agentHeartbeat = onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }
  if (req.method !== "POST")    { res.status(405).json({ error: "POST required" }); return; }

  const { token, deviceId, deviceName, hostname, username, agentVersion, readOnlyMode, os: osName } = req.body;

  const uid = await resolveToken(token);
  if (!uid) return res.status(401).json({ error: "Invalid or unknown AgentToken" });

  const did = sanitizeDeviceId(deviceId || hostname);

  await db.collection("users").doc(uid)
    .collection("devices").doc(did)
    .set({
      deviceId:      did,
      name:          deviceName || hostname || "unknown",
      os:            osName || "Windows",
      lastHeartbeat: admin.firestore.FieldValue.serverTimestamp(),
      last_seen:     admin.firestore.FieldValue.serverTimestamp(),
      agentVersion:  agentVersion || "unknown",
      readOnlyMode:  readOnlyMode !== false,
      online:        true,
    }, { merge: true });

  res.json({ ok: true });
});

// ── submitScan ────────────────────────────────────────────────────────────────
// Writes full scan + security summary to device sub-collections,
// then mirrors a compact summary to the device document for fast listing.

exports.submitScan = onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }
  if (req.method !== "POST")    { res.status(405).json({ error: "POST required" }); return; }

  const { token, scan, deviceId } = req.body;
  if (!scan || typeof scan !== "object") {
    return res.status(400).json({ error: "scan payload required" });
  }

  const uid = await resolveToken(token);
  if (!uid) return res.status(401).json({ error: "Invalid or unknown AgentToken" });

  const did       = sanitizeDeviceId(deviceId || scan.hostname);
  const deviceRef = db.collection("users").doc(uid).collection("devices").doc(did);

  // Write full scan doc
  const scanRef = deviceRef.collection("scans").doc();
  await scanRef.set({
    ...scan,
    uid,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  // Security summary
  const malwareSuspects = scan.malwareSuspects  || [];
  const startupSecurity = scan.startupSecurity  || [];
  const firewallStatus  = scan.firewallStatus   || {};
  const threatCount     = malwareSuspects.filter(m => m.severity === "critical").length;
  const suspiciousCount = malwareSuspects.filter(m => m.severity === "warning").length
                        + startupSecurity.filter(s => s.category === "suspicious").length;

  // Update device document with compact summary (used for multi-device listing)
  await deviceRef.set({
    lastScanAt:             admin.firestore.FieldValue.serverTimestamp(),
    lastScanId:             scanRef.id,
    healthScore:            scan.healthScore ?? null,
    suspiciousProcessCount: (scan.processes     || []).filter(p => p.suspicious).length,
    vulnerabilityCount:     (scan.vulnerabilities || []).length,
    storageWarning:         (scan.storage || []).some(d => d.usedPercent >= 80),
    threatCount,
    suspiciousCount,
    firewallGrade:          firewallStatus.grade ?? null,
    storage:                scan.storage || [],
  }, { merge: true });

  // Write security sub-doc
  await deviceRef.collection("security").doc("current").set({
    scanId:          scanRef.id,
    updatedAt:       admin.firestore.FieldValue.serverTimestamp(),
    malwareSuspects,
    startupSecurity,
    firewallStatus,
    threatCount,
    suspiciousCount,
  });

  res.json({ ok: true, scanId: scanRef.id });
});

// ── realtimeHeartbeat ─────────────────────────────────────────────────────────
// Called every 10 seconds by the agent. Writes live CPU/RAM data.

exports.realtimeHeartbeat = onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }
  if (req.method !== "POST")    { res.status(405).json({ error: "POST required" }); return; }

  const { token, deviceId, cpu_percent, ram_percent, ram_used_gb, ram_total_gb,
          top_processes, temperatures } = req.body;

  const uid = await resolveToken(token);
  if (!uid) return res.status(401).json({ error: "Invalid or unknown AgentToken" });

  const did = sanitizeDeviceId(deviceId);

  const now = admin.firestore.FieldValue.serverTimestamp();

  await db.collection("users").doc(uid)
    .collection("devices").doc(did)
    .collection("realtime").doc("current")
    .set({
      cpu_percent:   cpu_percent   ?? null,
      ram_percent:   ram_percent   ?? null,
      ram_used_gb:   ram_used_gb   ?? null,
      ram_total_gb:  ram_total_gb  ?? null,
      top_processes: top_processes ?? [],
      temperatures:  temperatures  ?? [],
      updatedAt:     now,
    });

  // Keep device online status fresh
  await db.collection("users").doc(uid)
    .collection("devices").doc(did)
    .set({ last_seen: now, online: true }, { merge: true });

  res.json({ ok: true });
});

// ── getScanRecommendations ────────────────────────────────────────────────────

exports.getScanRecommendations = onCall(
  { secrets: ["ANTHROPIC_API_KEY"] },
  async (request) => {
    if (!request.auth) throw new HttpsError("unauthenticated", "Authentication required");

    const { scanId, deviceId = "default", language = "en" } = request.data;
    if (!scanId) throw new HttpsError("invalid-argument", "scanId required");

    const uid     = request.auth.uid;
    const did     = sanitizeDeviceId(deviceId);
    const scanRef = db.collection("users").doc(uid)
                      .collection("devices").doc(did)
                      .collection("scans").doc(scanId);
    const snap    = await scanRef.get();

    if (!snap.exists)            throw new HttpsError("not-found",        "Scan not found");
    if (snap.data().uid !== uid) throw new HttpsError("permission-denied", "Access denied");

    if (snap.data().aiRecommendations && snap.data().aiRecommendationsLang === language) {
      return { recommendations: snap.data().aiRecommendations, cached: true };
    }

    const recommendations = await generateRecommendations(snap.data(), language);

    await scanRef.update({
      aiRecommendations:     recommendations,
      aiRecommendationsLang: language,
      aiGeneratedAt:         admin.firestore.FieldValue.serverTimestamp(),
    });

    return { recommendations, cached: false };
  }
);

// ── explainIssue ──────────────────────────────────────────────────────────────

exports.explainIssue = onCall(
  { secrets: ["ANTHROPIC_API_KEY"] },
  async (request) => {
    if (!request.auth) throw new HttpsError("unauthenticated", "Authentication required");

    const { issue, language = "en" } = request.data;
    if (!issue) throw new HttpsError("invalid-argument", "issue required");

    const explanation = await claudeExplain(issue, language);
    return { explanation };
  }
);

// ── onScanCreated ─────────────────────────────────────────────────────────────
// Triggers when a new scan is written. Auto-generates AI recommendations.

exports.onScanCreated = onDocumentCreated(
  { document: "users/{uid}/devices/{deviceId}/scans/{scanId}", secrets: ["ANTHROPIC_API_KEY"] },
  async (event) => {
    const { uid, deviceId, scanId } = event.params;
    const scan = event.data.data();

    let language = "en";
    try {
      const userSnap = await db.collection("users").doc(uid).get();
      if (userSnap.exists) language = userSnap.data().language || "en";
    } catch (_) {}

    try {
      const recommendations = await generateRecommendations(scan, language);
      await db.collection("users").doc(uid)
        .collection("devices").doc(deviceId)
        .collection("scans").doc(scanId)
        .update({
          aiRecommendations:     recommendations,
          aiRecommendationsLang: language,
          aiGeneratedAt:         admin.firestore.FieldValue.serverTimestamp(),
        });
      console.log(`AI recommendations generated for ${uid}/devices/${deviceId}/scans/${scanId}`);
    } catch (err) {
      console.error(`AI generation failed for ${uid}/devices/${deviceId}/scans/${scanId}:`, err);
    }
  }
);
