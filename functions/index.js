/**
 * Firebase Functions — PC Security Dashboard (public SaaS)
 *
 * Endpoints:
 *  generateAgentToken  — callable (auth required) — creates / returns user's AgentToken
 *  agentHeartbeat      — HTTP POST — agent sends liveness ping
 *  submitScan          — HTTP POST — agent submits full scan data
 *  getScanRecommendations — callable (auth required) — Claude AI analysis
 *  explainIssue        — callable (auth required) — explain a single issue
 *  onScanCreated       — Firestore trigger — auto-generate AI recommendations
 *
 * Data is stored under /users/{uid}/ — strict per-user isolation.
 * Agent tokens are stored in /agentTokens/{token} — not readable by clients.
 */

const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const admin  = require("firebase-admin");
const crypto = require("crypto");
const { generateRecommendations, explainIssue: claudeExplain } = require("./claude");

admin.initializeApp();
const db = admin.firestore();

// ── Token helpers ─────────────────────────────────────────────────────────────

function makeToken() {
  // Format: pcg-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (32 hex chars = 128-bit entropy)
  return "pcg-" + crypto.randomBytes(16).toString("hex");
}

async function resolveToken(token) {
  if (!token || typeof token !== "string") return null;
  const snap = await db.collection("agentTokens").doc(token).get();
  if (!snap.exists) return null;
  // Update last-used timestamp (best effort, don't await)
  snap.ref.update({ lastUsedAt: admin.firestore.FieldValue.serverTimestamp() }).catch(() => {});
  return snap.data().uid;
}

// ── generateAgentToken ────────────────────────────────────────────────────────
// Returns the user's existing token, or creates one if they don't have one yet.

exports.generateAgentToken = onCall(async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Authentication required");
  }
  const uid = request.auth.uid;

  // Check if user already has a token
  const userSnap = await db.collection("users").doc(uid).get();
  if (userSnap.exists && userSnap.data().agentToken) {
    return { token: userSnap.data().agentToken, isNew: false };
  }

  // Generate new token
  const token = makeToken();

  const batch = db.batch();

  // Store token → uid mapping (not readable by client rules)
  batch.set(db.collection("agentTokens").doc(token), {
    uid,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    lastUsedAt: null,
  });

  // Store token reference in user doc
  batch.set(db.collection("users").doc(uid), {
    agentToken: token,
    agentTokenCreatedAt: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });

  await batch.commit();
  return { token, isNew: true };
});

// ── agentHeartbeat ────────────────────────────────────────────────────────────
// Called by the agent every 60 seconds. Validates AgentToken, updates status.

exports.agentHeartbeat = onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }
  if (req.method !== "POST")    { res.status(405).json({ error: "POST required" }); return; }

  const { token, hostname, username, agentVersion, readOnlyMode } = req.body;

  const uid = await resolveToken(token);
  if (!uid) {
    return res.status(401).json({ error: "Invalid or unknown AgentToken" });
  }

  await db.collection("users").doc(uid)
    .collection("agent").doc("status")
    .set({
      lastHeartbeat: admin.firestore.FieldValue.serverTimestamp(),
      hostname:      hostname      || "unknown",
      username:      username      || "unknown",
      agentVersion:  agentVersion  || "unknown",
      readOnlyMode:  readOnlyMode  !== false,
      online:        true,
    }, { merge: true });

  res.json({ ok: true });
});

// ── submitScan ────────────────────────────────────────────────────────────────
// Called by the agent after each scan. Validates AgentToken, writes scan doc.

exports.submitScan = onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }
  if (req.method !== "POST")    { res.status(405).json({ error: "POST required" }); return; }

  const { token, scan } = req.body;
  if (!scan || typeof scan !== "object") {
    return res.status(400).json({ error: "scan payload required" });
  }

  const uid = await resolveToken(token);
  if (!uid) {
    return res.status(401).json({ error: "Invalid or unknown AgentToken" });
  }

  // Write scan under /users/{uid}/scans/{scanId}
  const scanRef = db.collection("users").doc(uid).collection("scans").doc();
  await scanRef.set({
    ...scan,
    uid,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  // Mirror summary to agent/status for fast dashboard reads
  await db.collection("users").doc(uid)
    .collection("agent").doc("status")
    .set({
      lastScanAt:             admin.firestore.FieldValue.serverTimestamp(),
      lastScanId:             scanRef.id,
      healthScore:            scan.healthScore ?? null,
      suspiciousProcessCount: (scan.processes  || []).filter(p => p.suspicious).length,
      vulnerabilityCount:     (scan.vulnerabilities || []).length,
      storageWarning:         (scan.storage || []).some(d => d.usedPercent >= 80),
    }, { merge: true });

  res.json({ ok: true, scanId: scanRef.id });
});

// ── getScanRecommendations ────────────────────────────────────────────────────

exports.getScanRecommendations = onCall(
  { secrets: ["ANTHROPIC_API_KEY"] },
  async (request) => {
    if (!request.auth) throw new HttpsError("unauthenticated", "Authentication required");

    const { scanId, language = "en" } = request.data;
    if (!scanId) throw new HttpsError("invalid-argument", "scanId required");

    const uid     = request.auth.uid;
    const scanRef = db.collection("users").doc(uid).collection("scans").doc(scanId);
    const snap    = await scanRef.get();

    if (!snap.exists)               throw new HttpsError("not-found",        "Scan not found");
    if (snap.data().uid !== uid)    throw new HttpsError("permission-denied", "Access denied");

    // Return cached recommendation if language matches
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
// Triggers on new scan under any user's subcollection.

exports.onScanCreated = onDocumentCreated(
  { document: "users/{uid}/scans/{scanId}", secrets: ["ANTHROPIC_API_KEY"] },
  async (event) => {
    const uid    = event.params.uid;
    const scanId = event.params.scanId;
    const scan   = event.data.data();

    let language = "en";
    try {
      const userSnap = await db.collection("users").doc(uid).get();
      if (userSnap.exists) language = userSnap.data().language || "en";
    } catch (_) {}

    try {
      const recommendations = await generateRecommendations(scan, language);
      await db.collection("users").doc(uid).collection("scans").doc(scanId).update({
        aiRecommendations:     recommendations,
        aiRecommendationsLang: language,
        aiGeneratedAt:         admin.firestore.FieldValue.serverTimestamp(),
      });
      console.log(`AI recommendations generated for ${uid}/scans/${scanId}`);
    } catch (err) {
      console.error(`AI generation failed for ${uid}/scans/${scanId}:`, err);
    }
  }
);
