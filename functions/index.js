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

  const resolvedName = deviceName || hostname || "unknown";

  await db.collection("users").doc(uid)
    .collection("devices").doc(did)
    .set({
      deviceId:      did,
      name:          resolvedName,
      os:            osName || "Windows",
      lastHeartbeat: admin.firestore.FieldValue.serverTimestamp(),
      last_seen:     admin.firestore.FieldValue.serverTimestamp(),
      agentVersion:  agentVersion || "unknown",
      readOnlyMode:  readOnlyMode !== false,
      online:        true,
    }, { merge: true });

  // Auto-deduplicate: if another doc has the same COMPUTERNAME, delete it
  if (resolvedName !== "unknown") {
    try {
      const dupeSnap = await db.collection("users").doc(uid)
        .collection("devices")
        .where("name", "==", resolvedName)
        .get();
      if (dupeSnap.size > 1) {
        const batch = db.batch();
        dupeSnap.docs
          .filter(d => d.id !== did)
          .forEach(d => batch.delete(d.ref));
        await batch.commit();
        console.log(`Deduped ${dupeSnap.size - 1} stale device(s) for uid=${uid} name="${resolvedName}"`);
      }
    } catch (e) {
      console.warn("Dedup check failed:", e.message);
    }
  }

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

  // Network fields from full scan (overwrite what realtimeHeartbeat already set)
  const netInfo         = scan.networkInfo || {};
  const netDangerPorts  = (netInfo.open_ports || []).filter(p => p.dangerous).length;

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
    // Network compact fields (from scan's full networkInfo)
    ...(Object.keys(netInfo).length > 0 && {
      network_connected:       netInfo.connected      ?? null,
      network_latency_ms:      netInfo.latency_ms     ?? null,
      network_local_ip:        netInfo.local_ip       ?? null,
      network_rdp_enabled:     netInfo.rdp_enabled    ?? false,
      network_ssh_enabled:     netInfo.ssh_enabled    ?? false,
      network_dangerous_ports: netDangerPorts,
    }),
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
          top_processes, temperatures, network } = req.body;

  const uid = await resolveToken(token);
  if (!uid) return res.status(401).json({ error: "Invalid or unknown AgentToken" });

  const did       = sanitizeDeviceId(deviceId);
  const deviceRef = db.collection("users").doc(uid).collection("devices").doc(did);
  const now       = admin.firestore.FieldValue.serverTimestamp();

  await deviceRef.collection("realtime").doc("current").set({
    cpu_percent:   cpu_percent   ?? null,
    ram_percent:   ram_percent   ?? null,
    ram_used_gb:   ram_used_gb   ?? null,
    ram_total_gb:  ram_total_gb  ?? null,
    top_processes: top_processes ?? [],
    temperatures:  temperatures  ?? [],
    updatedAt:     now,
  });

  // Keep device online status fresh; include Linux-specific fields if present
  const deviceUpdate = {
    last_seen:     now,
    online:        true,
    ...(req.body.uptime_seconds    != null && { uptime_seconds:    req.body.uptime_seconds }),
    ...(req.body.ssh_failed_logins != null && { ssh_failed_logins: req.body.ssh_failed_logins }),
    ...(req.body.firewall_active   != null && { firewall_active:   req.body.firewall_active }),
  };

  // Handle network data
  if (network && typeof network === "object") {
    const netRef   = deviceRef.collection("network").doc("current");
    const netSnap  = await netRef.get();
    const prevHist = netSnap.exists ? (netSnap.data().latency_history || []) : [];

    // Append new latency entry (epoch ms, not serverTimestamp — can't use that in arrays)
    const newEntry = {
      t:          Date.now(),
      latency_ms: network.latency_ms ?? null,
      connected:  network.connected  ?? false,
    };
    const latency_history = [...prevHist, newEntry].slice(-10);

    await netRef.set({
      connected:       network.connected    ?? null,
      latency_ms:      network.latency_ms   ?? null,
      local_ip:        network.local_ip     ?? null,
      public_ip:       network.public_ip    ?? null,
      network_name:    network.network_name ?? null,
      rdp_enabled:     network.rdp_enabled  ?? false,
      ssh_enabled:     network.ssh_enabled  ?? false,
      open_ports:      network.open_ports   ?? [],
      latency_history,
      updatedAt:       now,
    }, { merge: true });

    // Mirror compact fields to device doc for fast listing
    const dangerousPorts = (network.open_ports || []).filter(p => p.dangerous).length;
    Object.assign(deviceUpdate, {
      network_connected:      network.connected    ?? null,
      network_latency_ms:     network.latency_ms   ?? null,
      network_local_ip:       network.local_ip     ?? null,
      network_rdp_enabled:    network.rdp_enabled  ?? false,
      network_ssh_enabled:    network.ssh_enabled  ?? false,
      network_dangerous_ports: dangerousPorts,
    });
  }

  await deviceRef.set(deviceUpdate, { merge: true });

  // Return any pending commands for this device (Linux agent polls these)
  let pendingCommands = [];
  try {
    const cmdSnap = await deviceRef.collection("commands")
      .where("status", "==", "pending").limit(5).get();
    if (!cmdSnap.empty) {
      pendingCommands = cmdSnap.docs.map(d => ({ id: d.id, ...d.data() }));
      // Mark as in_progress so they won't be re-sent
      const batch = db.batch();
      cmdSnap.docs.forEach(d => batch.update(d.ref, { status: "in_progress" }));
      await batch.commit();
    }
  } catch (_) {}

  res.json({ ok: true, pendingCommands });
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

// ── cleanupDuplicateDevices ───────────────────────────────────────────────────
// Callable: groups /users/{uid}/devices by COMPUTERNAME, keeps the most-recently-seen
// entry per name, deletes the rest.  Safe to call at any time.

exports.cleanupDuplicateDevices = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Authentication required");

  const uid        = request.auth.uid;
  const devicesSnap = await db.collection("users").doc(uid).collection("devices").get();

  if (devicesSnap.empty) return { deleted: 0 };

  // Group by COMPUTERNAME (name field)
  const byName = {};
  devicesSnap.docs.forEach(d => {
    const name = (d.data().name || "").toLowerCase().trim();
    if (!name) return;
    if (!byName[name]) byName[name] = [];
    byName[name].push({ id: d.id, ref: d.ref, ts: d.data().last_seen?.toMillis?.() ?? 0 });
  });

  let deleted = 0;
  const batch  = db.batch();

  for (const group of Object.values(byName)) {
    if (group.length <= 1) continue;
    // Sort descending by last_seen — keep index 0 (freshest), delete the rest
    group.sort((a, b) => b.ts - a.ts);
    group.slice(1).forEach(({ ref }) => { batch.delete(ref); deleted++; });
  }

  if (deleted > 0) await batch.commit();
  return { deleted };
});

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

// ── sendLinuxCommand ──────────────────────────────────────────────────────────
// Callable (auth required): queues a command for the Linux agent to execute.
// Supported types: "block_ip" (payload: {ip}), "enable_ufw" (no payload needed)

exports.sendLinuxCommand = onCall(async (request) => {
  if (!request.auth) throw new HttpsError("unauthenticated", "Authentication required");

  const { deviceId, type, ip } = request.data;
  if (!deviceId) throw new HttpsError("invalid-argument", "deviceId required");
  if (!type)     throw new HttpsError("invalid-argument", "type required");

  const ALLOWED_TYPES = ["block_ip", "enable_ufw"];
  if (!ALLOWED_TYPES.includes(type)) {
    throw new HttpsError("invalid-argument", `Unknown command type: ${type}`);
  }
  if (type === "block_ip" && !ip) {
    throw new HttpsError("invalid-argument", "ip required for block_ip");
  }
  // Basic IP validation
  if (ip && !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    throw new HttpsError("invalid-argument", "Invalid IP address format");
  }

  const uid = request.auth.uid;
  const did = sanitizeDeviceId(deviceId);

  const cmdRef = db.collection("users").doc(uid)
    .collection("devices").doc(did)
    .collection("commands").doc();

  await cmdRef.set({
    type,
    ip:        ip || null,
    status:    "pending",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    result:    null,
  });

  return { commandId: cmdRef.id };
});

// ── reportCommandResult ───────────────────────────────────────────────────────
// HTTP POST (agent token auth): agent reports the result of executing a command.

exports.reportCommandResult = onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }
  if (req.method !== "POST")    { res.status(405).json({ error: "POST required" }); return; }

  const { token, deviceId, commandId, success, output } = req.body;

  const uid = await resolveToken(token);
  if (!uid) return res.status(401).json({ error: "Invalid or unknown AgentToken" });

  if (!commandId) return res.status(400).json({ error: "commandId required" });

  const did    = sanitizeDeviceId(deviceId);
  const cmdRef = db.collection("users").doc(uid)
    .collection("devices").doc(did)
    .collection("commands").doc(commandId);

  const snap = await cmdRef.get();
  if (!snap.exists) return res.status(404).json({ error: "Command not found" });

  await cmdRef.update({
    status:      success ? "done" : "error",
    result:      output  || null,
    completedAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  res.json({ ok: true });
});
