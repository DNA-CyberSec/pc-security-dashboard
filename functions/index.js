/**
 * Firebase Functions — PC Security Dashboard
 * Handles Claude API calls and business logic securely server-side.
 */

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const admin = require("firebase-admin");
const { generateRecommendations, explainIssue } = require("./claude");

admin.initializeApp();
const db = admin.firestore();

// ── getScanRecommendations ────────────────────────────────────────────────────
// Called from the web app's Report page to get AI analysis of a scan.

exports.getScanRecommendations = onCall(
  { secrets: ["ANTHROPIC_API_KEY"] },
  async (request) => {
    // Auth check — only the scan owner can request recommendations
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Authentication required");
    }

    const { scanId, language = "en" } = request.data;
    if (!scanId) {
      throw new HttpsError("invalid-argument", "scanId is required");
    }

    const scanRef = db.collection("scans").document(scanId);
    const scanSnap = await scanRef.get();

    if (!scanSnap.exists) {
      throw new HttpsError("not-found", "Scan not found");
    }

    const scanData = scanSnap.data();
    if (scanData.userId !== request.auth.uid) {
      throw new HttpsError("permission-denied", "Access denied");
    }

    // Check cache — avoid re-calling Claude for the same scan
    if (scanData.aiRecommendations && scanData.aiRecommendationsLang === language) {
      return { recommendations: scanData.aiRecommendations, cached: true };
    }

    const recommendations = await generateRecommendations(scanData, language);

    // Cache in Firestore
    await scanRef.update({
      aiRecommendations: recommendations,
      aiRecommendationsLang: language,
      aiGeneratedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { recommendations, cached: false };
  }
);

// ── explainIssue ──────────────────────────────────────────────────────────────
// Called when user clicks "explain" on a specific vulnerability or issue.

exports.explainIssue = onCall(
  { secrets: ["ANTHROPIC_API_KEY"] },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Authentication required");
    }

    const { issue, language = "en" } = request.data;
    if (!issue) {
      throw new HttpsError("invalid-argument", "issue is required");
    }

    const explanation = await explainIssue(issue, language);
    return { explanation };
  }
);

// ── onScanCreated ─────────────────────────────────────────────────────────────
// Triggered automatically when agent writes a new scan document.
// Pre-generates AI recommendations in the background.

exports.onScanCreated = onDocumentCreated(
  { document: "scans/{scanId}", secrets: ["ANTHROPIC_API_KEY"] },
  async (event) => {
    const scanData = event.data.data();
    const scanId = event.params.scanId;

    // Detect language preference from user doc
    let language = "en";
    try {
      const userSnap = await db.collection("users").doc(scanData.userId).get();
      if (userSnap.exists) {
        language = userSnap.data().language || "en";
      }
    } catch (e) {
      // Default to English
    }

    try {
      const recommendations = await generateRecommendations(scanData, language);
      await db.collection("scans").doc(scanId).update({
        aiRecommendations: recommendations,
        aiRecommendationsLang: language,
        aiGeneratedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      console.log(`AI recommendations generated for scan ${scanId}`);
    } catch (err) {
      console.error(`Failed to generate recommendations for scan ${scanId}:`, err);
    }
  }
);

// ── Firestore security rules are in firestore.rules (not enforced here) ───────
