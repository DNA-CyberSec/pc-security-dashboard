/**
 * claude.js — Claude API integration
 * Wraps Anthropic SDK calls with structured prompts for PC security analysis.
 */

const Anthropic = require("@anthropic-ai/sdk");

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const SYSTEM_PROMPT = `You are a PC health and security expert assistant.
You analyze scan results from Windows computers and provide clear, actionable recommendations.
Your recommendations must be:
- Prioritized by impact (critical issues first)
- Safe and non-destructive in phrasing
- Understandable to non-technical users
- Concise (max 5 bullet points unless severity warrants more)
Always mention that a backup is created before any cleanup action.`;

/**
 * Generates AI recommendations for a scan result.
 * @param {Object} scanData - Firestore scan document data
 * @param {string} language - "en" or "he"
 * @returns {Promise<string>} - Markdown-formatted recommendations
 */
async function generateRecommendations(scanData, language = "en") {
  const langInstruction =
    language === "he"
      ? "Respond in Hebrew (עברית). Use RTL-friendly formatting."
      : "Respond in English.";

  const summary = buildScanSummary(scanData);

  const message = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 1024,
    system: SYSTEM_PROMPT,
    messages: [
      {
        role: "user",
        content: `${langInstruction}

Analyze this PC scan result and provide prioritized recommendations:

${summary}

Format your response as a clear, numbered list of actionable recommendations.`,
      },
    ],
  });

  return message.content[0].text;
}

/**
 * Generates a natural-language explanation of a specific issue.
 * @param {Object} issue - A single vulnerability or finding
 * @param {string} language - "en" or "he"
 * @returns {Promise<string>}
 */
async function explainIssue(issue, language = "en") {
  const langInstruction =
    language === "he" ? "Respond in Hebrew." : "Respond in English.";

  const message = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 512,
    system: SYSTEM_PROMPT,
    messages: [
      {
        role: "user",
        content: `${langInstruction}

Explain this PC issue to a non-technical user in 2-3 sentences and suggest what to do:

Issue: ${JSON.stringify(issue)}`,
      },
    ],
  });

  return message.content[0].text;
}

/**
 * Builds a human-readable summary from raw scan data for the Claude prompt.
 */
function buildScanSummary(scan) {
  const lines = [];

  if (scan.healthScore != null) {
    lines.push(`Overall health score: ${scan.healthScore}/100`);
  }

  const storage = scan.storage || {};
  if (storage.usedPercent != null) {
    lines.push(`Disk usage: ${storage.usedPercent}% used (${storage.freeGB} GB free of ${storage.totalGB} GB)`);
  }

  const tempCount = (scan.tempFiles || []).length;
  if (tempCount > 0) {
    lines.push(`Temporary files found: ${tempCount} files`);
  }

  const largeCount = (scan.largeFiles || []).length;
  if (largeCount > 0) {
    const top = scan.largeFiles.slice(0, 3).map((f) => `${f.path} (${f.size})`).join(", ");
    lines.push(`Large files (>${500}MB): ${largeCount} found. Top: ${top}`);
  }

  const dupCount = (scan.duplicates || []).length;
  if (dupCount > 0) {
    lines.push(`Duplicate files: ${dupCount} groups found`);
  }

  const vulns = scan.vulnerabilities || [];
  if (vulns.length > 0) {
    lines.push(`Security vulnerabilities: ${vulns.map((v) => v.description).join("; ")}`);
  }

  const outdated = (scan.outdatedSoftware || []).length;
  if (outdated > 0) {
    lines.push(`Pending Windows updates: ${outdated}`);
  }

  const browser = scan.browserData || {};
  const browsers = Object.entries(browser)
    .filter(([, d]) => d && (d.cookies || d.history))
    .map(([name, d]) => `${name}: ${d.cookies || 0} cookies, ${d.history || 0} history entries`);
  if (browsers.length > 0) {
    lines.push(`Browser data: ${browsers.join("; ")}`);
  }

  return lines.join("\n");
}

module.exports = { generateRecommendations, explainIssue };
