// Group findings into the four risk categories Hexiosec-style reports use, and
// derive a simple health score (1 = needs work, 5 = healthy) per category.
// All derived from the report JSON — no extra API call.

export const CATEGORIES = ["Vulnérabilités", "Web", "Mail", "Réseau"];

const MAIL_RE = /spf|dmarc|dkim|mta-sts|smtp/i;
const WEB_RE = /en-tête|hsts|csp|https?|clair|clickjacking|referrer|permissions|x-content|x-frame|header|cookie/i;

export function categorize(finding) {
  if (finding.type === "VULNERABILITY") return "Vulnérabilités";
  const d = finding.description || "";
  if (MAIL_RE.test(d)) return "Mail";
  if (WEB_RE.test(d)) return "Web";
  return "Réseau";
}

// Lower is worse, matching a 1..5 health scale.
const SEVERITY_SCORE = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5 };

export function countByCategory(findings) {
  const counts = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  for (const f of findings) counts[categorize(f)] += 1;
  return counts;
}

// A category's score is driven by its worst finding; overall is the worst category.
export function healthScores(findings) {
  const worst = Object.fromEntries(CATEGORIES.map((c) => [c, 5]));
  for (const f of findings) {
    const cat = categorize(f);
    worst[cat] = Math.min(worst[cat], SEVERITY_SCORE[f.severity] ?? 5);
  }
  const categories = CATEGORIES.map((c) => ({ category: c, score: worst[c] }));
  const overall = categories.reduce((min, c) => Math.min(min, c.score), 5);
  return { categories, overall };
}
