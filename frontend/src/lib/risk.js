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

// Rank hosts by their worst finding, then by how many findings they carry.
// Mirrors Hexiosec's "top hosts at risk" view. Derived from the report JSON.
export function topHosts(findings, limit = 10) {
  const byHost = new Map();
  for (const f of findings) {
    const host = f.host || "—";
    const e = byHost.get(host) || { host, total: 0, worst: 5, counts: {} };
    e.total += 1;
    e.worst = Math.min(e.worst, SEVERITY_SCORE[f.severity] ?? 5);
    e.counts[f.severity] = (e.counts[f.severity] ?? 0) + 1;
    byHost.set(host, e);
  }
  return [...byHost.values()]
    .sort((a, b) => a.worst - b.worst || b.total - a.total)
    .slice(0, limit);
}

// A short remediation recommendation for a finding, from its category/description.
export function remediationFor(finding) {
  const cat = categorize(finding);
  const d = finding.description || "";
  if (cat === "Vulnérabilités") {
    return "Mettre à jour le composant vers une version corrigée (voir la CVE associée).";
  }
  if (cat === "Mail") {
    return "Renforcer l'authentification e-mail : SPF, DKIM, DMARC (p=reject) et MTA-STS.";
  }
  if (cat === "Web") {
    if (/clair|cleartext|non chiffr|http:\/\//i.test(d)) {
      return "Forcer HTTPS et rediriger tout trafic en clair.";
    }
    return "Ajouter les en-têtes de sécurité manquants (HSTS, CSP, X-Content-Type-Options, X-Frame-Options).";
  }
  return "Vérifier l'exposition de ce service et restreindre l'accès s'il n'est pas nécessaire.";
}

// One remediation action per finding, worst-first. The id is stable across reloads so a
// per-viewer "done" state can be kept in localStorage (see ScanDetail's ActionsCard).
export function remediationActions(findings) {
  return findings
    .map((f) => ({
      id: `${f.severity}::${f.host || "—"}::${f.description || ""}`,
      host: f.host || "—",
      severity: f.severity,
      description: f.description || "",
      category: categorize(f),
      advice: remediationFor(f),
    }))
    .sort((a, b) => (SEVERITY_SCORE[a.severity] ?? 5) - (SEVERITY_SCORE[b.severity] ?? 5));
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
