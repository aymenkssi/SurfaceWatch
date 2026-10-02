const dateFmt = new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "short" });

export const formatDate = (value) => (value ? dateFmt.format(new Date(value)) : "—");

// `description` is shown as a summary of what the scan does when hovering the level button.
export const LEVELS = {
  passive: {
    label: "Passif",
    description:
      "Reconnaissance passive : sous-domaines et adresses IP via des sources publiques (certificats, DNS, API). Aucun paquet envoyé vers vos systèmes. Sans vérification.",
  },
  standard: {
    label: "Standard",
    description:
      "Scan actif léger : découverte web (URL), technologies, et risques de configuration (en-têtes HTTP, SPF/DMARC/MTA-STS). Domaine vérifié requis.",
  },
  advanced: {
    label: "Avancé",
    description:
      "Standard + brute-force de surface : sous-domaines (dnsbrute) et répertoires web (webbrute) pour révéler des actifs cachés. Domaine vérifié + consentement.",
    requiresConsent: true,
  },
  deep: {
    label: "Approfondi",
    description:
      "Standard + scan de ports actif (masscan) et identification des services exposés (SSH, SMTP, FTP…). Domaine vérifié + consentement.",
    requiresConsent: true,
  },
};
