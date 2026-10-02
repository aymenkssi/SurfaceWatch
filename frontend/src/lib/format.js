const dateFmt = new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "short" });

export const formatDate = (value) => (value ? dateFmt.format(new Date(value)) : "—");

export const LEVELS = {
  passive: {
    label: "Passif",
    description: "Sources publiques uniquement, aucun paquet envoyé vers vos systèmes.",
  },
  standard: {
    label: "Standard",
    description: "Scan actif léger. Nécessite un domaine vérifié.",
  },
  advanced: {
    label: "Avancé",
    description: "Scan actif + brute-force de surface (sous-domaines et répertoires web). Domaine vérifié + consentement requis.",
    requiresConsent: true,
  },
  deep: {
    label: "Approfondi",
    description: "Scan de ports et identification des services exposés. Domaine vérifié + consentement requis.",
    requiresConsent: true,
  },
};
