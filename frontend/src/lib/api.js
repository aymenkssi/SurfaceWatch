import axios from "axios";

const TOKEN_KEY = "sw_token";

// Same-origin by default (FastAPI serves the built app; Vite proxies /api in dev).
export const api = axios.create({
  baseURL: `${import.meta.env.VITE_API_URL ?? ""}/api`,
});

export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (token) => localStorage.setItem(TOKEN_KEY, token),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};

api.interceptors.request.use((config) => {
  const token = tokenStore.get();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && tokenStore.get()) {
      tokenStore.clear();
      window.dispatchEvent(new Event("sw:logout"));
    }
    return Promise.reject(error);
  }
);

// Backend error details are in English; show French messages in the UI.
const MESSAGES = {
  "email already registered": "Un compte existe déjà avec cet e-mail.",
  "invalid email or password": "E-mail ou mot de passe incorrect.",
  "active scans require a verified domain": "Un scan actif nécessite un domaine vérifié.",
  "a scan is already running": "Un scan est déjà en cours. Attendez qu'il se termine.",
  "daily scan quota reached": "Quota de scans atteint pour aujourd'hui.",
  "scan queue unavailable": "Le service de scan est indisponible. Réessayez plus tard.",
  "token expired, request a new one": "Le jeton a expiré : générez-en un nouveau.",
  "scan still running": "Le scan est encore en cours.",
  "admin only": "Accès réservé aux administrateurs.",
  "domain already verified": "Ce domaine est déjà vérifié.",
  "domain not verified": "Ce domaine n'est pas vérifié.",
  "email is not configured": "L'envoi d'e-mails n'est pas activé sur ce serveur.",
  "invalid or expired reset link": "Ce lien est invalide, déjà utilisé ou expiré : faites une nouvelle demande.",
  "wrong password": "Mot de passe incorrect.",
  "wait for the running scan to finish": "Un scan est en cours : attendez sa fin avant de supprimer votre compte.",
};

export function errorMessage(error, fallback = "Une erreur est survenue.") {
  const detail = error?.response?.data?.detail;
  if (typeof detail === "string") {
    if (detail.startsWith("smtp error: ")) return `Échec de l'envoi : ${detail.slice(12)}`;
    return MESSAGES[detail] ?? detail;
  }
  if (Array.isArray(detail)) return "Données invalides : vérifiez le formulaire.";
  return fallback;
}

export async function downloadFile(url, filename) {
  const res = await api.get(url, { responseType: "blob" });
  const href = URL.createObjectURL(res.data);
  const a = Object.assign(document.createElement("a"), { href, download: filename });
  a.click();
  URL.revokeObjectURL(href);
}
