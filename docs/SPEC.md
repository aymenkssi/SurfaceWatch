# Spec MVP — SurfaceWatch

## Objectif du MVP
Prouver la chaîne complète sur un domaine vérifié :
**inscription → vérification DNS → scan passif → rapport HTML/PDF**.

## Parcours utilisateur
1. L'utilisateur crée un compte (e-mail + mot de passe ; magic link plus tard).
2. Il ajoute un domaine → le service génère un jeton et affiche l'enregistrement TXT à créer :
   `_surfacewatch-verify.exemple.fr  TXT  "sw-verify=<jeton>"`
3. Il clique sur « Vérifier » → le service interroge le DNS. Statut : `pending` → `verified`.
4. Il lance un scan (niveau `passive` dans le MVP).
5. Le scan passe en file d'attente → `running` → `done` / `failed`.
6. Il consulte le rapport en HTML et le télécharge en PDF.

## Niveaux de scan
| Niveau | Vérification requise | Preset BBOT | Statut |
|---|---|---|---|
| `passive` | Non (mais rate limit) | `subdomain-enum` + `-rf passive` | MVP |
| `standard` | **Oui** | `subdomain-enum` + `web` (léger) | v2 |

## Contenu du rapport (MVP)
- Résumé : nombre de sous-domaines, d'IP, de services web, date du scan
- Liste des sous-domaines découverts (avec IP résolues)
- Findings BBOT éventuels (`FINDING`, `VULNERABILITY`) triés par sévérité
- Limites du scan (passif, sources utilisées) et date d'expiration des données

## Garde-fous
- 1 scan simultané par utilisateur, N scans par jour (configurable)
- Timeout dur sur chaque job (`SCAN_TIMEOUT_SECONDS`)
- Journal d'audit de chaque scan
- Purge automatique des résultats après `RETENTION_DAYS`

## Hors périmètre MVP
Paiement, API publique, planification récurrente, e-mails d'alerte, clés API fournies
par l'utilisateur, module `email-enum`.

## Roadmap
- **v0.1** — squelette, vérification DNS, scan passif, rapport HTML *(en cours)*
- **v0.2** — comptes utilisateurs, Postgres, PDF, rate limit, journal d'audit
- **v0.3** — niveau `standard` (actif) pour domaines vérifiés, purge automatique
- **v0.4** — diff entre deux scans (nouveaux actifs), score de risque
- **v0.5** — croisement technos ↔ CISA KEV / NVD (réutiliser VulnWatch-AI)
- **Plus tard** — scans planifiés, alertes Teams/e-mail, clés API utilisateur

## Questions ouvertes
- Nom définitif du service et nom de domaine
- Hébergeur UE et sa politique vis-à-vis du scan sortant
- Rédaction des CGU (consultation juridique recommandée avant ouverture publique)
