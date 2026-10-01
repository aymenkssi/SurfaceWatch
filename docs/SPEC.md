# Spec MVP — SurfaceAttackWatch

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
| Niveau | Vérification requise | Consentement | Preset BBOT | Statut |
|---|---|---|---|---|
| `passive` | Non (mais rate limit) | Non | `subdomain-enum` + `-rf passive` | MVP |
| `standard` | **Oui** | Non | `subdomain-enum` + `web` (léger) | v0.3 |
| `advanced` | **Oui** (revérifiée au lancement) | **Oui** (explicite, journalisé) | `subdomain-enum` + `web` + `-m dnsbrute webbrute` | v0.4 |

Le niveau `advanced` active de la **force brute de surface** (sous-domaines via `dnsbrute`,
répertoires web via `webbrute`). Il reste sans force brute d'authentification (`legba`,
`medusa` — flag `invasive`), sans `iis-shortnames`/`web-heavy` ni `paramminer`. Il a son
propre quota journalier (`ADVANCED_MAX_SCANS_PER_DAY`, défaut 1) et son propre timeout
(`ADVANCED_SCAN_TIMEOUT_SECONDS`, défaut 3600 s), plus stricts que les niveaux inférieurs.

## Contenu du rapport (MVP)
- Résumé : nombre de sous-domaines, d'IP, de services web, date du scan
- Liste des sous-domaines découverts (avec IP résolues)
- Findings BBOT éventuels (`FINDING`, `VULNERABILITY`) triés par sévérité
- Limites du scan (passif, sources utilisées) et date d'expiration des données

## Garde-fous
- 1 scan simultané par utilisateur, N scans par jour (configurable)
- Niveau `advanced` : preuve de propriété revérifiée au lancement, consentement explicite
  obligatoire et journalisé, quota journalier et timeout dédiés plus stricts
- Timeout dur sur chaque job (`SCAN_TIMEOUT_SECONDS`, `ADVANCED_SCAN_TIMEOUT_SECONDS`)
- Journal d'audit de chaque scan (consentement inclus)
- Purge automatique des résultats après `RETENTION_DAYS`

## Administration (`/admin`)
- Réservée aux comptes `is_admin` (403 sinon, côté API). Le rôle ne s'attribue **que** depuis
  le serveur : `python -m app.cli make-admin <email>` (`revoke-admin` pour le retirer).
- Statistiques : utilisateurs (total, nouveaux 7/30 j), domaines (vérifiés DNS / manuels,
  en attente), scans demandés (24 h / 7 j / 30 j / total, par niveau, par jour sur 30 j,
  issus du journal d'audit donc non purgés), scans en cours, statuts et durée moyenne
  (fenêtre de rétention), journal d'audit récent.
- **Validation manuelle de propriété** : exception à la règle 1. Un admin peut marquer un
  domaine comme vérifié sans enregistrement TXT, avec un motif obligatoire. Le domaine est
  marqué `verification_method = manual` (+ `verified_by`) et l'action est journalisée
  (`domain.manual_verify` : admin, domaine, propriétaire, motif, IP, date). Un admin peut
  aussi retirer une vérification (`domain.revoke_verify`), ce qui régénère un jeton.

## Compte et e-mails
- **Suppression de compte** depuis « Mon compte » : confirmation par le mot de passe, refusée
  pendant un scan en cours. Efface compte, domaines, scans et jetons de réinitialisation ;
  l'entrée `account.deleted` est écrite au journal d'audit avant l'effacement (le journal est
  conservé, règle 4). Un e-mail de confirmation est envoyé si le SMTP est configuré.
- **Mot de passe oublié** : lien par e-mail, jeton aléatoire stocké haché (SHA-256), valable
  60 min, usage unique, seul le dernier lien demandé fonctionne, 3 demandes max par heure.
  Réponse identique que le compte existe ou non. La réinitialisation ferme toutes les sessions
  ouvertes et envoie un e-mail d'avertissement. Journal : `account.password_reset_requested`,
  `account.password_reset`.
- **Notifications** : e-mail de fin (ou d'échec) de scan, avec un lien seulement (pas de
  résultats dans l'e-mail). Désactivable dans « Mon compte ».
- **SMTP** fourni par l'exploitant via l'env (`SMTP_*`) ; sans SMTP, ces fonctions sont masquées.

## Hors périmètre MVP
Paiement, API publique, planification récurrente, e-mails d'alerte, clés API fournies
par l'utilisateur, module `email-enum`.

## Roadmap
- **v0.1** — squelette, vérification DNS, scan passif, rapport HTML *(en cours)*
- **v0.2** — comptes utilisateurs, Postgres, PDF, rate limit, journal d'audit
- **v0.3** — niveau `standard` (actif) pour domaines vérifiés, purge automatique
- **v0.4** — niveau `advanced` (force brute de surface, consentement + quota dédiés) ;
  diff entre deux scans (nouveaux actifs), score de risque
- **v0.5** — croisement technos ↔ CISA KEV / NVD (réutiliser VulnWatch-AI)
- **Plus tard** — scans planifiés, alertes Teams/e-mail, clés API utilisateur

## Questions ouvertes
- Nom définitif du service et nom de domaine
- Hébergeur UE et sa politique vis-à-vis du scan sortant
- Rédaction des CGU (consultation juridique recommandée avant ouverture publique)
