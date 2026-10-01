# SurfaceAttackWatch — contexte pour Claude Code

> Nom du service : **SurfaceAttackWatch** (surfaceattackwatch.com), ex-« SurfaceWatch ». Les
> identifiants techniques (`surfacewatch` : paquet, base, conteneurs, `_surfacewatch-verify`)
> restent inchangés. Service web **gratuit** de scan EASM (External Attack Surface Management)
> basé sur **BBOT** (Black Lantern Security), avec génération de rapports.

## Le projet en une phrase
Un utilisateur prouve qu'il possède un domaine, lance un scan de sa surface d'attaque
externe, et récupère un rapport lisible (HTML/PDF) avec les actifs découverts, les risques
et leur priorisation.

## Règles NON négociables (légal / éthique)
Ces règles passent avant toute fonctionnalité. Ne jamais les contourner, même « pour tester ».

1. **Aucun scan actif sans preuve de propriété du domaine.**
   - Méthode principale : enregistrement DNS TXT `_surfacewatch-verify.<domaine>` contenant un jeton unique.
   - Le jeton est lié à un utilisateur ET à un domaine, et expire.
   - Seule exception : validation manuelle par un **admin** (`/admin`), motif obligatoire,
     journalisée (`domain.manual_verify`) et marquée `verification_method = manual`.
     Le rôle admin ne s'attribue qu'en CLI serveur (`python -m app.cli make-admin`).
   - Contexte : art. 323-1 et 323-3-1 du Code pénal (accès frauduleux, mise à disposition d'outil).
2. **Mode passif** (sources publiques uniquement, aucun paquet vers la cible) : autorisé sans
   vérification, mais avec rate limit strict.
3. **Les presets BBOT sont imposés côté serveur.** L'utilisateur choisit un « niveau »
   (`passive`, `standard`, `advanced`), jamais des modules ou des options BBOT bruts.
   - Le niveau `advanced` **active de la force brute de surface** : `dnsbrute`
     (sous-domaines) et `webbrute` (répertoires web, liste de 1000 mots). Il n'est
     autorisé **que** pour un domaine avec preuve de propriété DNS TXT valide
     (revérifiée au lancement du job) **et** avec un consentement explicite de
     l'utilisateur, journalisé dans le trail d'audit. Il a son propre quota
     journalier et son propre timeout, plus stricts.
   - Même en `advanced`, restent **interdits** : la force brute d'authentification
     (`legba`, `medusa` — flag `invasive`), `iis-shortnames` / `web-heavy`
     (`webbrute_shortnames`), le `paramminer` (flag `web-paramminer`), et bien sûr
     `kitchen-sink`. Le consentement ne débloque jamais de modules bruts choisis
     par l'utilisateur : le preset reste imposé côté serveur.
4. **Journalisation obligatoire** de chaque scan : utilisateur, domaine, niveau, IP source, horodatage.
5. **RGPD** : hébergement UE, rétention courte des résultats (30 jours par défaut),
   suppression à la demande, pas de module `email-enum` dans le MVP.
6. **API tierces** : ne pas embarquer de clés gratuites (VirusTotal, Shodan, SecurityTrails…)
   pour servir le public — leurs CGU l'interdisent généralement. MVP = modules sans clé,
   puis option « l'utilisateur fournit ses propres clés ».

## Licence
- BBOT est sous **AGPL-3.0**. Décision prise : le projet sera **open source sous AGPL-3.0**
  (ajouter le fichier `LICENSE` avec le texte officiel — TODO).
- BBOT est appelé **en CLI via sous-processus** (pas importé comme librairie) pour garder
  une frontière nette.
- Ne pas utiliser « BBOT » dans le nom ou la marque du service.

## Stack
- **Back** : **Python 3.11+**, **FastAPI** (API JSON sous `/api`, auth JWT bearer + bcrypt)
- **Front** : **React 19** (JavaScript) + **Tailwind CSS** + composants **shadcn/ui** (Radix),
  axios, react-router, lucide-react, sonner — même stack que Waselni_V2.0, mais build **Vite**
  (au lieu de CRA/craco). Jinja2 ne sert plus qu'au template du rapport HTML/PDF.
- **Redis + RQ** pour la file de jobs (1 scan = 1 job, timeout, 1 scan simultané par utilisateur)
- **PostgreSQL** (SQLite acceptable en dev) — SQLAlchemy
- **BBOT 3.x** installé dans l'image du worker (`pipx install bbot`)
- **WeasyPrint** pour HTML → PDF
- **Docker Compose** : `web`, `worker`, `redis`, `db`

## Arborescence
```
app/
  main.py        # app FastAPI : monte /api et sert le build React (frontend/dist)
  api.py         # routes JSON : auth, domaines, scans, rapports
  auth.py        # bcrypt + JWT
  db.py / models.py  # SQLAlchemy : User, Domain, Scan, AuditLog
  worker.py      # jobs RQ : execute_scan (+ e-mail de fin de scan), purge_expired
  mailer.py      # e-mails SMTP : config admin en base (clé chiffrée), repli sur l'env
  crypto.py      # chiffrement des secrets stockés en base (clé dérivée de SECRET_KEY)
  cli.py         # commandes serveur : make-admin / revoke-admin
  config.py      # settings (pydantic-settings, variables d'env)
  domains.py     # normalisation de domaine, jetons, vérification DNS TXT
  scans.py       # lancement BBOT en sous-processus + parsing JSON
  reports.py     # agrégation des événements + rendu HTML/PDF
  templates/     # template du rapport (HTML/PDF)
frontend/        # React + Vite + Tailwind + shadcn/ui
tests/
docs/SPEC.md     # spec du MVP + roadmap
```

## Commandes
```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload         # API en local (:8000)
cd frontend && npm install && npm run dev   # front en local (:5173, proxy /api → :8000)
rq worker scans                        # worker (nécessite Redis)
pytest                                 # tests
docker compose up --build              # tout le stack
```

## Points à vérifier
- Options BBOT de `app/scans.py` vérifiées contre les sources de BBOT 3.0.2 (sept. 2026).
  Le niveau `standard` exclut les flags `loud`, `invasive`, `iis-shortnames` et `web-heavy`
  (sinon `-p web` active `iis_shortnames`, `webbrute_shortnames` et `dnsbrute`).
  Le niveau `advanced` ajoute explicitement `-m dnsbrute webbrute` et exclut les flags
  `invasive`, `iis-shortnames`, `web-heavy`, `web-paramminer` (résolu vérifié sur BBOT 3.0.2 :
  modules chargés = `dnsbrute`, `webbrute` uniquement côté brute-force ; `legba`, `medusa`,
  `webbrute_shortnames`, `paramminer_*` bien exclus). Revérifier à chaque montée de version de BBOT.
- Le dossier de sortie BBOT d'un scan est supprimé dès que ses événements sont en base
  (rétention gérée par l'app, pas par `keep_scans`, qui ne concerne que `~/.bbot/scans`).
- Tester d'abord BBOT sur un domaine qu'on possède, jamais sur un domaine tiers.

## Conventions
- Code et commentaires en anglais, documentation projet en français.
- Toute entrée utilisateur (domaine) passe par `domains.normalize_domain()` avant usage.
- Ne jamais construire de commande shell par concaténation : toujours `subprocess` avec une liste d'arguments.
- Réponses et propositions concises.

## Lien avec VulnWatch-AI
Projet perso existant (Streamlit, CISA KEV / NVD / Defender). À terme, réutiliser sa logique
pour croiser les technologies détectées par BBOT avec CISA KEV / NVD dans le rapport.
