# SurfaceWatch — contexte pour Claude Code

> Nom provisoire. Service web **gratuit** de scan EASM (External Attack Surface Management)
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
   - Contexte : art. 323-1 et 323-3-1 du Code pénal (accès frauduleux, mise à disposition d'outil).
2. **Mode passif** (sources publiques uniquement, aucun paquet vers la cible) : autorisé sans
   vérification, mais avec rate limit strict.
3. **Les presets BBOT sont imposés côté serveur.** L'utilisateur choisit un « niveau »
   (`passive`, `standard`), jamais des modules ou des options BBOT bruts.
   Jamais de `kitchen-sink`, `web-heavy`, `webbrute`, `paramminer` en production.
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
- **Python 3.11+**, **FastAPI** + templates Jinja2 (HTMX plus tard si besoin)
- **Redis + RQ** pour la file de jobs (1 scan = 1 job, timeout, 1 scan simultané par utilisateur)
- **PostgreSQL** (SQLite acceptable en dev) — SQLAlchemy
- **BBOT 3.x** installé dans l'image du worker (`pipx install bbot`)
- **WeasyPrint** pour HTML → PDF
- **Docker Compose** : `web`, `worker`, `redis`, `db`

## Arborescence
```
app/
  main.py        # routes FastAPI
  config.py      # settings (pydantic-settings, variables d'env)
  domains.py     # normalisation de domaine, jetons, vérification DNS TXT
  scans.py       # lancement BBOT en sous-processus + parsing JSON
  reports.py     # agrégation des événements + rendu HTML/PDF
  templates/     # pages web + template de rapport
tests/
docs/SPEC.md     # spec du MVP + roadmap
```

## Commandes
```bash
pip install -e ".[dev]"
uvicorn app.main:app --reload         # web en local
rq worker scans                        # worker (nécessite Redis)
pytest                                 # tests
docker compose up --build              # tout le stack
```

## Points à vérifier
- **BBOT 3.0 a changé la CLI** par rapport à la 2.x. Les options utilisées dans `app/scans.py`
  (`-rf passive`, `-om json`, `-o`, `-n`, `-y`) et l'emplacement du fichier JSON de sortie
  doivent être revérifiés contre la doc officielle 3.x avant la première exécution réelle.
- Tester d'abord BBOT sur un domaine qu'on possède, jamais sur un domaine tiers.

## Conventions
- Code et commentaires en anglais, documentation projet en français.
- Toute entrée utilisateur (domaine) passe par `domains.normalize_domain()` avant usage.
- Ne jamais construire de commande shell par concaténation : toujours `subprocess` avec une liste d'arguments.
- Réponses et propositions concises.

## Lien avec VulnWatch-AI
Projet perso existant (Streamlit, CISA KEV / NVD / Defender). À terme, réutiliser sa logique
pour croiser les technologies détectées par BBOT avec CISA KEV / NVD dans le rapport.
