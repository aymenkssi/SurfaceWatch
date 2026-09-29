# SurfaceWatch

Service web gratuit de scan EASM (surface d'attaque externe) avec génération de rapports,
basé sur [BBOT](https://github.com/blacklanternsecurity/bbot). *Nom provisoire.*

**Statut : v0.1 — squelette.** Voir [`docs/SPEC.md`](docs/SPEC.md) pour la spec et la roadmap,
et [`CLAUDE.md`](CLAUDE.md) pour les règles du projet.

## Démarrage rapide
```bash
cp .env.example .env        # puis changer SECRET_KEY
docker compose up --build
# → http://localhost:8000
```

En local sans Docker :
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
uvicorn app.main:app --reload
```

## Principe de sécurité
Aucun scan actif sans preuve de propriété du domaine (enregistrement DNS TXT).
Ne testez BBOT que sur des domaines qui vous appartiennent.

## Licence
AGPL-3.0 (comme BBOT).
