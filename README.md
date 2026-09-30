# SurfaceWatch

Service web gratuit de scan EASM (surface d'attaque externe) avec génération de rapports,
basé sur [BBOT](https://github.com/blacklanternsecurity/bbot). *Nom provisoire.*

**Statut : v0.2 — application web (front React + API).** Voir [`docs/SPEC.md`](docs/SPEC.md) pour la spec et la roadmap,
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
uvicorn app.main:app --reload          # API sur :8000
rq worker scans                         # worker (nécessite Redis)

cd frontend && npm install && npm run dev   # front sur http://localhost:5173
```

## Architecture
- **Front** : React 19 + Tailwind + shadcn/ui (même stack que Waselni_V2.0), build Vite.
- **Back** : FastAPI (API JSON `/api`, JWT), SQLAlchemy, worker RQ qui lance BBOT en sous-processus.
- En production, FastAPI sert aussi le build React (`frontend/dist`) : une seule origine.

## Principe de sécurité
Aucun scan actif sans preuve de propriété du domaine (enregistrement DNS TXT).
Ne testez BBOT que sur des domaines qui vous appartiennent.

## Licence
AGPL-3.0 (comme BBOT).
