# Déploiement de SurfaceAttackWatch sur le VPS (surfaceattackwatch.com)

Même méthode que les autres apps du VPS (Traefik + Docker Compose, un dossier par app sous
`/opt/apps`, réseau Docker partagé `web`, certificats Let's Encrypt), avec deux différences :

- **PostgreSQL au lieu de MongoDB** (conteneur `surfacewatch-db`, volume `surfacewatch_pgdata`).
- **Un seul conteneur web** : FastAPI sert l'API (`/api`) *et* le build React. Pas de conteneur
  nginx pour le front, pas de `REACT_APP_BACKEND_URL` (même origine).

| Conteneur | Rôle | Réseaux |
|---|---|---|
| `surfacewatch-web` | FastAPI + front React (port 8000, exposé via Traefik) | `internal`, `web` |
| `surfacewatch-worker` | worker RQ qui lance BBOT | `internal` |
| `surfacewatch-redis` | file de jobs | `internal` |
| `surfacewatch-db` | PostgreSQL 16 | `internal` |

Aucun port n'est ouvert sur l'hôte : seul Traefik (80/443) reçoit le trafic. Postgres et Redis
ne sont joignables que depuis le réseau privé `internal` de SurfaceAttackWatch, donc aucun conflit
avec les MongoDB des autres apps.

Fichiers utilisés : [`docker-compose.prod.yml`](../docker-compose.prod.yml),
[`.env.production.example`](../.env.production.example), [`Dockerfile`](../Dockerfile).

## 0. Prérequis déjà en place sur le VPS
Docker, le réseau `web` et Traefik (`/opt/apps/proxy`) tournent déjà pour les autres apps.
À vérifier :
```bash
docker network ls | grep web
docker ps | grep traefik
```
Si ce n'est pas le cas, suivre d'abord les sections « Installer Docker », « Créer un réseau
Docker partagé » et « Installer Traefik » du document de déploiement multi-apps.

**Ressources** : l'image du worker contient BBOT ; compter environ 1 Go de RAM libre par
scan en cours (1 scan simultané par utilisateur). Vérifier avec `free -h` et `df -h`.

## 1. Préparer le DNS
Chez le registrar de `surfaceattackwatch.com` :

| Type | Nom | Valeur |
|---|---|---|
| A | `@` | IP du VPS |
| A | `www` | IP du VPS |

(Et `AAAA` si le VPS a une IPv6 joignable.) Vérifier avant de lancer, sinon Let's Encrypt échoue :
```bash
dig +short surfaceattackwatch.com
dig +short www.surfaceattackwatch.com
```

## 2. Cloner l'application
```bash
mkdir -p /opt/apps/surfacewatch
cd /opt/apps/surfacewatch
git clone https://github.com/aymenkssi/SurfaceWatch.git .
```
Le dépôt étant privé, `git clone` demande un identifiant GitHub et un *personal access token*
(lecture seule sur ce dépôt) en guise de mot de passe, ou utiliser une clé SSH de déploiement.

## 3. Créer le `.env`
```bash
cp .env.production.example .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 32)/" .env
sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 32)/" .env
chmod 600 .env
```
Points importants :
- `COMPOSE_FILE=docker-compose.prod.yml` (déjà dans le fichier) : les commandes habituelles
  `docker compose build / up -d / logs` utilisent directement la config de prod.
- Comme pour MongoDB, la base n'est pas sur `localhost` : l'URL est
  `postgresql+psycopg://surfacewatch:<mot de passe>@db:5432/surfacewatch`. Elle est construite
  automatiquement par `docker-compose.prod.yml` à partir de `POSTGRES_PASSWORD` : ne pas définir
  `DATABASE_URL` à la main.
- Le mot de passe Postgres n'est lu qu'à la **création** du volume. Pour le changer ensuite, il
  faut le faire dans Postgres (`ALTER USER surfacewatch PASSWORD '...'`) puis dans `.env`.
- Garder une copie du `.env` hors du VPS (gestionnaire de mots de passe).

### E-mails (mot de passe oublié, notifications)
Les e-mails passent par **votre propre compte SMTP** (aucune clé n'est embarquée). Variables
à renseigner dans `.env` :

| Variable | Exemple | Rôle |
|---|---|---|
| `SMTP_HOST` | `smtp-relay.brevo.com` | serveur SMTP ; **vide = e-mails désactivés** |
| `SMTP_PORT` | `587` | `587` (STARTTLS) ou `465` (SSL) |
| `SMTP_SECURITY` | `starttls` | `starttls`, `ssl` ou `none` |
| `SMTP_USER` / `SMTP_PASSWORD` | identifiants SMTP | laisser vide si le serveur n'en demande pas |
| `SMTP_FROM` | `noreply@surfaceattackwatch.com` | expéditeur ; le domaine doit être autorisé (SPF/DKIM) chez le fournisseur |
| `PUBLIC_URL` | `https://surfaceattackwatch.com` | base des liens envoyés par e-mail |

Sans SMTP, le lien « Mot de passe oublié ? » est masqué et aucune notification n'est envoyée.
Préférer un fournisseur hébergé dans l'UE (RGPD). Test rapide après démarrage :
```bash
docker exec surfacewatch-web python -c "from app import mailer; print(mailer.send('vous@exemple.fr', 'Test', 'OK'))"
```
`True` = e-mail remis au serveur SMTP ; `False` = voir `docker logs surfacewatch-web`.

## 4. Lancer l'application
```bash
cd /opt/apps/surfacewatch
docker compose build
docker compose up -d
```
Les tables sont créées automatiquement au premier démarrage. Traefik détecte le conteneur via
ses labels ; inutile de le redémarrer, sauf si le certificat ne sort pas :
```bash
cd /opt/apps/proxy && docker compose restart traefik
```

Les labels Traefik (dans `docker-compose.prod.yml`) :
- routeur `surfacewatch` : `Host(surfaceattackwatch.com) || Host(www.surfaceattackwatch.com)`,
  entrypoint `websecure`, certresolver `letsencrypt`, port 8000 ;
- routeur `surfacewatch-http` : redirection HTTP → HTTPS limitée à ce domaine (la config de
  Traefik et les autres apps ne sont pas modifiées).

Les noms de routeurs/middlewares sont préfixés `surfacewatch` pour ne pas entrer en collision
avec ceux des autres apps (Traefik les partage entre tous les conteneurs).

## 5. Tester
```bash
docker ps
curl -I http://surfaceattackwatch.com          # 301 vers https
curl -I https://surfaceattackwatch.com         # 200
curl -i https://surfaceattackwatch.com/health  # {"status":"ok"}
docker exec surfacewatch-db psql -U surfacewatch -c '\dt'   # users, domains, scans, audit_log, password_reset_tokens
```
Puis dans le navigateur : créer un compte, ajouter **un domaine qui vous appartient**, poser
l'enregistrement TXT `_surfacewatch-verify.<domaine>`, vérifier, lancer un scan passif.

Vérifier que le journal d'audit enregistre la vraie IP du client (règle 4) et non celle de
Traefik :
```bash
docker exec surfacewatch-db psql -U surfacewatch -c \
  'select created_at, action, source_ip from audit_log order by created_at desc limit 5'
```

Donner le rôle admin à votre compte (après l'avoir créé dans l'interface) ; la page
`/admin` apparaît alors dans le menu :
```bash
docker exec surfacewatch-web python -m app.cli make-admin vous@exemple.fr
```

## 6. Purge RGPD quotidienne (rétention 30 jours)
Les résultats expirés sont purgés après chaque scan ; ajouter une purge quotidienne pour les
périodes sans scan (`crontab -e`) :
```cron
30 3 * * * docker exec surfacewatch-worker python -m app.worker purge >> /var/log/surfacewatch-purge.log 2>&1
```

## 7. Commandes d'investigation
```bash
docker logs -f surfacewatch-web
docker logs -f surfacewatch-worker
docker logs -f surfacewatch-db
docker logs -f surfacewatch-redis
docker logs -f traefik
```
Console Postgres (équivalent de `mongosh`) :
```bash
docker exec -it surfacewatch-db psql -U surfacewatch -d surfacewatch
# \dt                       liste des tables
# select email from users;  …
# \q
```

## 8. Mise à jour
```bash
cd /opt/apps/surfacewatch
git pull origin main
docker compose build
docker compose up -d
```
Seulement l'app (sans toucher à Postgres/Redis) :
```bash
docker compose build web worker
docker compose up -d web worker
```
⚠️ Ne jamais faire `docker compose down -v` : `-v` supprime le volume Postgres.

## 9. Sauvegarde PostgreSQL (remplace `mongodump`)
```bash
mkdir -p /var/backups/surfacewatch
docker exec surfacewatch-db pg_dump -U surfacewatch -d surfacewatch -Fc \
  > /var/backups/surfacewatch/surfacewatch_$(date +%Y%m%d_%H%M%S).dump
```
Sauvegarde quotidienne avec rotation 7 jours (`crontab -e`) — courte, car les résultats de scan
ne doivent pas survivre à la rétention de 30 jours dans les sauvegardes :
```cron
0 3 * * * docker exec surfacewatch-db pg_dump -U surfacewatch -d surfacewatch -Fc > /var/backups/surfacewatch/surfacewatch_$(date +\%Y\%m\%d).dump && find /var/backups/surfacewatch -name '*.dump' -mtime +7 -delete
```

## 10. Restauration (remplace `mongorestore`)
```bash
cd /opt/apps/surfacewatch
docker compose stop web worker
docker exec -i surfacewatch-db pg_restore -U surfacewatch -d surfacewatch --clean --if-exists \
  < /var/backups/surfacewatch/surfacewatch_AAAAMMJJ_HHMMSS.dump
docker compose start web worker
```

## 11. Certificat SSL
Si le certificat n'est pas émis (`docker logs traefik | grep -i acme`) : vérifier le DNS
(étape 1) et que les ports 80/443 sont ouverts, puis `docker compose restart traefik` dans
`/opt/apps/proxy`.
⚠️ La procédure « Relancer Traefik SSL » du document (suppression du volume
`proxy_traefik_letsencrypt`) régénère les certificats de **toutes** les apps du VPS : à garder
en dernier recours (attention aux limites de Let's Encrypt).

## 12. Nettoyage Docker
Mêmes commandes que pour les autres apps (`docker system df`, `docker image prune -a`,
`docker container prune`). ⚠️ Ne jamais lancer `docker volume prune -a` pendant que SurfaceAttackWatch
est arrêté : `surfacewatch_pgdata` partirait avec.
