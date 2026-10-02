# --- Front end: React (Vite) build ---------------------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- Back end: FastAPI + RQ worker (BBOT runs here as a CLI subprocess) --------------------
FROM python:3.11-slim

# WeasyPrint system libraries (PDF export), then BBOT's core dependencies: BBOT installs
# these itself at scan time through sudo, which does not exist here (the worker is not root).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
        unzip curl git make gcc libc6-dev xz-utils p7zip-full libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir -e ".[pdf]" && pip install --no-cache-dir bbot
COPY --from=frontend /frontend/dist ./frontend/dist

# Run as non-root
RUN useradd -m sw && mkdir -p /srv/data && chown -R sw /srv

# Install the module dependencies of every scan level now (pip packages, massdns...): some need
# root, which the worker never has. Run as root but with the worker's home, so BBOT's tools and
# cache land in /home/sw/.bbot. Scans then run BBOT with --no-deps (see app/scans.py).
RUN HOME=/home/sw python -m app.scans install-deps && chown -R sw:sw /home/sw
USER sw

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
