# --- Front end: React (Vite) build ---------------------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- Back end: FastAPI + RQ worker (BBOT runs here as a CLI subprocess) --------------------
FROM python:3.11-slim

# WeasyPrint system libraries (PDF export) + masscan for the "deep" level port scan.
# masscan needs raw sockets (root); sudo is granted ONLY for the masscan binary so the
# worker itself keeps running as the unprivileged "sw" user (see the sudoers rule below).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
        masscan sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir -e ".[pdf]" && pip install --no-cache-dir bbot
COPY --from=frontend /frontend/dist ./frontend/dist

# Run as non-root. BBOT's portscan module shells out to masscan with sudo; grant the
# "sw" user passwordless sudo for that one binary only (least privilege) and nothing else.
RUN useradd -m sw && mkdir -p /srv/data && chown -R sw /srv \
    && MASSCAN="$(command -v masscan || echo /usr/bin/masscan)" \
    && echo "sw ALL=(root) NOPASSWD: ${MASSCAN}" > /etc/sudoers.d/masscan \
    && chmod 0440 /etc/sudoers.d/masscan
USER sw

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
