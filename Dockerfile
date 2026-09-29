FROM python:3.11-slim

# WeasyPrint system libraries (PDF export)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir -e ".[pdf]" && pip install --no-cache-dir bbot

# Run as non-root
RUN useradd -m sw && mkdir -p /srv/data && chown -R sw /srv
USER sw

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
