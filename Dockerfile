FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────────────
WORKDIR /app

# ── Python dependencies ────────────────────────────────────────────────────
# Copy requirements first so Docker layer-caches the pip install step
# as long as requirements.txt is unchanged.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application source ─────────────────────────────────────────────────────
COPY . .

# ── Runtime directories ────────────────────────────────────────────────────
# /app/data      — SQLite database file
# /app/wordlists — subdomain wordlist(s)
# Both should be mounted as volumes in production (see docker-compose.yml).
RUN mkdir -p /app/data /app/wordlists

# ── Non-root user for defence-in-depth ────────────────────────────────────
RUN groupadd --system assetmon && \
    useradd --system --gid assetmon --no-create-home assetmon && \
    chown -R assetmon:assetmon /app
USER assetmon

# ── Entry point ────────────────────────────────────────────────────────────
ENTRYPOINT ["python", "assetmonitor.py"]

# Default command: start the daemon with the mounted config file.
CMD ["daemon", "--config", "/app/config.yaml", "--db", "/app/data/monitor.db"]
