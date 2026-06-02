FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────
# nmap       — port scanning
# libcap2-bin— setcap to grant nmap NET_RAW without running as root
# dnsutils   — dig/nslookup for manual debugging inside the container
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    dnsutils \
    ca-certificates \
    curl \
    && setcap cap_net_raw+ep /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────────────
WORKDIR /app

# ── Non-root user ─────────────────────────────────────────────────────────
# Fixed UID 1000 so Linux host volume mounts can be pre-chowned to match.
# With cap_net_raw set on the nmap binary above, this user can run SYN scans
# when the container is started with --cap-add NET_RAW (see docker-compose).
RUN groupadd --system --gid 1000 assetmon && \
    useradd --system --uid 1000 --gid 1000 --no-log-init --no-create-home assetmon

# ── Python dependencies ────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application source ─────────────────────────────────────────────────────
COPY . .

# ── Runtime directories and default config ─────────────────────────────────
# Bake a default config.yaml from the example so the container starts
# with zero host-side setup required. Users can override via a mounted
# config.yaml or manage all settings through the web dashboard.
RUN mkdir -p /app/data /app/wordlists && \
    cp /app/config.yaml.example /app/config.yaml && \
    chown -R assetmon:assetmon /app

USER assetmon

# ── Ports ─────────────────────────────────────────────────────────────────
# 5000 — web dashboard
EXPOSE 5000

# ── Entry point ────────────────────────────────────────────────────────────
ENTRYPOINT ["python", "assetmonitor.py"]
CMD ["daemon", "--config", "/app/config.yaml", "--db", "/app/data/assetmonitor.db"]
