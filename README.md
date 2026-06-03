# AssetMonitor

Continuous external attack-surface monitor. Discovers subdomains, port-scans live hosts, monitors websites for structural changes, and alerts the moment anything shifts.

---

## What It Does

| Capability | Detail |
|------------|--------|
| **Subdomain Discovery** | 10 enumeration techniques per domain — CT logs, DNS bruteforce, passive DNS, Wayback Machine, SSL SANs, JS analysis, DNS records, AXFR, reverse IP |
| **Live Host Verification** | DNS + HTTP probing, technology fingerprinting, subdomain takeover detection |
| **Port Scanning** | nmap-based open port discovery per live host; tracks port opens/closes over time |
| **Change Detection** | Content hash, DOM diff, endpoint delta, asset tracking, response size anomaly, tech stack diff, HTTP header changes |
| **Web Dashboard** | Full management UI at `http://localhost:5000` — add targets, manage scan profiles, view results, configure alerts |
| **Alerts** | Slack, Telegram, Discord, Email, Webhook — configured through the dashboard |
| **Scan Profiles** | Passive / Stealth / Standard / Aggressive built-ins + custom profiles, assignable per target |
| **Multi-user Auth** | Session-based login; multiple user accounts manageable through the Settings panel |

---

## Quick Start

**Requirements:** Docker and Docker Compose (Docker Desktop on macOS/Windows, or Docker Engine + Compose on Linux)

```bash
# 1. Clone and start
git clone <repo-url> asset-monitor
cd asset-monitor
docker-compose up -d

# 2. Open the dashboard
open http://localhost:5000
```

That's it. The container starts immediately with default settings and no host-side configuration required.

**Linux only** — pre-create the data directory with the correct owner before step 1:
```bash
mkdir -p data && chown 1000:1000 data
```

---

## First Login

On first start the container generates a random admin password and prints it to the container log:

```bash
docker-compose logs assetmonitor | grep -A3 "DEFAULT ADMIN"
```

Or tail the live log:
```bash
docker-compose logs -f assetmonitor
```

You'll see a block like:
```
┌─ DEFAULT ADMIN CREDENTIALS ──────────────────────────────────────┐
│  Username: admin                                                   │
│  Password: abc123xyz...                                            │
│  Change via Settings → Users after first login.                   │
└──────────────────────────────────────────────────────────────────┘
```

To set a fixed admin password, uncomment and set `DASHBOARD_SECRET` in `docker-compose.yml` before first start.

---

## Adding Targets

Everything is managed through the dashboard at `http://localhost:5000`.

1. Click **Add Target** on the Targets tab
2. Choose type: **Domain** (full subdomain enumeration), **Subdomain** (direct monitoring), or **Website URL** (content diff)
3. Optionally assign a **Scan Profile** and choose whether to scan immediately
4. Click **Add Target**

---

## Scan Profiles

Four built-in profiles, assignable per domain:

| Profile | Mode | Description |
|---------|------|-------------|
| **Passive Only** | Passive | CT logs + Wayback only. Zero active probing. |
| **Stealth** | Stealth | Low-and-slow active scan. Minimal detection footprint. |
| **Standard** | Open | All enumeration techniques, full TCP scan, full crawl. |
| **Aggressive** | Aggressive | Everything on, fast nmap with script detection, deep crawl. |

Custom profiles can be created under the **Profiles** tab.

---

## Settings

Open the **⚙** gear icon in the top-right corner to configure:

- **Scan** — interval, timeout, crawl depth
- **Notifications** — Slack, Telegram, Discord, Email, Webhook
- **API Keys** — VirusTotal, SecurityTrails, Shodan, Censys
- **Users** — create, delete, change passwords

All settings are stored in the database and persist across container restarts. No config file editing required.

---

## Port Scanning

nmap runs against every live host each scan cycle. Port states are compared against the previous scan and any new `PORT_OPENED` or `PORT_CLOSED` events fire alerts at the configured severity.

Port severities:

| Severity | Ports |
|----------|-------|
| CRITICAL | 2375/2376 (Docker daemon) |
| HIGH | 23, 3389, 5900, 6379, 9200, 27017, 11211 |
| MEDIUM | 22, 25, 3306, 5432, 1433, 1521 |
| LOW | All others |

SYN scanning is enabled by default in Docker (`cap_add: NET_RAW` + `cap_net_raw` on the nmap binary). Requires `DASHBOARD_SECRET` or custom `config.yaml` to switch to `-sT` TCP connect mode if SYN scan is unwanted.

---

## Operational Commands

```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# View logs (HTTP access logs + application logs stream here)
docker-compose logs -f assetmonitor

# Rebuild after code changes
docker-compose build && docker-compose up -d

# Trigger a manual scan from the CLI inside the container
docker-compose exec assetmonitor python assetmonitor.py scan

# Shell into the container
docker-compose exec assetmonitor bash
```

---

## Recovering Dashboard Access

If you cannot log in (lost password / no credentials were printed on first start):

**Option 1 — Reset via CLI (no restart needed):**
```bash
# Generate a new random password and print it
docker-compose exec assetmonitor python assetmonitor.py reset-admin

# Or set a specific password
docker-compose exec assetmonitor python assetmonitor.py reset-admin --password mynewpassword
```

**Option 2 — Set a fixed password via environment variable:**
```yaml
# docker-compose.yml — uncomment and set:
DASHBOARD_SECRET: "mynewpassword"
```
Then `docker-compose up -d` — the password is synced on every start.

**Finding the auto-generated password in the logs:**
```bash
# Search for the initial credentials block
docker-compose logs assetmonitor | grep -A4 "DEFAULT ADMIN"
```

---

## Data Persistence

The SQLite database lives in `./data/assetmonitor.db`. This volume is mounted from the host, so all scan history, settings, and user accounts survive container restarts and image rebuilds.

Back up `./data/` to preserve everything.

---

## Advanced: Custom Config File

If you prefer file-based configuration over the web UI, mount a `config.yaml`:

1. Copy the example: `cp config.yaml.example config.yaml`
2. Edit as needed
3. Uncomment the config volume in `docker-compose.yml`:
   ```yaml
   volumes:
     - ./data:/app/data
     - ./config.yaml:/app/config.yaml:ro   # ← uncomment this
   ```
4. Restart: `docker-compose up -d`

DB settings (managed via the dashboard) always take precedence over `config.yaml` values at runtime.

---

## Port Badge Colours (Dashboard)

| Colour | Meaning |
|--------|---------|
| Red | Risky — RDP, VNC, Telnet, Docker daemon, unauthenticated Redis/MongoDB |
| Blue | Web — 80, 443, 8080, 8443, 3000, etc. |
| Yellow | Database — MySQL, PostgreSQL, MongoDB, Elasticsearch, etc. |
| Green | SSH (22, 2222) |
| Grey | Other |
