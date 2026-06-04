# AssetMonitor

Continuous external attack-surface monitor. Discovers subdomains, port-scans live hosts, monitors websites for changes, and alerts when anything shifts.

---

## What It Does

| Capability | Detail |
|---|---|
| **Subdomain Discovery** | 10 techniques — CT logs, DNS bruteforce, passive DNS, Wayback Machine, SSL SANs, JS analysis, DNS records, AXFR, reverse IP |
| **Live Host Verification** | DNS + HTTP probing, technology fingerprinting, subdomain takeover detection |
| **Port Scanning** | nmap-based open port discovery per live host; tracks opens/closes over time |
| **Change Detection** | Content hash, DOM diff, endpoint delta, asset tracking, response size anomaly, tech stack diff, HTTP header changes |
| **Website Monitoring** | Add a URL directly — monitors live status, page title, technologies |
| **Web Dashboard** | Full UI at `http://localhost:5000` — add targets, manage scan profiles, view results, configure alerts |
| **Alerts** | Slack, Telegram, Discord, Email, Webhook — configured through the dashboard |
| **Scan Profiles** | Passive / Stealth / Standard / Aggressive built-ins + custom profiles per target |
| **Multi-user Auth** | Session-based login, RBAC, CSRF protection, bcrypt passwords |

---

## Requirements

- Docker
- Docker Compose (included with Docker Desktop on macOS/Windows; install separately on Linux)

No Python, no pip, no host dependencies.

---

## Quick Start

```bash
# 1. Clone the repo
git clone <repo-url> asset-monitor
cd asset-monitor

# Linux only — set correct ownership on the data directory
mkdir -p data && chown 1000:1000 data

# 2. Start
docker compose up -d

# 3. Get your login credentials
cat data/initial_credentials.txt

# 4. Open the dashboard
open http://localhost:5000   # macOS
# or navigate to http://localhost:5000 in your browser
```

On first start, the container generates a random admin password and writes it to `data/initial_credentials.txt`. Read it, log in, then delete the file.

---

## First Login

After `docker compose up -d`:

```bash
cat data/initial_credentials.txt
```

Output:
```
AssetMonitor — Initial Admin Credentials
==========================================
Username : admin
Password : abc123xyz...

Change this password immediately via Settings → Users.
Delete this file after your first login.
```

**Set a fixed password instead** — uncomment `DASHBOARD_SECRET` in `docker-compose.yml` before first start:

```yaml
environment:
  DASHBOARD_SECRET: "your-chosen-password"
```

The `DASHBOARD_SECRET` env var is synced as the admin password on every container start, so rotating it is safe.

---

## Adding Targets

Everything is managed through the dashboard at `http://localhost:5000`.

1. Click **Add Target** on the Targets tab
2. Choose type:
   - **Root Domain** — full subdomain enumeration + port scan + change detection
   - **Known Subdomain** — add a specific FQDN directly to monitoring
   - **Website URL** — monitor a specific URL for liveness and change detection
3. Optionally assign a **Scan Profile** and check **Trigger scan immediately**
4. Click **Add Target**

---

## Scan Profiles

Four built-in profiles, assignable per domain:

| Profile | Mode | Description |
|---|---|---|
| **Passive Only** | Passive | CT logs + Wayback only. Zero active probing. |
| **Stealth** | Stealth | Low-and-slow active scan. Minimal detection footprint. |
| **Standard** | Open | All techniques, full TCP scan, full crawl. |
| **Aggressive** | Aggressive | Everything on, fast nmap with script detection, deep crawl. |

Custom profiles can be created under the **Profiles** tab.

---

## Settings

Click the **⚙** gear icon (top right) to configure:

- **Scan** — interval, timeout, crawl depth
- **Notifications** — Slack, Telegram, Discord, Email, Webhook
- **API Keys** — VirusTotal, SecurityTrails, Shodan, Censys
- **Users** — create, delete, change passwords

All settings are stored in the database and persist across restarts.

---

## Docker Commands

```bash
# Start (detached)
docker compose up -d

# Stop
docker compose down

# View logs
docker compose logs -f assetmonitor

# Rebuild after code changes
docker compose build && docker compose up -d

# Shell into the container
docker compose exec assetmonitor bash

# Trigger a manual scan
docker compose exec assetmonitor python assetmonitor.py scan

# Reset admin password (if locked out)
docker compose exec assetmonitor python assetmonitor.py reset-admin
# or with a specific password:
docker compose exec assetmonitor python assetmonitor.py reset-admin --password newpassword
```

---

## Recovering Dashboard Access

If you are locked out:

```bash
# Generate a new random password and print it
docker compose exec assetmonitor python assetmonitor.py reset-admin

# Or set a specific password
docker compose exec assetmonitor python assetmonitor.py reset-admin --password mypassword
```

Or set `DASHBOARD_SECRET` in `docker-compose.yml` and restart — the password is synced on every start.

---

## Port Scanning

nmap runs against every live host each scan cycle. New `PORT_OPENED` / `PORT_CLOSED` events trigger alerts at the configured severity.

| Severity | Ports |
|---|---|
| CRITICAL | 2375/2376 (Docker daemon) |
| HIGH | 23, 3389, 5900, 6379, 9200, 27017, 11211 |
| MEDIUM | 22, 25, 3306, 5432, 1433, 1521 |
| LOW | All others |

SYN scanning is enabled in Docker by default (`cap_add: NET_RAW`).

---

## Data Persistence

The SQLite database and all settings live in `./data/`. This directory is mounted from the host, so everything survives container restarts and image rebuilds.

```bash
# Back up everything
cp -r ./data ./data.backup
```

---

## Custom Config File (Optional)

The dashboard covers all common settings. For file-based configuration:

1. Copy the example: `cp config.yaml.example config.yaml`
2. Edit as needed
3. Uncomment the config volume in `docker-compose.yml`:
   ```yaml
   volumes:
     - ./data:/app/data
     - ./config.yaml:/app/config.yaml:ro
   ```
4. `docker compose up -d`

Dashboard settings (stored in DB) take precedence over `config.yaml` values at runtime.

---

## Port Badge Colours

| Colour | Meaning |
|---|---|
| Red | Risky — RDP, VNC, Telnet, Docker daemon, unauthenticated Redis/MongoDB |
| Blue | Web — 80, 443, 8080, 8443, 3000, etc. |
| Yellow | Database — MySQL, PostgreSQL, MongoDB, Elasticsearch, etc. |
| Green | SSH (22, 2222) |
| Grey | Other |
