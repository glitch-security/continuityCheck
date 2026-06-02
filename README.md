# AssetMonitor

Automated web asset and subdomain monitoring platform for security professionals.

Continuously discovers subdomains, port-scans live hosts, monitors websites for structural changes, detects new endpoints and features, and sends real-time alerts the moment anything changes. A built-in web dashboard shows the full picture — open ports, header security, subdomain status, and all change events — in your browser.

---

## What It Does

| Capability | Detail |
|------------|--------|
| **Subdomain Discovery** | 10 parallel enumeration techniques per domain (CT logs, DNS brute force, passive DNS, Wayback, SSL SANs, JS analysis, DNS records, AXFR, reverse IP) |
| **Live Host Verification** | DNS + HTTP probing, fingerprinting, subdomain takeover detection |
| **Port Scanning** | nmap-based open port discovery for every live host; tracks port opens/closes over time |
| **Website Monitoring** | BFS crawler, JS analysis, security file checks |
| **Change Detection** | Content hash, DOM diff, endpoint delta, asset tracking, response size anomaly, tech stack diff, HTTP security headers |
| **Web Dashboard** | Browser UI at `http://localhost:5000` — port scan results, subdomain status, header analysis, live event feed |
| **Alerts** | Slack, Telegram, Discord, Email, Webhook — all configurable per severity |
| **Persistence** | SQLite database — full history of every scan, port state, and header snapshot |
| **Reporting** | Terminal tables, JSON export, HTML report |

---

## Quick Start (5 minutes)

### Option A — Python (Local)

**Requirements:** Python 3.11+, pip, nmap installed on the host

```bash
# Install nmap (required for port scanning)
# macOS:  brew install nmap
# Ubuntu: apt-get install nmap
# Windows: https://nmap.org/download.html

# 1. Navigate to the project
cd asset-monitor

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate       # macOS / Linux
# venv\Scripts\activate        # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Set up configuration
cp config.yaml.example config.yaml

# 5. Add your targets
echo "example.com" >> domains.txt
echo "https://example.com" >> websites.txt

# 6. Run your first scan
python assetmonitor.py scan --module subdomains --domain example.com

# 7. View results in the terminal
python assetmonitor.py report --type subdomains

# 8. Start the daemon + dashboard
python assetmonitor.py daemon
# Dashboard: http://localhost:5000
```

---

### Option B — Docker (Recommended for Continuous Monitoring)

**Requirements:** Docker, Docker Compose

nmap is installed and configured automatically inside the container — nothing extra needed on the host.

```bash
# 1. Set up config and input files
cp config.yaml.example config.yaml
cp domains.txt.example domains.txt
cp subdomains.txt.example subdomains.txt
cp websites.txt.example websites.txt

# 2. Edit your targets (one per line, remove the example entries)
nano domains.txt
nano websites.txt

# 3. Edit config.yaml — add notification webhooks if needed
nano config.yaml

# 4. Linux only — make the data directory writable by the container user
mkdir -p data && chown 1000:1000 data

# 5. Start the daemon
docker-compose up -d

# 6. Open the dashboard
# http://localhost:5000

# 7. View logs
docker-compose logs -f

# 8. Run a manual scan inside the container
docker-compose exec assetmonitor python assetmonitor.py scan
```

---

## Web Dashboard

Once the daemon is running, open **http://localhost:5000** in any browser.

The dashboard auto-refreshes every 60 seconds.

### Dashboard Sections

| Tab | What it shows |
|-----|---------------|
| **Port Scans** | Latest nmap result per host — open ports as colour-coded badges (red = risky, blue = web, yellow = database, green = SSH), scan time, duration |
| **Subdomains** | All discovered subdomains — live/dead status, HTTP code, IPs, open ports, detected technologies. NEW badge on subdomains discovered in the last 24h. TAKEOVER badge on vulnerable hosts |
| **HTTP Headers** | Security header audit per subdomain — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Flags server/X-Powered-By information leakage |
| **Change Events** | Full event timeline — filterable by severity and time window (24h / 48h / 7d / 30d). CRITICAL events shown in a banner across all tabs |

### Summary Cards

The top row shows live counts: Domains, Subdomains, Live Hosts, Open Ports, Events (24h), Critical (24h), High (24h).

### Port Badge Colours

| Colour | Meaning |
|--------|---------|
| Red | Risky port — RDP (3389), VNC (5900), Telnet (23), Docker daemon (2375/2376), unauthenticated Redis/MongoDB |
| Blue | Web port — 80, 443, 8080, 8443, 3000, etc. |
| Yellow | Database port — MySQL, PostgreSQL, MongoDB, Elasticsearch, etc. |
| Green | SSH (22, 2222) |
| Grey | Other |

---

## Input Files

### `domains.txt` — Root domains for full subdomain enumeration

```
# One domain per line. Comments start with #
example.com
target-company.com
another-target.org
```

### `subdomains.txt` — Known subdomains to monitor directly (no enumeration)

```
# Full FQDNs — will be probed, port-scanned, and monitored for changes
admin.example.com
api.example.com
staging.example.com
```

### `websites.txt` — Full URLs for content and structure monitoring

```
# Full URLs — will be crawled and diffed on every scan
https://example.com
https://app.example.com/dashboard
```

---

## Configuration

Copy `config.yaml.example` to `config.yaml` and edit the sections you need.

### Minimum required configuration

```yaml
scan:
  interval_minutes: 360

notifications:
  min_severity: "MEDIUM"
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### Full configuration reference

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `scan` | `interval_minutes` | `360` | Scan interval in minutes |
| `scan` | `concurrent_threads` | `10` | Parallel workers |
| `scan` | `request_timeout_seconds` | `10` | HTTP timeout per request |
| `scan` | `max_crawl_depth` | `3` | How deep the crawler follows links |
| `scan` | `max_pages_per_domain` | `500` | Page budget per domain per scan |
| `scan` | `respect_robots_txt` | `false` | Honour robots.txt during crawl |
| `enumeration.techniques` | `certificate_transparency` | `true` | Query crt.sh CT logs (wildcard + apex queries) |
| `enumeration.techniques` | `dns_bruteforce` | `true` | Wordlist-based DNS brute force |
| `enumeration.techniques` | `passive_dns` | `true` | Query passive DNS databases |
| `enumeration.techniques` | `wayback_machine` | `true` | Mine Wayback Machine |
| `enumeration.techniques` | `ssl_san_extraction` | `true` | Extract TLS certificate SANs |
| `enumeration.techniques` | `js_analysis` | `true` | Parse JS files for subdomains |
| `enumeration.techniques` | `zone_transfer` | `true` | Attempt DNS AXFR |
| `enumeration.techniques` | `reverse_ip` | `true` | Reverse IP lookup |
| `enumeration` | `wordlist_path` | `./wordlists/subdomains-5000.txt` | DNS brute force wordlist |
| `enumeration` | `max_dns_concurrent` | `50` | Max parallel DNS queries |
| `verification` | `ports` | `[80,443,8080,8443,8888]` | HTTP probe ports |
| `verification` | `takeover_check` | `true` | Check for subdomain takeover |
| `monitoring.change_detection` | `content_hash` | `true` | Hash-based content change |
| `monitoring.change_detection` | `dom_structural_diff` | `true` | HTML structure diff |
| `monitoring.change_detection` | `endpoint_inventory` | `true` | Track URL endpoints |
| `monitoring.change_detection` | `technology_stack` | `true` | Detect tech changes |
| `monitoring.change_detection` | `response_size_anomaly` | `true` | Flag size anomalies |
| `monitoring.change_detection` | `asset_tracking` | `true` | Track JS/CSS/image files |
| `port_scanning` | `enabled` | `true` | Run nmap against live hosts |
| `port_scanning` | `ports` | *(security-focused list)* | Ports to scan — comma-separated or nmap range |
| `port_scanning` | `scan_arguments` | `-sT -T4 -sV --open` | nmap flags (see SYN scanning below) |
| `port_scanning` | `timeout_seconds` | `120` | Max nmap runtime per host |
| `port_scanning` | `max_concurrent` | `5` | Parallel host scans |
| `web` | `enabled` | `true` | Run the web dashboard |
| `web` | `host` | `0.0.0.0` | Dashboard bind address |
| `web` | `port` | `5000` | Dashboard port |
| `notifications` | `min_severity` | `MEDIUM` | Minimum severity to alert on |

---

## Port Scanning

### How it works

Every scan cycle, nmap runs against all live subdomains. Results are stored in the database and compared against the previous scan for the same host. Any newly opened or closed port emits a `PORT_OPENED` or `PORT_CLOSED` change event with the appropriate severity.

Port severities are pre-mapped:

| Severity | Ports |
|----------|-------|
| CRITICAL | 2375, 2376 (Docker daemon) |
| HIGH | 23 (Telnet), 3389 (RDP), 5900/5901 (VNC), 6379 (Redis), 9200/9300 (Elasticsearch), 27017/27018 (MongoDB), 11211 (Memcached) |
| MEDIUM | 22 (SSH), 25 (SMTP), 3306 (MySQL), 5432 (PostgreSQL), 1521 (Oracle), 1433 (MSSQL) |
| LOW | All other ports |

### Scan type: TCP connect vs SYN

The default scan (`-sT`) uses TCP connect — works with no root access or extra Linux capabilities.

To enable SYN scanning (faster, lower noise on target logs):

**Docker:** already configured — `cap_add: [NET_RAW]` is set in `docker-compose.yml` and the nmap binary has `cap_net_raw` applied by the Dockerfile. Switch `scan_arguments` in `config.yaml`:

```yaml
port_scanning:
  scan_arguments: "-sS -T4 -sV --version-intensity 2 --open"
```

**Local Python:** run with `sudo`, or grant `cap_net_raw` to your nmap binary:

```bash
sudo setcap cap_net_raw+ep $(which nmap)
```

### Disabling port scanning

```yaml
port_scanning:
  enabled: false
```

---

## HTTP Security Headers

Monitored headers per subdomain on every scan:

| Header | Why it matters |
|--------|---------------|
| `Strict-Transport-Security` | Forces HTTPS, prevents SSL stripping |
| `Content-Security-Policy` | Blocks XSS and data injection |
| `X-Frame-Options` | Prevents clickjacking |
| `X-Content-Type-Options` | Blocks MIME-type sniffing |
| `Referrer-Policy` | Controls referrer information leakage |
| `Permissions-Policy` | Restricts browser feature access |

Information-leaking headers also tracked: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`.

A `SECURITY_HEADER_REMOVED` change event (severity MEDIUM) fires whenever a previously present security header disappears.

---

## Notification Setup

### Slack

1. Go to https://api.slack.com/apps → Create App → Incoming Webhooks
2. Enable Incoming Webhooks → Add New Webhook to Workspace
3. Copy the webhook URL into `config.yaml`:

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/T00/B00/xxxx"
```

### Telegram

1. Message [@BotFather](https://t.me/BotFather) → `/newbot` → copy the token
2. Add the bot to your channel/group
3. Get your chat ID: message the bot, then visit `https://api.telegram.org/bot<TOKEN>/getUpdates`

```yaml
notifications:
  telegram:
    enabled: true
    bot_token: "123456789:ABCdef..."
    chat_id: "-1001234567890"
```

### Discord

1. Server Settings → Integrations → Webhooks → New Webhook
2. Copy the webhook URL:

```yaml
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/000/xxx"
```

### Email

```yaml
notifications:
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_username: "you@gmail.com"
    smtp_password: "your-app-password"
    to_addresses:
      - "security@yourcompany.com"
```

> **Gmail users:** Generate an App Password at myaccount.google.com → Security → App Passwords

### API Keys (Optional — improves subdomain discovery)

```yaml
api_keys:
  virustotal: "your-vt-api-key"        # virustotal.com/gui/user/apikey
  securitytrails: "your-st-key"        # securitytrails.com/app/account/credentials
  shodan: "your-shodan-key"            # account.shodan.io
```

Without API keys, the tool uses free sources only (crt.sh, HackerTarget, AlienVault, Wayback Machine).

---

## CLI Reference

```
python assetmonitor.py [OPTIONS] COMMAND [ARGS]

Options:
  --config TEXT      Path to config.yaml  [default: config.yaml]
  --db TEXT          Path to SQLite database  [default: data/assetmonitor.db]
  --log-level TEXT   debug | info | warning | error  [default: INFO]
```

### Commands

#### `scan` — Run a monitoring scan

```bash
# Scan everything (subdomains + websites + port scans)
python assetmonitor.py scan

# Subdomain enumeration only
python assetmonitor.py scan --module subdomains

# Enumerate one domain specifically
python assetmonitor.py scan --module subdomains --domain example.com

# Port scan all live hosts
python assetmonitor.py scan --module ports

# Website crawl and change detection only
python assetmonitor.py scan --module websites

# Check known subdomains from subdomains.txt only
python assetmonitor.py scan --module known-subdomains
```

#### `add` — Add targets to monitoring

```bash
# Add a root domain (triggers full subdomain enumeration on next scan)
python assetmonitor.py add domain example.com

# Add a specific subdomain to monitor directly
python assetmonitor.py add subdomain admin.example.com

# Add a website URL for content monitoring
python assetmonitor.py add website https://app.example.com
```

#### `report` — View results in the terminal

```bash
# All discovered subdomains
python assetmonitor.py report --type subdomains

# Live subdomains only
python assetmonitor.py report --type subdomains --status alive

# All change events
python assetmonitor.py report --type changes

# Only CRITICAL and HIGH events
python assetmonitor.py report --type changes --severity HIGH

# Events from the last 24 hours
python assetmonitor.py report --type changes --since 24h

# Events from the last 7 days for one domain
python assetmonitor.py report --type changes --since 7d --domain example.com
```

#### `export` — Export to file

```bash
# JSON export (full inventory)
python assetmonitor.py export --format json --output report.json

# HTML report (styled, shareable)
python assetmonitor.py export --format html --output report.html

# Export for one domain only
python assetmonitor.py export --format html --output client_report.html --domain example.com
```

#### `daemon` — Start continuous monitoring + dashboard

```bash
# Start the scheduler and the web dashboard
python assetmonitor.py daemon
# Dashboard: http://localhost:5000
```

---

## Alert Severity Levels

| Severity | What triggers it | Example |
|----------|-----------------|---------|
| `CRITICAL` | Immediate action required | Subdomain takeover, Docker daemon exposed (2375), `.git`/`.env` exposed |
| `HIGH` | Investigate today | New live subdomain, RDP/VNC port opened, unauthenticated database exposed, admin panel found |
| `MEDIUM` | Review this week | New endpoint, tech stack change, security header removed, new JS bundle, SSH port opened |
| `LOW` | Informational | Port closed, content changed, new links, header value changed |
| `INFO` | Background noise | Dead subdomain, scan completed |

Set `min_severity: "HIGH"` to only be alerted on serious findings.

---

## Subdomain Enumeration — Techniques Used

| # | Technique | What it finds | Requires |
|---|-----------|--------------|----------|
| 1 | **Certificate Transparency** | Subdomains from TLS cert issuance (wildcard + apex queries against crt.sh) | Nothing |
| 2 | **DNS Brute Force** | Subdomains from wordlist resolution | Nothing |
| 3 | **Passive DNS** | Historical DNS data from 5 providers | Optional API keys |
| 4 | **Wayback Machine** | Historically crawled subdomains | Nothing |
| 5 | **SSL SAN Extraction** | Subdomains from cert SAN fields | Nothing |
| 6 | **JS File Analysis** | API hosts/subdomains in JS bundles | Nothing |
| 7 | **DNS Records** | MX, NS, TXT, SOA subdomain references | Nothing |
| 8 | **Zone Transfer** | Full DNS zone if misconfigured | Nothing |
| 9 | **Reverse IP Lookup** | Co-hosted domains on same IP | Nothing |
| 10 | **Search Engine Dorking** | Indexed subdomains from Google/Bing | Optional |

---

## Change Detection — What Gets Monitored

| Detection | What it catches |
|-----------|----------------|
| **Content Hash** | Any page content change (strips dynamic tokens before hashing) |
| **DOM Structural Diff** | New forms, scripts, iframes, navigation items |
| **Endpoint Inventory** | New or removed URL paths and API endpoints |
| **Technology Stack** | Framework/server/library version changes |
| **Response Size Anomaly** | Statistical outlier responses (>2σ from mean) — catches defacement/injection |
| **Asset Tracking** | New JS files, changed JS hashes, new external script domains |
| **Port Changes** | Opened or closed TCP/UDP ports on live hosts |
| **Security Headers** | Added, removed, or changed HTTP security headers |

---

## Project Structure

```
asset-monitor/
├── assetmonitor.py          # Entry point
├── config.yaml.example      # Configuration template
├── requirements.txt         # Python dependencies
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── domains.txt.example
├── subdomains.txt.example
├── websites.txt.example
├── wordlists/
│   ├── subdomains.txt           # 243-entry default wordlist
│   └── subdomains-5000.txt      # 5 000-entry extended wordlist (default)
├── data/                    # SQLite database (created on first run)
└── src/
    ├── config.py            # Config loader (Pydantic v2)
    ├── database.py          # SQLite ORM (SQLAlchemy 2.x)
    ├── cli.py               # CLI commands (Click)
    ├── scheduler.py         # Daemon scheduler (APScheduler)
    ├── enumeration/         # 10 subdomain discovery techniques
    ├── verification/        # DNS, HTTP, fingerprint, takeover, classifier
    ├── monitoring/          # BFS crawler, JS analyzer, security files
    ├── detection/           # 6 change detection engines
    ├── scanning/            # nmap port scanner + orchestration manager
    ├── notifications/       # Slack, Telegram, Discord, Email, Webhook
    ├── reporting/           # JSON and HTML exporters
    └── web/
        ├── server.py        # Flask dashboard server + REST API
        └── templates/
            └── dashboard.html   # Single-page browser dashboard
```

---

## Typical Workflow for a Pentest Engagement

```bash
# Day 1 — Set up monitoring before you start testing
echo "client.com" >> domains.txt
python assetmonitor.py scan --module subdomains --domain client.com
python assetmonitor.py report --type subdomains --status alive

# Start the dashboard to see everything at a glance
python assetmonitor.py daemon &
# http://localhost:5000

# Immediately port-scan all live hosts found
python assetmonitor.py scan --module ports

# Mid-engagement — check what changed since yesterday
python assetmonitor.py report --type changes --since 24h

# End of engagement — export full inventory
python assetmonitor.py export --format html --output client_assets.html
python assetmonitor.py export --format json --output client_assets.json
```

---

## Troubleshooting

**`Config file not found`**
```bash
cp config.yaml.example config.yaml
```

**`ModuleNotFoundError`**
```bash
# Make sure you're using the virtual environment
source venv/bin/activate
pip install -r requirements.txt
```

**`nmap: command not found` (local Python mode)**
```bash
# macOS
brew install nmap
# Ubuntu / Debian
sudo apt-get install nmap
# Windows — download installer from https://nmap.org/download.html
```

**Port scanning returns no results**
```
1. Confirm nmap is installed: nmap --version
2. Check port_scanning.enabled: true in config.yaml
3. Port scans only run against subdomains with status "alive" — run a subdomain
   scan first so the DB knows which hosts are live.
4. Run with --log-level debug to see per-host nmap output.
```

**Dashboard not loading (`http://localhost:5000`)**
```
1. Check web.enabled: true in config.yaml
2. Confirm the daemon is running: docker-compose logs -f
3. On Linux, confirm port 5000 is not blocked: sudo ufw allow 5000
4. If running locally (not Docker), make sure no other service is on port 5000.
   Change web.port in config.yaml if needed.
```

**DNS brute force is very slow**
```
Lower max_dns_concurrent in config.yaml, or switch to the smaller wordlist:
wordlist_path: "./wordlists/subdomains.txt"  # 243 entries
```

**No alerts being sent**
```
1. Check notifications.min_severity — set to LOW to test all alerts
2. Verify webhook URL is correct
3. Run with --log-level debug to see notification dispatch logs
```

**Docker container keeps restarting**
```bash
docker-compose logs assetmonitor
# Common causes: missing config.yaml, missing domains.txt,
# or data/ directory not writable by UID 1000 (Linux only).
# Fix: chown 1000:1000 data/
```

**`Subdomain takeover` alert — what do I do?**
```
A dangling CNAME points to an unclaimed resource (e.g. deleted S3 bucket,
removed Heroku app). Claim the resource immediately or remove the DNS record.
```

**SYN scanning fails / nmap permission denied (local mode)**
```bash
# Grant cap_net_raw to nmap so it can send raw packets without sudo
sudo setcap cap_net_raw+ep $(which nmap)

# Then switch scan mode in config.yaml:
# scan_arguments: "-sS -T4 -sV --version-intensity 2 --open"
```

---

## Wordlists

Two wordlists are shipped:

| File | Entries | Use |
|------|---------|-----|
| `wordlists/subdomains.txt` | 243 | Fast scan, low noise |
| `wordlists/subdomains-5000.txt` | 5 000 | Default — good coverage across web, API, admin, dev, DB, cloud, CI/CD, regional, and infra prefixes |

Switch wordlists in `config.yaml`:

```yaml
enumeration:
  wordlist_path: "./wordlists/subdomains.txt"        # fast
  # wordlist_path: "./wordlists/subdomains-5000.txt" # thorough (default)
```

For deeper coverage, drop in any SecLists-compatible wordlist:

```bash
curl -o wordlists/subdomains-top1m.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## License

For internal and authorized security testing use only. Do not use against systems you do not have explicit written permission to test.
