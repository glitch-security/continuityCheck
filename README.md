# AssetMonitor

Automated web asset and subdomain monitoring platform for security professionals.

Continuously discovers subdomains, monitors websites for structural changes, detects new endpoints and features, and sends real-time alerts the moment anything changes.

---

## What It Does

| Capability | Detail |
|------------|--------|
| **Subdomain Discovery** | 10 parallel enumeration techniques per domain |
| **Live Host Verification** | DNS + HTTP probing, fingerprinting, takeover detection |
| **Website Monitoring** | BFS crawler, JS analysis, security file checks |
| **Change Detection** | Content hash, DOM diff, endpoint delta, asset tracking, size anomaly |
| **Alerts** | Slack, Telegram, Discord, Email, Webhook — all configurable |
| **Persistence** | SQLite database — full history of every scan |
| **Reporting** | Terminal tables, JSON export, HTML report |

---

## Quick Start (5 minutes)

### Option A — Python (Local)

**Requirements:** Python 3.11+, pip

```bash
# 1. Clone or navigate to the project
cd asset-monitor

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate       # macOS / Linux
# venv\Scripts\activate        # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up configuration
cp config.yaml.example config.yaml

# 5. Add your targets
echo "example.com" >> domains.txt
echo "https://example.com" >> websites.txt

# 6. Run your first scan
python assetmonitor.py scan --module subdomains --domain example.com

# 7. View results
python assetmonitor.py report --type subdomains
```

---

### Option B — Docker (Recommended for Continuous Monitoring)

**Requirements:** Docker, Docker Compose

```bash
# 1. Set up config and input files
cp config.yaml.example config.yaml
cp domains.txt.example domains.txt
cp subdomains.txt.example subdomains.txt
cp websites.txt.example websites.txt

# 2. Edit your targets (one per line, remove the example entries)
nano domains.txt
nano websites.txt

# 3. Edit config.yaml — add your notification webhooks
nano config.yaml

# 4. Start the daemon
docker-compose up -d

# 5. View logs
docker-compose logs -f

# 6. Run a manual scan inside the container
docker-compose exec assetmonitor python assetmonitor.py scan
```

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
# Full FQDNs — will be probed and monitored for changes
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

Open `config.yaml` and configure the sections you need.

### Minimum required configuration

```yaml
# How often to scan (minutes)
scan:
  interval_minutes: 360

# At minimum, enable one notification channel
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
| `enumeration.techniques` | `certificate_transparency` | `true` | Query crt.sh CT logs |
| `enumeration.techniques` | `dns_bruteforce` | `true` | Wordlist-based DNS brute force |
| `enumeration.techniques` | `passive_dns` | `true` | Query passive DNS databases |
| `enumeration.techniques` | `wayback_machine` | `true` | Mine Wayback Machine |
| `enumeration.techniques` | `ssl_san_extraction` | `true` | Extract TLS certificate SANs |
| `enumeration.techniques` | `js_analysis` | `true` | Parse JS files for subdomains |
| `enumeration.techniques` | `zone_transfer` | `true` | Attempt DNS AXFR |
| `enumeration.techniques` | `reverse_ip` | `true` | Reverse IP lookup |
| `enumeration` | `wordlist_path` | `./wordlists/subdomains.txt` | DNS brute force wordlist |
| `enumeration` | `max_dns_concurrent` | `50` | Max parallel DNS queries |
| `verification` | `ports` | `[80,443,8080,8443,8888]` | Ports to probe |
| `verification` | `takeover_check` | `true` | Check for subdomain takeover |
| `monitoring.change_detection` | `content_hash` | `true` | Hash-based content change |
| `monitoring.change_detection` | `dom_structural_diff` | `true` | HTML structure diff |
| `monitoring.change_detection` | `endpoint_inventory` | `true` | Track URL endpoints |
| `monitoring.change_detection` | `technology_stack` | `true` | Detect tech changes |
| `monitoring.change_detection` | `response_size_anomaly` | `true` | Flag size anomalies |
| `monitoring.change_detection` | `asset_tracking` | `true` | Track JS/CSS/image files |
| `notifications` | `min_severity` | `MEDIUM` | Minimum severity to alert on |

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
    smtp_password: "your-app-password"    # use an App Password for Gmail
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

Without API keys, the tool degrades gracefully to free sources only (crt.sh, HackerTarget, AlienVault, Wayback Machine).

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
# Scan everything
python assetmonitor.py scan

# Subdomain enumeration only
python assetmonitor.py scan --module subdomains

# Enumerate one domain specifically
python assetmonitor.py scan --module subdomains --domain example.com

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
python assetmonitor.py report --type subdomains --status LIVE

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
python assetmonitor.py export --format html --output example_report.html --domain example.com
```

#### `daemon` — Start continuous monitoring

```bash
# Run the scheduled daemon (uses interval_minutes from config)
python assetmonitor.py daemon
```

---

## Alert Severity Levels

| Severity | What triggers it | Example |
|----------|-----------------|---------|
| `CRITICAL` | Immediate action required | Subdomain takeover, `.git` or `.env` exposed, supply-chain JS injection |
| `HIGH` | Investigate today | New live subdomain, admin panel appeared, new auth endpoint |
| `MEDIUM` | Review this week | New endpoint, tech stack change, new JS bundle, size anomaly |
| `LOW` | Informational | Content changed, new links, header changes |
| `INFO` | Background noise | Dead subdomain, scan completed |

Set `min_severity: "HIGH"` to only be alerted on serious findings.

---

## Subdomain Enumeration — Techniques Used

| # | Technique | What it finds | Requires |
|---|-----------|--------------|----------|
| 1 | **Certificate Transparency** | Subdomains from TLS cert issuance | Nothing |
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

---

## Project Structure

```
asset-monitor/
├── assetmonitor.py          # Entry point
├── config.yaml.example      # Configuration template
├── requirements.txt         # Python dependencies
├── Dockerfile
├── docker-compose.yml
├── domains.txt.example
├── subdomains.txt.example
├── websites.txt.example
├── wordlists/
│   └── subdomains.txt       # DNS brute force wordlist (243 entries)
├── data/                    # SQLite database (created on first run)
└── src/
    ├── config.py            # Config loader (Pydantic)
    ├── database.py          # SQLite ORM (SQLAlchemy)
    ├── cli.py               # CLI commands (Click)
    ├── scheduler.py         # Daemon scheduler (APScheduler)
    ├── enumeration/         # 10 subdomain discovery techniques
    ├── verification/        # DNS, HTTP, fingerprint, takeover, classifier
    ├── monitoring/          # BFS crawler, JS analyzer, security files
    ├── detection/           # 6 change detection engines
    ├── notifications/       # Slack, Telegram, Discord, Email, Webhook
    └── reporting/           # JSON and HTML exporters
```

---

## Typical Workflow for a Pentest Engagement

```bash
# Day 1 — Set up monitoring before you start testing
echo "client.com" >> domains.txt
python assetmonitor.py scan --module subdomains --domain client.com
python assetmonitor.py report --type subdomains --status LIVE

# Get notified as new assets appear during the engagement
python assetmonitor.py daemon &

# Mid-engagement — check what changed
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
# Make sure you're using the virtualenv
source venv/bin/activate
pip install -r requirements.txt
```

**DNS brute force is very slow**
```
Reduce the wordlist or lower max_dns_concurrent in config.yaml.
Default wordlist has 243 entries — add more from SecLists for deeper coverage.
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
# Usually: missing config.yaml or domains.txt — create them first
```

**`Subdomain takeover` alert — what do I do?**
```
A dangling CNAME points to an unclaimed resource (e.g. deleted S3 bucket,
removed Heroku app). Claim the resource immediately or remove the DNS record.
```

---

## Extending the Wordlist

The default wordlist has 243 entries. For deeper coverage, use SecLists:

```bash
# Download a larger wordlist from SecLists
curl -o wordlists/subdomains-top5000.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt

# Update config.yaml to use it
# wordlist_path: "./wordlists/subdomains-top5000.txt"
```

---

## License

For internal and authorized security testing use only. Do not use against systems you do not have explicit written permission to test.
