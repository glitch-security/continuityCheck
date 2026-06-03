# AssetMonitor — Test Agent Instructions

> **Instructions for a Claude agent performing full test coverage, security review, and bug reporting on the AssetMonitor codebase.**
>
> Read this entire file before doing anything. Follow every section in order. Do not skip steps.

---

## 0. Before You Start

### Read these files first (in this order)
1. `CODEBASE.md` — full architectural reference
2. `README.md` — operational overview
3. `src/database.py` — all models and DatabaseManager methods
4. `src/web/server.py` — all Flask routes
5. `src/cli.py` — CLI commands
6. `src/scheduler.py` — scan orchestration
7. `src/config.py` — Pydantic config models
8. `src/web/templates/login.html` — login page
9. `src/web/templates/dashboard.html` — dashboard SPA

### Tools and agents to use

You MUST use the following Claude Code subagents during this session. Spawn them as directed in each section below:

| Agent | When to use |
|-------|-------------|
| `everything-claude-code:python-reviewer` | After each module is tested — review for Pythonic correctness, type hints, error handling |
| `everything-claude-code:security-reviewer` | After all tests run — full security audit of all code |
| `everything-claude-code:silent-failure-hunter` | After security review — hunt swallowed errors and bad fallbacks |
| `everything-claude-code:code-reviewer` | Final pass — overall code quality and maintainability |
| `everything-claude-code:type-design-analyzer` | On `database.py` and `config.py` — type safety audit |

---

## 1. Environment Setup

```bash
# Confirm Python 3.11+ is available
python3 --version

# Create and activate virtualenv
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Confirm the project root is the working directory
ls assetmonitor.py src/ docker-compose.yml
```

If `requirements.txt` is missing entries that cause `ImportError` during tests, note them in the report under **Dependency Issues**.

---

## 2. Static Analysis Pass

Run these before writing any tests. Record all output in the report.

```bash
# Type checking
pip install mypy
mypy src/ --ignore-missing-imports --no-strict-optional 2>&1 | tee /tmp/mypy_output.txt

# Linting
pip install ruff
ruff check src/ 2>&1 | tee /tmp/ruff_output.txt

# Security-focused static scan
pip install bandit
bandit -r src/ -f txt 2>&1 | tee /tmp/bandit_output.txt
```

Record all ERROR and WARNING lines from each tool in the report under **Static Analysis Findings**.

---

## 3. Database Layer Tests

File: `src/database.py`

Write and run the following tests using `pytest` (or inline `python3 -c` assertions). Use `:memory:` for all DB tests.

### 3.1 Core model creation
```python
from src.database import DatabaseManager
db = DatabaseManager(':memory:')
# Verify all tables were created
from sqlalchemy import inspect
inspector = inspect(db._engine)
expected_tables = [
    'domains', 'subdomains', 'subdomain_scans', 'endpoints',
    'assets', 'change_events', 'port_scans', 'open_ports',
    'scan_profiles', 'app_settings'
]
missing = [t for t in expected_tables if t not in inspector.get_table_names()]
assert not missing, f"Missing tables: {missing}"
```

### 3.2 Built-in profile seeding
```python
profiles = db.get_all_profiles()
assert len(profiles) == 4
names = {p.name for p in profiles}
assert names == {'Passive Only', 'Stealth', 'Standard', 'Aggressive'}
assert all(p.is_builtin for p in profiles)
```

### 3.3 Domain CRUD
```python
dom = db.add_domain('example.com')
assert dom.id is not None
assert dom.domain == 'example.com'

# Idempotent add
dom2 = db.add_domain('example.com')
assert dom2.id == dom.id

# get_domain
result = db.get_domain('example.com')
assert result is not None

# delete_domain
assert db.delete_domain(dom.id) is True
assert db.get_domain('example.com') is None
assert db.delete_domain(999) is False  # non-existent
```

### 3.4 Subdomain CRUD
```python
dom = db.add_domain('example.com')
sub, is_new = db.upsert_subdomain('api.example.com', dom.id, status='alive', http_status=200)
assert is_new is True

sub2, is_new2 = db.upsert_subdomain('api.example.com', dom.id, status='dead')
assert is_new2 is False
assert sub2.status == 'dead'
assert sub2.id == sub.id

live = db.get_live_subdomains(dom.id)
assert len(live) == 0  # status is now dead
```

### 3.5 Change events
```python
ev = db.add_change_event('PORT_OPENED', 'HIGH', 'api.example.com', 'Port 22 opened', {'port': 22})
assert ev.id is not None
assert ev.alerted is False

events = db.get_recent_events(hours=24)
assert any(e.id == ev.id for e in events)

db.mark_events_alerted([ev.id])
# Reload and verify
events = db.get_recent_events(hours=24)
alerted_ev = next(e for e in events if e.id == ev.id)
assert alerted_ev.alerted is True
```

### 3.6 AppSetting operations
```python
# get_setting with default
assert db.get_setting('nonexistent', 'fallback') == 'fallback'
assert db.get_setting('nonexistent') is None

# set and get
db.set_setting('test:key', 'hello')
assert db.get_setting('test:key') == 'hello'

# update
db.set_setting('test:key', 'world')
assert db.get_setting('test:key') == 'world'

# None value
db.set_setting('test:null', None)
assert db.get_setting('test:null') is None
```

### 3.7 Config override operations
```python
db.set_config_overrides({'scan': {'interval_minutes': 30, 'max_crawl_depth': 2}})
overrides = db.get_config_overrides()
assert overrides['scan']['interval_minutes'] == 30
assert overrides['scan']['max_crawl_depth'] == 2

# Overwrite clears previous and sets new
db.set_config_overrides({'scan': {'interval_minutes': 60}})
overrides = db.get_config_overrides()
assert overrides['scan']['interval_minutes'] == 60
assert 'max_crawl_depth' not in overrides.get('scan', {})
```

### 3.8 apply_settings_to_config
```python
from src.config import load_config
config = load_config('config.yaml')
db.set_config_overrides({'scan': {'interval_minutes': 999}})
db.apply_settings_to_config(config)
assert config.scan.interval_minutes == 999
```

### 3.9 User management
```python
import hashlib

# No users initially
assert db.list_users() == []

# Create user
pw_hash = 'sha256:' + hashlib.sha256(b'testpass').hexdigest()
db.set_user('alice', pw_hash, 'admin')

users = db.list_users()
assert len(users) == 1
assert users[0]['username'] == 'alice'
assert users[0]['role'] == 'admin'

# verify_password — correct
assert db.verify_password('alice', 'testpass') == 'admin'

# verify_password — wrong password
assert db.verify_password('alice', 'wrongpass') is None

# verify_password — non-existent user
assert db.verify_password('nobody', 'pass') is None

# delete user
assert db.delete_user('alice') is True
assert db.delete_user('alice') is False  # already gone
assert db.list_users() == []
```

### 3.10 ensure_default_admin
```python
# No env var set — should create admin and return password
import os
os.environ.pop('DASHBOARD_SECRET', None)
db2 = DatabaseManager(':memory:')
pwd = db2.ensure_default_admin()
assert pwd is not None
assert len(pwd) > 8
assert db2.verify_password('admin', pwd) == 'admin'

# Called again — no users created, returns None
pwd2 = db2.ensure_default_admin()
assert pwd2 is None

# With DASHBOARD_SECRET set
os.environ['DASHBOARD_SECRET'] = 'mysecret123'
db3 = DatabaseManager(':memory:')
result = db3.ensure_default_admin()
assert result is None  # doesn't return the password when env var is set
assert db3.verify_password('admin', 'mysecret123') == 'admin'
os.environ.pop('DASHBOARD_SECRET')
```

### 3.11 Flask secret key stability
```python
s1 = db.get_or_create_flask_secret()
s2 = db.get_or_create_flask_secret()
assert s1 == s2
assert len(s1) == 64  # 32 bytes hex = 64 chars
```

### 3.12 Port scan operations
```python
dom = db.add_domain('example.com')
sub, _ = db.upsert_subdomain('api.example.com', dom.id)
scan = db.add_port_scan(
    host='api.example.com',
    subdomain_id=sub.id,
    status='up',
    scan_duration=1.5,
    ports=[{'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'product': 'nginx', 'version': '1.24', 'extrainfo': ''}]
)
assert scan.id is not None

latest = db.get_latest_port_scan('api.example.com')
assert latest.id == scan.id

all_scans = db.get_all_latest_port_scans()
assert any(s.host == 'api.example.com' for s in all_scans)
ports = db.get_open_ports_for_scan(scan.id)
assert len(ports) == 1
assert ports[0].port == 80
```

### 3.13 Dashboard summary
```python
summary = db.get_dashboard_summary()
required_keys = ['domains', 'subdomains_total', 'subdomains_live', 'open_ports_total', 'events_24h', 'critical_24h', 'high_24h']
for k in required_keys:
    assert k in summary, f"Missing key: {k}"
```

### 3.14 get_all_domains_with_stats
```python
dom = db.add_domain('test.com')
sub, _ = db.upsert_subdomain('www.test.com', dom.id, status='alive')
rows = db.get_all_domains_with_stats()
row = next(r for r in rows if r['domain'] == 'test.com')
assert row['total_subs'] == 1
assert row['live_subs'] == 1
assert row['profile_id'] is None
```

### 3.15 Profile operations
```python
# Cannot edit built-in
result = db.update_profile(1, name='Modified')
assert result is None

# Cannot delete built-in
assert db.delete_profile(1) is False

# Create custom profile
p = db.create_profile('My Profile', 'A test profile', {'scan_mode': 'open'})
assert p.id is not None
assert not p.is_builtin

# Update custom
p2 = db.update_profile(p.id, name='Updated Profile')
assert p2.name == 'Updated Profile'

# Assign to domain
dom = db.add_domain('assign-test.com')
assert db.set_domain_profile(dom.id, p.id) is True
assert db.set_domain_profile(999, p.id) is False  # non-existent domain

# Delete custom
assert db.delete_profile(p.id) is True
# Domain profile_id should be cleared (ON DELETE SET NULL)
rows = db.get_all_domains_with_stats()
row = next(r for r in rows if r['domain'] == 'assign-test.com')
assert row['profile_id'] is None
```

### 3.16 get_domain_details
```python
dom = db.add_domain('detail.com')
sub, _ = db.upsert_subdomain('www.detail.com', dom.id, status='alive')
details = db.get_domain_details(dom.id)
assert details is not None
assert details['domain']['domain'] == 'detail.com'
assert 'stats' in details
assert 'subdomains' in details
assert 'port_scans' in details
assert 'recent_changes' in details
assert db.get_domain_details(99999) is None
```

**After completing 3.x tests, spawn:**
```
Agent(subagent_type="everything-claude-code:python-reviewer",
      prompt="Review src/database.py for: correct SQLAlchemy 2.x session handling, 
      missing flush() calls before refresh(), transaction isolation, error handling 
      in all methods, correct use of expire_on_commit=False, type annotation completeness. 
      Flag any method that could silently fail or return stale data.")
```

---

## 4. Web API Tests (Flask Test Client)

### 4.1 Setup helper
```python
import hashlib
from src.database import DatabaseManager
from src.config import load_config
from src.notifications.manager import NotificationManager
from src.scheduler import SchedManager
from src.web.server import create_app

def make_test_app():
    db = DatabaseManager(':memory:')
    config = load_config('config.yaml')
    nm = NotificationManager(config, db)
    sched = SchedManager(config, db, nm)
    app = create_app(db, config, sched)
    client = app.test_client()
    # Create admin user
    pw_hash = 'sha256:' + hashlib.sha256(b'testpass').hexdigest()
    db.set_user('admin', pw_hash, 'admin')
    # Log in
    client.post('/login', json={'username': 'admin', 'password': 'testpass'})
    return app, client, db, config, sched
```

### 4.2 Auth routes
```python
app, client, db, config, sched = make_test_app()

# /health — no auth required
r = client.get('/health')
assert r.status_code == 200
assert r.get_json()['status'] == 'ok'

# Unauthenticated client
unauth = app.test_client()
assert unauth.get('/').status_code == 302  # redirect to /login
assert unauth.get('/api/summary').status_code == 401
assert unauth.get('/api/domains').status_code == 401

# Login with wrong creds
r = unauth.post('/login', json={'username': 'admin', 'password': 'wrong'})
assert r.status_code == 401

# Login with correct creds
r = unauth.post('/login', json={'username': 'admin', 'password': 'testpass'})
assert r.status_code == 200
assert r.get_json()['ok'] is True

# After login, / should return 200
assert unauth.get('/').status_code == 200

# /api/session returns current user
r = client.get('/api/session')
d = r.get_json()
assert d['authenticated'] is True
assert d['username'] == 'admin'

# Empty body login
r = unauth.post('/login', json={})
assert r.status_code == 400
```

### 4.3 Summary and domain APIs
```python
app, client, db, config, sched = make_test_app()

r = client.get('/api/summary')
assert r.status_code == 200
d = r.get_json()
assert 'domains' in d
assert 'events_24h' in d

r = client.get('/api/domains')
assert r.status_code == 200
assert isinstance(r.get_json(), list)

r = client.get('/api/subdomains')
assert r.status_code == 200

r = client.get('/api/ports')
assert r.status_code == 200

r = client.get('/api/headers')
assert r.status_code == 200

r = client.get('/api/changes')
assert r.status_code == 200

r = client.get('/api/changes?hours=24')
assert r.status_code == 200

r = client.get('/api/changes?hours=99999')  # clamped to 8760
assert r.status_code == 200
```

### 4.4 Target CRUD
```python
app, client, db, config, sched = make_test_app()

# Add domain
r = client.post('/api/targets', json={'type': 'domain', 'value': 'test.com'})
assert r.status_code == 201
domain_id = r.get_json()['id']

# Add domain — duplicate
r = client.post('/api/targets', json={'type': 'domain', 'value': 'test.com'})
assert r.status_code == 201  # idempotent

# Add subdomain
r = client.post('/api/targets', json={'type': 'subdomain', 'value': 'api.test.com'})
assert r.status_code == 201

# Add website
r = client.post('/api/targets', json={'type': 'website', 'value': 'https://test.com'})
assert r.status_code == 201

# Missing value
r = client.post('/api/targets', json={'type': 'domain', 'value': ''})
assert r.status_code == 400

# Invalid type
r = client.post('/api/targets', json={'type': 'invalid', 'value': 'test.com'})
assert r.status_code == 400

# Delete domain
r = client.delete(f'/api/targets/domain/{domain_id}')
assert r.status_code == 200

# Delete non-existent
r = client.delete('/api/targets/domain/99999')
assert r.status_code == 404
```

### 4.5 Profile API
```python
app, client, db, config, sched = make_test_app()

# List profiles — 4 built-ins
r = client.get('/api/profiles')
assert r.status_code == 200
profiles = r.get_json()
assert len(profiles) == 4

# Create custom profile
r = client.post('/api/profiles', json={
    'name': 'My Profile',
    'description': 'Test',
    'settings': {'scan_mode': 'open'}
})
assert r.status_code == 201
pid = r.get_json()['id']

# Missing name
r = client.post('/api/profiles', json={'description': 'no name'})
assert r.status_code == 400

# Update custom
r = client.put(f'/api/profiles/{pid}', json={'name': 'Updated'})
assert r.status_code == 200
assert r.get_json()['name'] == 'Updated'

# Update built-in — should fail
r = client.put('/api/profiles/1', json={'name': 'Hacked'})
assert r.status_code == 404

# Delete custom
r = client.delete(f'/api/profiles/{pid}')
assert r.status_code == 200

# Delete built-in — should fail
r = client.delete('/api/profiles/1')
assert r.status_code == 404

# Delete non-existent
r = client.delete('/api/profiles/99999')
assert r.status_code == 404
```

### 4.6 PATCH domain profile assignment
```python
app, client, db, config, sched = make_test_app()
r = client.post('/api/targets', json={'type': 'domain', 'value': 'patch-test.com'})
domain_id = r.get_json()['id']

# Assign built-in profile
r = client.patch(f'/api/targets/domain/{domain_id}', json={'profile_id': 1})
assert r.status_code == 200

# Clear profile
r = client.patch(f'/api/targets/domain/{domain_id}', json={'profile_id': None})
assert r.status_code == 200

# Missing profile_id key
r = client.patch(f'/api/targets/domain/{domain_id}', json={})
assert r.status_code == 400

# Non-existent domain
r = client.patch('/api/targets/domain/99999', json={'profile_id': 1})
assert r.status_code == 404
```

### 4.7 Domain details
```python
app, client, db, config, sched = make_test_app()
r = client.post('/api/targets', json={'type': 'domain', 'value': 'detail-test.com'})
domain_id = r.get_json()['id']

r = client.get(f'/api/domains/{domain_id}/details')
assert r.status_code == 200
d = r.get_json()
assert 'domain' in d
assert 'stats' in d
assert 'subdomains' in d
assert 'port_scans' in d
assert 'recent_changes' in d

r = client.get('/api/domains/99999/details')
assert r.status_code == 404
```

### 4.8 Settings API
```python
app, client, db, config, sched = make_test_app()

# GET settings — empty initially
r = client.get('/api/settings')
assert r.status_code == 200
assert isinstance(r.get_json(), dict)

# POST settings
r = client.post('/api/settings', json={
    'scan': {'interval_minutes': 120, 'max_crawl_depth': 5},
    'notifications': {'min_severity': 'HIGH'}
})
assert r.status_code == 200
assert r.get_json()['saved'] is True

# Verify config was updated
assert config.scan.interval_minutes == 120
assert config.scan.max_crawl_depth == 5

# GET settings now returns stored values
r = client.get('/api/settings')
d = r.get_json()
assert d['scan']['interval_minutes'] == 120

# POST empty — should clear overrides
r = client.post('/api/settings', json={})
assert r.status_code == 200
```

### 4.9 User management API
```python
app, client, db, config, sched = make_test_app()

# List users
r = client.get('/api/users')
assert r.status_code == 200
users = r.get_json()
assert any(u['username'] == 'admin' for u in users)

# Create user
r = client.post('/api/users', json={'username': 'viewer1', 'password': 'pass123', 'role': 'viewer'})
assert r.status_code == 201

# Invalid role
r = client.post('/api/users', json={'username': 'x', 'password': 'y', 'role': 'superadmin'})
assert r.status_code == 400

# Missing password
r = client.post('/api/users', json={'username': 'x'})
assert r.status_code == 400

# Change password
r = client.post('/api/users/viewer1/password', json={'password': 'newpass'})
assert r.status_code == 200

# Verify new password works
assert db.verify_password('viewer1', 'newpass') == 'viewer'

# Delete user
r = client.delete('/api/users/viewer1')
assert r.status_code == 200

# Delete non-existent
r = client.delete('/api/users/nobody')
assert r.status_code == 404

# Cannot delete self
r = client.delete('/api/users/admin')
assert r.status_code == 400
```

### 4.10 Scan status and trigger
```python
app, client, db, config, sched = make_test_app()

# Scan status
r = client.get('/api/scan/status')
assert r.status_code == 200
d = r.get_json()
assert 'running' in d
assert d['running'] is False

# Trigger without scheduler — 503
app2, client2, db2, config2, _ = make_test_app()
app3 = create_app(db2, config2, None)  # no scheduler
client3 = app3.test_client()
pw_hash = 'sha256:' + hashlib.sha256(b'x').hexdigest()
db2.set_user('u', pw_hash, 'admin')
client3.post('/login', json={'username': 'u', 'password': 'x'})
r = client3.post('/api/scan/trigger', json={})
assert r.status_code == 503
```

**After completing section 4, spawn:**
```
Agent(subagent_type="everything-claude-code:python-reviewer",
      prompt="Review src/web/server.py for: correct Flask session usage (session variable 
      shadowing the Flask session import in api_subdomains and api_headers — 
      session_ vs session), consistent error handling, missing input validation, 
      routes that don't check user role (admin vs viewer), any route that modifies 
      state without checking role.")
```

---

## 5. CLI Tests

### 5.1 Help text
```bash
python assetmonitor.py --help
python assetmonitor.py daemon --help
python assetmonitor.py scan --help
python assetmonitor.py add --help
python assetmonitor.py report --help
python assetmonitor.py export --help
python assetmonitor.py reset-admin --help
```

All should return 0 exit code and meaningful help text. Record any missing or misleading descriptions.

### 5.1a reset-admin command
```bash
# Generate a random admin password
python assetmonitor.py reset-admin
# Verify it prints a password in the banner
# Verify the admin user record exists in the DB

# Set a known password
python assetmonitor.py reset-admin --password testpassword123
# Should print "Admin password updated." (no banner)

# Verify login works with the set password via Flask test client
# (see section 4.1 — verify_password returns "admin" role)
```

### 5.2 Add command
```bash
python assetmonitor.py add domain testcli.example.com
python assetmonitor.py add subdomain api.testcli.example.com
python assetmonitor.py add website https://testcli.example.com

# Verify in DB
python assetmonitor.py report --type subdomains
```

### 5.3 Report command
```bash
python assetmonitor.py report --type subdomains
python assetmonitor.py report --type changes
python assetmonitor.py report --type changes --severity HIGH
python assetmonitor.py report --type changes --since 24h
python assetmonitor.py report --type changes --since 7d
python assetmonitor.py report --type changes --since 30m
python assetmonitor.py report --type changes --since invalid   # should exit with error
```

### 5.4 Config loading
```bash
# Missing config
python assetmonitor.py --config /nonexistent/config.yaml report --type changes
# Should exit with non-zero and clear error, not a Python traceback
echo "Exit code: $?"
```

### 5.5 daemon command — does it start?
```bash
# Start daemon in background, let it run 10 seconds, kill it
timeout 10 python assetmonitor.py daemon || true
# Should not crash on startup
```

---

## 6. Scheduler Tests

### 6.1 reschedule method
```python
from src.database import DatabaseManager
from src.config import load_config
from src.notifications.manager import NotificationManager
from src.scheduler import SchedManager

db = DatabaseManager(':memory:')
config = load_config('config.yaml')
nm = NotificationManager(config, db)
sched = SchedManager(config, db, nm)

sched.start()
import time; time.sleep(1)

# reschedule while running
sched.reschedule(120)

# reschedule while stopped (should not raise)
sched.stop()
sched.reschedule(60)  # should silently no-op
```

### 6.2 _apply_profile_to_config
```python
from src.scheduler import _apply_profile_to_config
from src.config import load_config
import copy

config = load_config('config.yaml')
orig_interval = config.scan.interval_minutes

profile_settings = {
    'enumeration': {
        'certificate_transparency': False,
        'dns_bruteforce': False,
        'passive_dns': True,
    },
    'port_scanning': {'enabled': False, 'arguments': ''},
    'crawl': {'enabled': False, 'max_depth': 0, 'max_pages': 0},
}

cfg_copy = copy.deepcopy(config)
_apply_profile_to_config(cfg_copy, profile_settings)

assert cfg_copy.enumeration.techniques.certificate_transparency is False
assert cfg_copy.enumeration.techniques.dns_bruteforce is False
assert cfg_copy.enumeration.techniques.passive_dns is True
assert cfg_copy.port_scanning.enabled is False
assert cfg_copy.scan.max_crawl_depth == 0

# Original config should be unchanged
assert config.enumeration.techniques.dns_bruteforce == load_config('config.yaml').enumeration.techniques.dns_bruteforce
```

---

## 7. Config Tests

### 7.1 All config fields present
```python
from src.config import load_config
config = load_config('config.yaml')

# Verify key fields exist and have correct types
assert isinstance(config.scan.interval_minutes, int)
assert isinstance(config.scan.max_crawl_depth, int)
assert isinstance(config.enumeration.techniques.certificate_transparency, bool)
assert isinstance(config.port_scanning.enabled, bool)
assert isinstance(config.web.port, int)
assert isinstance(config.notifications.min_severity, str)
```

### 7.2 config.yaml.example completeness
Compare all fields used in `scheduler.py` and `src/enumeration/`, `src/verification/`, etc. against `config.yaml.example`. Note any fields referenced in code that are missing from the example config.

---

## 8. Edge Cases and Boundary Conditions

Test these manually and record results:

### 8.1 Empty database
- Start with a fresh DB (delete `data/assetmonitor.db`)
- Open dashboard — all tabs should load without JS errors
- Summary cards should show 0, not errors

### 8.2 Unicode and special characters in domain names
```python
db = DatabaseManager(':memory:')
# Punycode domain
dom = db.add_domain('xn--nxasmq6b.com')
assert dom is not None

# Long subdomain
long_fqdn = 'a' * 60 + '.example.com'
sub, _ = db.upsert_subdomain(long_fqdn, dom.id)
assert sub is not None
```

### 8.3 Large result sets
```python
db = DatabaseManager(':memory:')
dom = db.add_domain('big.com')
# Insert 500 subdomains
for i in range(500):
    db.upsert_subdomain(f'sub{i}.big.com', dom.id)

subs = db.get_all_domains_with_stats()
row = next(r for r in subs if r['domain'] == 'big.com')
assert row['total_subs'] == 500

# Dashboard summary should not timeout
summary = db.get_dashboard_summary()
assert summary['subdomains_total'] == 500
```

### 8.4 Concurrent writes (WAL mode)
```python
import threading
db = DatabaseManager('data/concurrent_test.db')
dom = db.add_domain('concurrent.com')
errors = []

def writer(i):
    try:
        db.upsert_subdomain(f'sub{i}.concurrent.com', dom.id)
    except Exception as e:
        errors.append(str(e))

threads = [threading.Thread(target=writer, args=(i,)) for i in range(50)]
for t in threads: t.start()
for t in threads: t.join()

assert not errors, f"Concurrent write errors: {errors}"
import os; os.remove('data/concurrent_test.db')
```

### 8.5 Malformed JSON in AppSetting
```python
db = DatabaseManager(':memory:')
# Directly corrupt a user entry
db.set_setting('user:broken', 'not-valid-json')
users = db.list_users()
# Should not crash, broken entry should be skipped or handled gracefully
```

### 8.6 API input boundary tests
```python
app, client, db, config, sched = make_test_app()

# Extremely long domain name
r = client.post('/api/targets', json={'type': 'domain', 'value': 'a' * 300 + '.com'})
# Should either succeed or return 400 — should NOT 500

# SQL injection attempt in domain
r = client.post('/api/targets', json={'type': 'domain', 'value': "'; DROP TABLE domains; --"})
# Should not cause a 500 or damage the DB

# XSS payload in domain
r = client.post('/api/targets', json={'type': 'domain', 'value': '<script>alert(1)</script>.com'})
# Should not cause a 500

# Empty JSON body
r = client.post('/api/targets', content_type='application/json', data='')
# Should return 400

# Non-JSON body
r = client.post('/api/targets', data='type=domain&value=test.com', content_type='application/x-www-form-urlencoded')
# Should return 400
```

---

## 9. Security Review

**After completing all tests above, spawn these agents sequentially:**

### 9.1 Security reviewer
```
Agent(subagent_type="everything-claude-code:security-reviewer",
      prompt="Perform a full security audit of the AssetMonitor codebase at 
      /path/to/asset-monitor/src/. 
      
      Focus areas in priority order:
      
      1. Authentication & Session Management (server.py):
         - Session fixation: is the session ID rotated after login?
         - CSRF: POST routes that modify state — is there CSRF protection?
         - Brute force: is there rate limiting on /login?
         - Session secret: is the Flask secret_key sufficiently random and stable?
         - Role enforcement: do viewer-role users have access to admin-only operations?
      
      2. Injection (database.py, server.py):
         - SQLAlchemy ORM usage — are all queries parameterised?
         - Any raw SQL strings that include user input?
         - LIKE queries in set_config_overrides — is the prefix anchored correctly?
      
      3. SSRF (server.py, scheduler.py, enumeration/):
         - User-supplied URLs in /api/targets — are they validated before fetching?
         - Website URLs stored in websites.txt — what prevents internal network scanning?
      
      4. Information disclosure:
         - Do error responses leak stack traces?
         - Are passwords or hashes ever logged?
         - Does /api/session leak sensitive data?
         - Do X-Powered-By or Server headers reveal the tech stack?
      
      5. Secrets management:
         - API keys stored in AppSetting — are they stored in plaintext?
         - Is there any hardcoded secret?
      
      6. Path traversal:
         - _append_to_file() in server.py — is the path fixed or user-controlled?
      
      7. Password security:
         - SHA-256 without salt — is this acceptable for an internal tool?
         - Minimum password length enforcement?
      
      Report each finding with: Title, Severity (CRITICAL/HIGH/MEDIUM/LOW), 
      Description, Attack scenario, Remediation.")
```

### 9.2 Silent failure hunter
```
Agent(subagent_type="everything-claude-code:silent-failure-hunter",
      prompt="Review src/database.py, src/web/server.py, src/scheduler.py, src/cli.py 
      for silent failures:
      - Exception handlers that log but don't propagate and leave state inconsistent
      - Methods that return None on failure with no indication of why
      - set_config_overrides() — if the DELETE + INSERT fails halfway, is the DB left inconsistent?
      - mark_events_alerted() — if called with empty list, does it silently succeed or error?
      - ensure_default_admin() — what happens if set_user() throws?
      - _apply_config_overrides() — what if setattr() throws on a Pydantic validator?
      Report each finding with file, line range, what fails silently, and what the consequence is.")
```

### 9.3 Type design analyzer
```
Agent(subagent_type="everything-claude-code:type-design-analyzer",
      prompt="Analyze type design in src/database.py and src/config.py:
      - Are Optional[str] returns consistently handled by callers?
      - The verify_password() return type is Optional[str] (role) — is this clear enough 
        or should it be a proper type?
      - AppSetting.value is Optional[str] — what happens when callers get None unexpectedly?
      - DatabaseManager methods that return bool for success — are callers checking the return?
      - JSON columns typed as Optional[Any] — is this too loose?
      Report mismatches between declared types and actual runtime values.")
```

---

## 10. Docker and Deployment Tests

Run these with the actual Docker container:

```powershell
# Build
docker compose build

# Start
docker compose up -d

# Check container is healthy
docker compose ps
# assetmonitor should show "healthy" after ~60s

# Check logs for admin credentials on first start
docker compose logs assetmonitor | head -50

# Verify /health endpoint
curl http://localhost:5000/health

# Verify /login redirects correctly without auth
curl -I http://localhost:5000/

# Verify /api/summary requires auth
curl http://localhost:5000/api/summary
# Should return {"error": "Unauthorized"}

# Test DASHBOARD_SECRET flow
docker compose down
# Add DASHBOARD_SECRET: "testpassword123" to docker-compose.yml
docker compose up -d
# Verify login works with admin / testpassword123
curl -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"testpassword123"}'

# Verify data persists across restart
docker compose restart assetmonitor
curl http://localhost:5000/health
# Wait 30s for container to come up
# Login should still work with same password
```

---

## 11. Known Issue: Session Variable Shadowing

**Check this specific bug in `server.py`:**

In `api_subdomains()` and `api_headers()`, the local variable `session_` is used instead of `session` to avoid shadowing the Flask `session` import. Verify that:
1. The Flask `session` import at the top of the file is used correctly in auth routes
2. The local `session_` variable in database query blocks does not shadow it
3. Run both API endpoints and confirm they return correct data

---

## 12. Report Format

Generate a file named `TEST_REPORT.md` with the following structure:

```markdown
# AssetMonitor Test Report
**Date:** YYYY-MM-DD
**Tester:** Claude Agent
**Codebase:** asset-monitor @ [commit hash if available]

---

## Executive Summary
[2-3 sentences: overall health, blocking issues, recommendation]

---

## Test Results

| Test Suite | Pass | Fail | Skip | Notes |
|------------|------|------|------|-------|
| Database Layer (3.x) | N | N | N | |
| Web API (4.x) | N | N | N | |
| CLI (5.x) | N | N | N | |
| Scheduler (6.x) | N | N | N | |
| Config (7.x) | N | N | N | |
| Edge Cases (8.x) | N | N | N | |
| Docker (10.x) | N | N | N | |

---

## Bugs Found

### BUG-001: [Title]
- **Severity:** CRITICAL / HIGH / MEDIUM / LOW
- **File:** src/xxx.py line N
- **Description:** What is broken
- **Reproduction:** Exact steps / code to reproduce
- **Expected:** What should happen
- **Actual:** What actually happens
- **Fix:** Specific recommended fix

[repeat for each bug]

---

## Security Findings

[Output from security-reviewer agent, formatted as findings]

---

## Silent Failures

[Output from silent-failure-hunter agent]

---

## Type Design Issues

[Output from type-design-analyzer agent]

---

## Static Analysis Summary

### mypy errors
[paste relevant errors]

### ruff warnings
[paste relevant warnings]

### bandit findings
[paste findings with severity]

---

## Missing Test Coverage

List any code paths that could not be tested and why:
- [path] — [reason]

---

## Dependency Issues

List any missing or version-conflicting dependencies:
- [package] — [issue]

---

## Recommendations (Priority Order)

1. [Most critical fix]
2. [Second priority]
...

---

## Notes for the Next Agent

[Any context, gotchas, or partial findings that the fix-agent should know]
```

---

## 13. Final Checklist Before Submitting Report

- [ ] All 3.x database tests run and results recorded
- [ ] All 4.x API tests run and results recorded
- [ ] All 5.x CLI tests run and results recorded
- [ ] Scheduler tests run
- [ ] Edge cases tested (8.1 through 8.6)
- [ ] `everything-claude-code:security-reviewer` spawned and output captured
- [ ] `everything-claude-code:silent-failure-hunter` spawned and output captured
- [ ] `everything-claude-code:type-design-analyzer` spawned and output captured
- [ ] `everything-claude-code:python-reviewer` spawned after sections 3 and 4
- [ ] Docker build and startup tested
- [ ] `TEST_REPORT.md` written with all sections complete
- [ ] Every bug has a reproduction case and a specific fix recommendation

---

## Important Notes for the Test Agent

1. **Do not modify production code** during testing. Record bugs, do not fix them. Fixes come after the report is reviewed.

2. **Use `:memory:` for all Python-level DB tests** to avoid polluting the real database.

3. **The `session` import conflict in `server.py`** — Flask's `session` is imported at module level. Inside route handlers that use SQLAlchemy sessions, the local variable must be named `session_` not `session`. Check every route that uses both.

4. **config.yaml must exist** at project root for tests that call `load_config('config.yaml')`. If it doesn't exist, copy from `config.yaml.example` first.

5. **Don't run actual nmap scans** during testing. The port scanning modules are out of scope for this test pass.

6. **Windows note:** If running on Windows, path separators in file-based tests may differ. Note any Windows-specific failures separately in the report.

7. **The `_append_to_file` function** in `server.py` writes to relative paths (`websites.txt`). In tests, this will write to the current working directory. Clean up any created `.txt` files after testing.
