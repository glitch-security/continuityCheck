"""
Flask web dashboard server.

Provides:
  GET  /                            — full dashboard HTML
  GET  /login                       — login page
  POST /login                       — authenticate (JSON body: {username, password})
  GET  /logout                      — clear session and redirect to /login
  GET  /health                      — Docker healthcheck endpoint (no auth required)
  GET  /api/summary                 — aggregated stat cards
  GET  /api/domains                 — all root domains with subdomain stats
  GET  /api/subdomains              — all subdomains with status + latest port data
  GET  /api/ports                   — latest port scan per host
  GET  /api/changes                 — recent change events (default: last 48h)
  GET  /api/headers                 — latest HTTP header snapshots per subdomain
  POST /api/targets                 — add a new domain / subdomain / website
  DELETE /api/targets/domain/<id>   — delete a root domain (cascade)
  PATCH /api/targets/domain/<id>    — assign a scan profile to a domain
  GET  /api/domains/<id>/details    — per-domain full detail payload
  GET  /api/profiles                — all scan profiles
  POST /api/profiles                — create a custom profile
  PUT  /api/profiles/<id>           — update a custom profile
  DELETE /api/profiles/<id>         — delete a custom profile
  POST /api/scan/trigger            — trigger an on-demand scan (background thread)
  GET  /api/scan/status             — current scan state
  GET  /api/settings                — current config overrides (from DB)
  POST /api/settings                — save config overrides
  GET  /api/session                 — current session info (username, role)
  GET  /api/users                   — list users
  POST /api/users                   — create a user
  DELETE /api/users/<username>      — delete a user
  POST /api/users/<username>/password — change a user's password

Runs in a daemon thread alongside APScheduler so it never blocks the scan
loop, and exits automatically when the main process exits.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import TYPE_CHECKING, Any, Optional

from flask import Flask, jsonify, redirect, render_template, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager
    from ..scheduler import SchedManager

logger = logging.getLogger(__name__)

# Compiled once — RFC 1123 / RFC 5321 domain name validation
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)$"
)

_limiter = Limiter(key_func=get_remote_address, default_limits=[])

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# ---------------------------------------------------------------------------
# Scan state — shared across Flask threads (protected by _scan_lock)
# ---------------------------------------------------------------------------

_scan_lock = threading.Lock()
_scan_state: dict = {
    "running": False,
    "started_at": None,
    "domain": None,
    "error": None,
    "last_completed": None,
    "last_subs_found": 0,
    "last_events": 0,
}


def _serial(obj: Any) -> Any:
    """JSON serialiser for datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")


def _ev_to_dict(ev: Any) -> dict:
    return {
        "id": ev.id,
        "event_type": ev.event_type,
        "severity": ev.severity,
        "target": ev.target,
        "description": ev.description,
        "detected_at": ev.detected_at.isoformat() if ev.detected_at else None,
        "alerted": ev.alerted,
        "diff_data": ev.diff_data,
    }


# Paths that never require authentication
_AUTH_EXEMPT = frozenset(["/login", "/logout", "/health"])


def create_app(
    db: "DatabaseManager",
    config: "AppConfig",
    sched_manager: Optional["SchedManager"] = None,
) -> Flask:
    app = Flask(__name__, template_folder=_TEMPLATE_DIR)
    _limiter.init_app(app)

    # Stable secret key — persists across container restarts via DB
    app.secret_key = db.get_or_create_flask_secret()
    app.permanent_session_lifetime = timedelta(days=30)

    # ------------------------------------------------------------------ #
    # Auth gate + CSRF validation
    # ------------------------------------------------------------------ #

    _CSRF_EXEMPT_METHODS = frozenset(["GET", "HEAD", "OPTIONS"])

    @app.before_request
    def _require_login():
        path = request.path
        if path in _AUTH_EXEMPT or path.startswith("/static/"):
            return None
        if not session.get("authenticated"):
            if path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect("/login")
        # CSRF check for all mutating requests from authenticated sessions
        if request.method not in _CSRF_EXEMPT_METHODS:
            expected = session.get("csrf_token")
            provided = request.headers.get("X-CSRF-Token")
            if not expected or not secrets.compare_digest(expected, provided or ""):
                if path.startswith("/api/"):
                    return jsonify({"error": "CSRF token invalid"}), 403
                return redirect("/login")
        return None

    # ------------------------------------------------------------------ #
    # Require-admin decorator
    # ------------------------------------------------------------------ #

    def require_admin(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("role") != "admin":
                return jsonify({"error": "Forbidden — admin role required"}), 403
            return f(*args, **kwargs)
        return decorated

    # ------------------------------------------------------------------ #
    # Security response headers
    # ------------------------------------------------------------------ #

    @app.after_request
    def _add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # ------------------------------------------------------------------ #
    # Login / logout
    # ------------------------------------------------------------------ #

    @app.route("/login", methods=["GET"])
    def login_page():
        if session.get("authenticated"):
            return redirect("/")
        return render_template("login.html")

    @app.route("/login", methods=["POST"])
    @_limiter.limit("5 per minute")
    def login_submit():
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        role = db.verify_password(username, password)
        if role is None:
            return jsonify({"error": "Invalid credentials"}), 401
        # Regenerate session to prevent fixation
        session.clear()
        session.permanent = True
        session["authenticated"] = True
        session["username"] = username
        session["role"] = role
        session["csrf_token"] = secrets.token_hex(32)
        return jsonify({"ok": True, "username": username, "role": role})

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    # ------------------------------------------------------------------ #
    # Health endpoint (Docker healthcheck — no auth)
    # ------------------------------------------------------------------ #

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    # ------------------------------------------------------------------ #
    # Dashboard HTML
    # ------------------------------------------------------------------ #

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html")

    # ------------------------------------------------------------------ #
    # API — session info
    # ------------------------------------------------------------------ #

    @app.route("/api/session")
    def api_session():
        return jsonify({
            "authenticated": session.get("authenticated", False),
            "username": session.get("username"),
            "role": session.get("role"),
            "csrf_token": session.get("csrf_token"),
        })

    # ------------------------------------------------------------------ #
    # API — summary cards
    # ------------------------------------------------------------------ #

    @app.route("/api/summary")
    def api_summary():
        try:
            data = db.get_dashboard_summary()
            return jsonify(data)
        except Exception as exc:
            logger.error("api_summary error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — all root domains with subdomain stats
    # ------------------------------------------------------------------ #

    @app.route("/api/domains")
    def api_domains():
        try:
            rows = db.get_all_domains_with_stats()
            return jsonify(rows)
        except Exception as exc:
            logger.error("api_domains error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — all subdomains with latest open-port list
    # ------------------------------------------------------------------ #

    @app.route("/api/subdomains")
    def api_subdomains():
        try:
            from sqlalchemy import select
            from ..database import Subdomain

            with db.get_session() as session_:
                subs = list(session_.scalars(
                    select(Subdomain).order_by(Subdomain.fqdn)
                ).all())

            latest_scans = db.get_all_latest_port_scans()
            host_ports: dict[str, list[dict]] = {}
            for scan in latest_scans:
                host_ports[scan.host] = [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                    }
                    for p in scan.open_ports
                ]

            rows = []
            for s in subs:
                rows.append({
                    "id": s.id,
                    "fqdn": s.fqdn,
                    "status": s.status,
                    "http_status": s.http_status,
                    "ip_addresses": s.ip_addresses or [],
                    "technologies": s.technologies or [],
                    "classification": s.classification,
                    "page_title": s.page_title,
                    "takeover_vulnerable": s.takeover_vulnerable,
                    "first_seen": s.first_seen.isoformat() if s.first_seen else None,
                    "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                    "open_ports": host_ports.get(s.fqdn, []),
                })
            return jsonify(rows)
        except Exception as exc:
            logger.error("api_subdomains error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — latest port scan per host
    # ------------------------------------------------------------------ #

    @app.route("/api/ports")
    def api_ports():
        try:
            scans = db.get_all_latest_port_scans()
            rows = []
            for scan in scans:
                rows.append({
                    "host": scan.host,
                    "status": scan.status,
                    "scanned_at": scan.scanned_at.isoformat() if scan.scanned_at else None,
                    "scan_duration": scan.scan_duration,
                    "error": scan.error,
                    "ports": [
                        {
                            "port": p.port,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                            "extra_info": p.extra_info,
                        }
                        for p in sorted(scan.open_ports, key=lambda x: x.port)
                    ],
                })
            return jsonify(rows)
        except Exception as exc:
            logger.error("api_ports error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — recent change events
    # ------------------------------------------------------------------ #

    @app.route("/api/changes")
    def api_changes():
        try:
            hours = int(request.args.get("hours", 48))
        except (ValueError, TypeError):
            return jsonify({"error": "hours must be a positive integer"}), 400
        try:
            hours = min(max(hours, 1), 8760)
            events = db.get_recent_events(hours=hours)
            return jsonify([_ev_to_dict(e) for e in events])
        except Exception as exc:
            logger.error("api_changes error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — HTTP header snapshots
    # ------------------------------------------------------------------ #

    @app.route("/api/headers")
    def api_headers():
        SECURITY_HEADERS = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "x-xss-protection",
        ]
        INFO_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

        try:
            from sqlalchemy import select, func as sqlfunc
            from ..database import Subdomain, SubdomainScan

            with db.get_session() as session_:
                subq = (
                    select(
                        SubdomainScan.subdomain_id,
                        sqlfunc.max(SubdomainScan.scanned_at).label("max_at"),
                    )
                    .group_by(SubdomainScan.subdomain_id)
                    .subquery()
                )
                pairs = session_.execute(
                    select(Subdomain, SubdomainScan)
                    .join(SubdomainScan, Subdomain.id == SubdomainScan.subdomain_id)
                    .join(
                        subq,
                        (SubdomainScan.subdomain_id == subq.c.subdomain_id)
                        & (SubdomainScan.scanned_at == subq.c.max_at),
                    )
                    .where(SubdomainScan.raw_headers.isnot(None))
                    .order_by(Subdomain.fqdn)
                ).all()

            rows = []
            for sub, scan in pairs:
                raw = scan.raw_headers or {}
                headers = {k.lower(): v for k, v in raw.items()}
                sec_status = {
                    h: ("present" if h in headers else "missing")
                    for h in SECURITY_HEADERS
                }
                info_leaked = {h: headers[h] for h in INFO_HEADERS if h in headers}
                rows.append({
                    "fqdn": sub.fqdn,
                    "status_code": scan.http_status,
                    "scanned_at": scan.scanned_at.isoformat() if scan.scanned_at else None,
                    "security_headers": sec_status,
                    "info_leaked": info_leaked,
                    "all_headers": headers,
                })
            return jsonify(rows)
        except Exception as exc:
            logger.error("api_headers error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — add a new target (domain / subdomain / website)
    # ------------------------------------------------------------------ #

    @app.route("/api/targets", methods=["POST"])
    @require_admin
    def api_add_target():
        data = request.get_json(silent=True) or {}
        target_type = (data.get("type") or "").lower()
        value = (data.get("value") or "").strip()
        scan_now = bool(data.get("scan_now", False))
        techniques = data.get("techniques") or {}

        if not value:
            return jsonify({"error": "value is required"}), 400
        if target_type not in ("domain", "subdomain", "website"):
            return jsonify({"error": "type must be domain, subdomain, or website"}), 400
        if target_type in ("domain", "subdomain"):
            if len(value) > 253 or not _DOMAIN_RE.match(value):
                return jsonify({"error": "Invalid domain name"}), 400

        try:
            if target_type == "domain":
                dom = db.add_domain(value)
                result = {"type": "domain", "id": dom.id, "value": dom.domain}

                if scan_now and sched_manager:
                    _trigger_background_scan(sched_manager, dom.domain, techniques)
                    result["scan_triggered"] = True

            elif target_type == "subdomain":
                parts = value.split(".")
                root = ".".join(parts[-2:]) if len(parts) >= 2 else value
                parent = db.get_domain(root) or db.add_domain(root)
                sub, is_new = db.upsert_subdomain(
                    fqdn=value,
                    domain_id=parent.id,
                    discovery_technique="manual",
                )
                result = {"type": "subdomain", "id": sub.id, "value": sub.fqdn, "is_new": is_new}

                if scan_now and sched_manager:
                    _trigger_background_scan(sched_manager, parent.domain, techniques)
                    result["scan_triggered"] = True

            else:  # website
                from ..monitoring.website_store import add_website
                website_techniques = data.get("website_techniques") or {}
                add_website(value, website_techniques if website_techniques else None)
                result = {"type": "website", "value": value}

                if scan_now and sched_manager:
                    _trigger_background_full_scan(sched_manager)
                    result["scan_triggered"] = True

            return jsonify(result), 201

        except Exception as exc:
            logger.error("api_add_target error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — website list (websites.txt) with live-status enrichment
    # ------------------------------------------------------------------ #

    @app.route("/api/websites")
    def api_websites():
        import urllib.parse
        try:
            from ..monitoring.website_store import read_websites
            entries = read_websites()

            rows = []
            for entry in entries:
                url = entry.get("url", "")
                techniques = entry.get("techniques", {})
                norm = url if url.startswith(("http://", "https://")) else "https://" + url
                hostname = urllib.parse.urlparse(norm).hostname or ""
                status = "unknown"
                http_status = None
                page_title = ""
                last_seen = None
                technologies_list: list = []
                if hostname:
                    sub = db.get_subdomain(hostname)
                    if sub:
                        status = sub.status
                        http_status = sub.http_status
                        page_title = sub.page_title or ""
                        last_seen = sub.last_seen.isoformat() if sub.last_seen else None
                        technologies_list = sub.technologies or []
                rows.append({
                    "url": url,
                    "hostname": hostname,
                    "status": status,
                    "http_status": http_status,
                    "page_title": page_title,
                    "last_seen": last_seen,
                    "technologies": technologies_list,
                    "techniques": techniques,
                })
            return jsonify(rows)
        except Exception as exc:
            logger.error("api_websites error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/websites", methods=["DELETE"])
    @require_admin
    def api_delete_website():
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url is required"}), 400
        try:
            from ..monitoring.website_store import remove_website
            removed = remove_website(url)
            if not removed:
                return jsonify({"error": "URL not found"}), 404
            return jsonify({"deleted": url})
        except Exception as exc:
            logger.error("api_delete_website error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/websites", methods=["PATCH"])
    @require_admin
    def api_update_website_techniques():
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        techniques = data.get("techniques") or {}
        if not url:
            return jsonify({"error": "url is required"}), 400
        try:
            from ..monitoring.website_store import update_techniques
            updated = update_techniques(url, techniques)
            if not updated:
                return jsonify({"error": "URL not found"}), 404
            return jsonify({"updated": True, "url": url, "techniques": techniques})
        except Exception as exc:
            logger.error("api_update_website_techniques error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — assign a profile to a domain
    # ------------------------------------------------------------------ #

    @app.route("/api/targets/domain/<int:domain_id>", methods=["PATCH"])
    @require_admin
    def api_patch_domain(domain_id: int):
        data = request.get_json(silent=True) or {}
        if "profile_id" not in data:
            return jsonify({"error": "profile_id is required"}), 400
        profile_id = data["profile_id"]
        ok = db.set_domain_profile(domain_id, profile_id)
        if not ok:
            return jsonify({"error": "Domain not found"}), 404
        return jsonify({"updated": True, "domain_id": domain_id, "profile_id": profile_id})

    # ------------------------------------------------------------------ #
    # API — per-domain detail page data
    # ------------------------------------------------------------------ #

    @app.route("/api/domains/<int:domain_id>/details")
    def api_domain_details(domain_id: int):
        try:
            details = db.get_domain_details(domain_id)
            if details is None:
                return jsonify({"error": "Domain not found"}), 404
            return jsonify(details)
        except Exception as exc:
            logger.error("api_domain_details error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — scan profiles
    # ------------------------------------------------------------------ #

    @app.route("/api/profiles")
    def api_profiles():
        try:
            profiles = db.get_all_profiles()
            return jsonify([
                {
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "is_builtin": p.is_builtin,
                    "settings": p.settings,
                    "created_at": p.created_at.isoformat() if p.created_at else None,
                }
                for p in profiles
            ])
        except Exception as exc:
            logger.error("api_profiles error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/profiles", methods=["POST"])
    @require_admin
    def api_create_profile():
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        description = (data.get("description") or "").strip()
        settings = data.get("settings") or {}
        if not name:
            return jsonify({"error": "name is required"}), 400
        try:
            p = db.create_profile(name, description, settings)
            return jsonify({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "is_builtin": p.is_builtin,
                "settings": p.settings,
            }), 201
        except Exception as exc:
            logger.error("api_create_profile error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/profiles/<int:profile_id>", methods=["PUT"])
    @require_admin
    def api_update_profile(profile_id: int):
        data = request.get_json(silent=True) or {}
        try:
            p = db.update_profile(
                profile_id,
                name=data.get("name"),
                description=data.get("description"),
                settings=data.get("settings"),
            )
            if p is None:
                return jsonify({"error": "Profile not found or is built-in"}), 404
            return jsonify({"id": p.id, "name": p.name, "description": p.description, "settings": p.settings})
        except Exception as exc:
            logger.error("api_update_profile error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/profiles/<int:profile_id>", methods=["DELETE"])
    @require_admin
    def api_delete_profile(profile_id: int):
        try:
            deleted = db.delete_profile(profile_id)
            if not deleted:
                return jsonify({"error": "Profile not found or is built-in"}), 404
            return jsonify({"deleted": True, "id": profile_id})
        except Exception as exc:
            logger.error("api_delete_profile error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — delete a root domain
    # ------------------------------------------------------------------ #

    @app.route("/api/targets/domain/<int:domain_id>", methods=["DELETE"])
    @require_admin
    def api_delete_domain(domain_id: int):
        try:
            deleted = db.delete_domain(domain_id)
            if not deleted:
                return jsonify({"error": "Domain not found"}), 404
            return jsonify({"deleted": True, "id": domain_id})
        except Exception as exc:
            logger.error("api_delete_domain error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — trigger an on-demand scan
    # ------------------------------------------------------------------ #

    @app.route("/api/scan/trigger", methods=["POST"])
    @require_admin
    def api_scan_trigger():
        if not sched_manager:
            return jsonify({"error": "Scheduler not available in this mode"}), 503

        with _scan_lock:
            if _scan_state["running"]:
                return jsonify({"error": "A scan is already in progress"}), 409

        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip() or None
        techniques = data.get("techniques") or {}

        if domain:
            _trigger_background_scan(sched_manager, domain, techniques)
        else:
            _trigger_background_full_scan(sched_manager)

        return jsonify({"started": True, "domain": domain})

    # ------------------------------------------------------------------ #
    # API — scan status
    # ------------------------------------------------------------------ #

    @app.route("/api/scan/status")
    def api_scan_status():
        with _scan_lock:
            return jsonify(dict(_scan_state))

    # ------------------------------------------------------------------ #
    # API — settings (config overrides stored in DB)
    # ------------------------------------------------------------------ #

    @app.route("/api/settings", methods=["GET"])
    def api_get_settings():
        try:
            overrides = db.get_config_overrides()
            return jsonify(overrides)
        except Exception as exc:
            logger.error("api_get_settings error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/settings", methods=["POST"])
    @require_admin
    def api_post_settings():
        data = request.get_json(silent=True) or {}
        try:
            db.set_config_overrides(data)
            db.apply_settings_to_config(config)
            # Reschedule if interval changed
            new_interval = (data.get("scan") or {}).get("interval_minutes")
            if new_interval and sched_manager:
                try:
                    sched_manager.reschedule(int(new_interval))
                except Exception as exc:
                    logger.warning("reschedule failed: %s", exc)
            return jsonify({"saved": True})
        except Exception as exc:
            logger.error("api_post_settings error: %s", exc)
            return jsonify({"error": str(exc)}), 500

    # ------------------------------------------------------------------ #
    # API — user management
    # ------------------------------------------------------------------ #

    @app.route("/api/users", methods=["GET"])
    def api_list_users():
        try:
            return jsonify(db.list_users())
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/users", methods=["POST"])
    @require_admin
    def api_create_user():
        import bcrypt as _bcrypt
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = (data.get("role") or "viewer").strip()
        if not username or not password:
            return jsonify({"error": "username and password required"}), 400
        if role not in ("admin", "viewer"):
            return jsonify({"error": "role must be admin or viewer"}), 400
        try:
            password_hash = "bcrypt:" + _bcrypt.hashpw(
                password.encode(), _bcrypt.gensalt()
            ).decode()
            db.set_user(username, password_hash, role)
            return jsonify({"created": True, "username": username, "role": role}), 201
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/users/<username>", methods=["DELETE"])
    @require_admin
    def api_delete_user(username: str):
        if username == session.get("username"):
            return jsonify({"error": "Cannot delete currently logged-in user"}), 400
        try:
            ok = db.delete_user(username)
            if not ok:
                return jsonify({"error": "User not found"}), 404
            return jsonify({"deleted": True, "username": username})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/users/<username>/password", methods=["POST"])
    def api_change_password(username: str):
        import bcrypt as _bcrypt
        if session.get("role") != "admin" and username != session.get("username"):
            return jsonify({"error": "Forbidden"}), 403
        data = request.get_json(silent=True) or {}
        new_password = data.get("password") or ""
        if not new_password:
            return jsonify({"error": "password required"}), 400
        try:
            user = db.get_user(username)
            if user is None:
                return jsonify({"error": "User not found"}), 404
            password_hash = "bcrypt:" + _bcrypt.hashpw(
                new_password.encode(), _bcrypt.gensalt()
            ).decode()
            db.set_user(username, password_hash, user.get("role", "viewer"))
            return jsonify({"updated": True})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    return app


# ---------------------------------------------------------------------------
# Background scan helpers
# ---------------------------------------------------------------------------

def _trigger_background_scan(
    sched_manager: "SchedManager",
    domain: Optional[str],
    techniques: dict,
) -> None:
    """Kick off a single-domain async scan in a background thread."""
    import asyncio

    def _run() -> None:
        with _scan_lock:
            if _scan_state["running"]:
                return
            _scan_state.update({"running": True, "started_at": datetime.now(timezone.utc).isoformat(), "domain": domain, "error": None})
        try:
            sub_count, event_count = asyncio.run(
                sched_manager.run_domain_scan(domain, technique_overrides=techniques or None)
            )
            with _scan_lock:
                _scan_state.update({
                    "running": False,
                    "last_completed": datetime.now(timezone.utc).isoformat(),
                    "last_subs_found": sub_count,
                    "last_events": event_count,
                })
        except Exception as exc:
            logger.error("Background domain scan failed: %s", exc, exc_info=True)
            with _scan_lock:
                _scan_state.update({"running": False, "error": str(exc)})

    threading.Thread(target=_run, daemon=True, name=f"scan-{domain or 'all'}").start()


def _trigger_background_full_scan(sched_manager: "SchedManager") -> None:
    """Kick off a full scan (all domains) in a background thread."""
    import asyncio

    def _run() -> None:
        with _scan_lock:
            if _scan_state["running"]:
                return
            _scan_state.update({"running": True, "started_at": datetime.now(timezone.utc).isoformat(), "domain": None, "error": None})
        try:
            asyncio.run(sched_manager.run_full_scan())
            with _scan_lock:
                _scan_state.update({
                    "running": False,
                    "last_completed": datetime.now(timezone.utc).isoformat(),
                })
        except Exception as exc:
            logger.error("Background full scan failed: %s", exc, exc_info=True)
            with _scan_lock:
                _scan_state.update({"running": False, "error": str(exc)})

    threading.Thread(target=_run, daemon=True, name="scan-full").start()


def _append_to_file(path: str, value: str) -> None:
    """Append a value to a text file if not already present."""
    import os as _os
    _os.makedirs(_os.path.dirname(path) or ".", exist_ok=True)
    existing: list[str] = []
    if _os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            existing = [line.strip() for line in fh if not line.strip().startswith("#")]
    if value not in existing:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{value}\n")


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------

def start_web_server(
    db: "DatabaseManager",
    config: "AppConfig",
    host: str = "0.0.0.0",
    port: int = 5000,
    sched_manager: Optional["SchedManager"] = None,
) -> threading.Thread:
    """Start the Flask dashboard in a daemon thread."""
    app = create_app(db, config, sched_manager)

    thread = threading.Thread(
        target=lambda: app.run(
            host=host,
            port=port,
            debug=False,
            use_reloader=False,
            threaded=True,
        ),
        daemon=True,
        name="web-dashboard",
    )
    thread.start()
    logger.info("Web dashboard started on http://%s:%d", host, port)
    return thread
