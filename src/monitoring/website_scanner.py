"""
Comprehensive website scanner.

Runs a multi-technique scan against a single website URL:
  1. HTTP probe + technology fingerprinting (via VerificationManager)
  2. BFS crawl  — pages, endpoints, forms, external links
  3. JS analysis — API endpoints, routes, env vars extracted from JS files
  4. Security files — robots.txt, .git, .env, swagger, etc.
  5. Screenshot (optional, requires playwright)

Returns a rich result dict that the scheduler persists to the database
and uses to emit typed ChangeEvents.
"""

from __future__ import annotations

import logging
import os
import urllib.parse
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ..config import AppConfig
    from ..database import DatabaseManager

logger = logging.getLogger(__name__)


async def scan_website(
    url: str,
    techniques: dict,
    config: "AppConfig",
    db: "DatabaseManager",
) -> dict:
    """
    Run all enabled techniques against *url*.

    Parameters
    ----------
    url:
        Full URL to scan (e.g. ``https://example.com``).
    techniques:
        Dict of boolean flags: ``crawl``, ``js_analysis``,
        ``security_files``, ``screenshot``.
    config:
        Application configuration.
    db:
        DatabaseManager for persistence helpers.

    Returns
    -------
    dict with keys:
        - ``url``              (str)
        - ``hostname``         (str)
        - ``domain_id``        (int | None)
        - ``live``             (bool)
        - ``status``           (str)   — "alive" / "dead" / "unknown"
        - ``http_status``      (int)
        - ``page_title``       (str)
        - ``technologies``     (list[dict])
        - ``pages``            (list[dict])
        - ``endpoints``        (list[str])   — unique paths from crawl
        - ``api_endpoints``    (list[str])   — paths extracted from JS
        - ``js_routes``        (list[str])   — front-end route definitions
        - ``security_files``   (list[dict])  — accessible sensitive paths
        - ``disallow_paths``   (list[str])   — robots.txt Disallow entries
        - ``screenshot_path``  (str | None)
        - ``error``            (str | None)
    """
    result: dict = {
        "url": url,
        "hostname": "",
        "domain_id": None,
        "live": False,
        "status": "unknown",
        "http_status": 0,
        "page_title": "",
        "technologies": [],
        "pages": [],
        "endpoints": [],
        "api_endpoints": [],
        "js_routes": [],
        "security_files": [],
        "disallow_paths": [],
        "screenshot_path": None,
        "error": None,
    }

    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result["url"] = url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    if not hostname:
        result["error"] = f"Cannot parse hostname from URL: {url}"
        return result
    result["hostname"] = hostname

    # Find or create a parent domain record
    parts = hostname.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    domain = db.get_domain(root) or db.add_domain(root)
    result["domain_id"] = domain.id

    cfg_scan = config.scan
    timeout = cfg_scan.request_timeout_seconds
    verify_ssl = cfg_scan.verify_ssl

    # ------------------------------------------------------------------
    # Step 1 — HTTP probe + fingerprint via VerificationManager
    # (persists to DB and handles status / tech detection)
    # ------------------------------------------------------------------
    try:
        from ..verification.manager import VerificationManager
        vm = VerificationManager(config, db)
        probe = await vm.verify_subdomain(hostname, domain.id, "website")
        result["live"] = probe.get("live", False)
        result["http_status"] = probe.get("status_code", 0)
        result["page_title"] = probe.get("page_title", "")
        result["technologies"] = probe.get("technologies", [])
        if result["live"]:
            result["status"] = "alive"
        elif probe.get("dns_resolved"):
            result["status"] = "dead"
        else:
            result["status"] = "unknown"
    except Exception as exc:
        logger.warning("Probe failed for %s: %s", url, exc)
        result["error"] = str(exc)
        return result

    if not result["live"]:
        return result

    # Use the canonical URL returned by the prober (follows redirects)
    base_url = url

    # ------------------------------------------------------------------
    # Step 2 — BFS crawl
    # ------------------------------------------------------------------
    if techniques.get("crawl", True):
        try:
            from .crawler import BFSCrawler
            crawler = BFSCrawler(
                base_url=base_url,
                max_depth=cfg_scan.max_crawl_depth,
                max_pages=cfg_scan.max_pages_per_domain,
                timeout=timeout,
                verify_ssl=verify_ssl,
                user_agent=cfg_scan.user_agent,
            )
            crawl_data = await crawler.crawl()
            result["pages"] = crawl_data.get("pages", [])
            result["endpoints"] = crawl_data.get("endpoints", [])

            # Persist endpoints to DB
            sub = db.get_subdomain(hostname)
            if sub:
                for path in result["endpoints"]:
                    try:
                        db.upsert_endpoint(sub.id, path, "GET")
                    except Exception:
                        pass

            # Extract JS file URLs for the next step
            js_urls: list[str] = []
            for asset in crawl_data.get("assets", []):
                if asset.get("asset_type") == "js":
                    js_urls.append(asset["url"])

        except Exception as exc:
            logger.warning("Crawl failed for %s: %s", url, exc)
            js_urls = []
    else:
        js_urls = []

    # ------------------------------------------------------------------
    # Step 3 — JS analysis
    # ------------------------------------------------------------------
    if techniques.get("js_analysis", True) and js_urls:
        try:
            from .js_analyzer import analyze_js_file
            all_api_endpoints: set[str] = set()
            all_routes: set[str] = set()

            for js_url in js_urls[:20]:  # cap at 20 files to avoid runaway
                try:
                    js_result = await analyze_js_file(
                        url=js_url,
                        domain=root,
                        timeout=timeout,
                        verify_ssl=verify_ssl,
                    )
                    all_api_endpoints.update(js_result.get("endpoints", []))
                    all_routes.update(js_result.get("routes", []))
                except Exception as js_exc:
                    logger.debug("JS analysis failed for %s: %s", js_url, js_exc)

            result["api_endpoints"] = sorted(all_api_endpoints)
            result["js_routes"] = sorted(all_routes)

            # Persist JS-discovered endpoints to DB
            sub = db.get_subdomain(hostname)
            if sub:
                for path in result["api_endpoints"]:
                    try:
                        db.upsert_endpoint(sub.id, path, "GET")
                    except Exception:
                        pass

        except Exception as exc:
            logger.warning("JS analysis step failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Step 4 — Security files
    # ------------------------------------------------------------------
    if techniques.get("security_files", True):
        try:
            from .security_files import check_security_files
            sec_result = await check_security_files(
                base_url=base_url,
                timeout=timeout,
                verify_ssl=verify_ssl,
            )
            result["security_files"] = sec_result.get("found", [])
            result["disallow_paths"] = sec_result.get("disallow_paths", [])
        except Exception as exc:
            logger.warning("Security files check failed for %s: %s", url, exc)

    # ------------------------------------------------------------------
    # Step 5 — Screenshot (optional, requires playwright)
    # ------------------------------------------------------------------
    if techniques.get("screenshot", False):
        result["screenshot_path"] = await _take_screenshot(url, timeout)

    return result


async def _take_screenshot(url: str, timeout: int = 15) -> Optional[str]:
    """Take a headless browser screenshot. Returns path or None on failure."""
    try:
        from playwright.async_api import async_playwright  # type: ignore[import]
    except ImportError:
        logger.debug("playwright not installed — screenshot skipped")
        return None

    import hashlib

    screenshot_dir = "data/screenshots"
    os.makedirs(screenshot_dir, exist_ok=True)
    filename = hashlib.sha256(url.encode()).hexdigest()[:16] + ".png"
    path = os.path.join(screenshot_dir, filename)

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            page = await browser.new_page(viewport={"width": 1280, "height": 800})
            await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
            await page.screenshot(path=path, full_page=False)
            await browser.close()
        logger.info("Screenshot saved: %s", path)
        return path
    except Exception as exc:
        logger.warning("Screenshot failed for %s: %s", url, exc)
        return None
