"""
Detection manager.

Orchestrates all change-detection techniques for a single page or subdomain
scan.  Retrieves the previous scan state from the database, runs each enabled
detector, collates the change events, and returns them ready for insertion.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..config import AppConfig
from ..database import DatabaseManager
from .asset_tracker import diff_assets
from .content_hash import compute_stable_hash, detect_changes
from .dom_diff import diff_dom, extract_dom_structure
from .endpoint_delta import diff_endpoints
from .size_anomaly import compute_anomaly
from .tech_stack import diff_headers, diff_technologies

logger = logging.getLogger(__name__)


class DetectionManager:
    """
    High-level coordinator for change detection.

    Parameters
    ----------
    config:
        Application configuration.
    db:
        Initialised database manager.
    """

    def __init__(self, config: AppConfig, db: DatabaseManager) -> None:
        self._config = config
        self._db = db
        self._det_cfg = config.monitoring.change_detection

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze_page(
        self,
        url: str,
        subdomain_id: int,
        current_crawl_data: dict,
    ) -> list[dict]:
        """
        Run all enabled detection techniques for a single crawled page.

        The method loads the most recent previous scan record for *subdomain_id*
        from the database to use as the baseline.

        Parameters
        ----------
        url:
            The URL of the page that was crawled.
        subdomain_id:
            Primary key of the subdomain in the database.
        current_crawl_data:
            The dict produced by :class:`~monitoring.crawler.BFSCrawler` for
            this page.  Expected keys: ``body_hash``, ``response_size``,
            ``headers``, ``scripts``, ``forms``, ``links``, and optionally
            ``html`` (raw HTML body).

        Returns
        -------
        List of change-event dicts ready for
        :meth:`~database.DatabaseManager.add_change_event`.
        """
        events: list[dict] = []

        # Load previous scan records from DB
        # DatabaseManager exposes add_scan_record but not a bulk getter;
        # we try the optional helper and fall back gracefully.
        previous_scans: list = []
        if hasattr(self._db, "get_scan_records_for_subdomain"):
            previous_scans = self._db.get_scan_records_for_subdomain(subdomain_id) or []

        previous_scan = previous_scans[-1] if previous_scans else None

        old_headers: dict = {}
        old_endpoints: list[str] = []
        old_assets: list[dict] = []
        old_response_sizes: list[int] = []
        old_html: str = ""

        if previous_scan is not None:
            old_headers = getattr(previous_scan, "raw_headers", None) or {}
            old_endpoints = getattr(previous_scan, "endpoints", None) or []
            old_assets = getattr(previous_scan, "assets", None) or []
            old_html = getattr(previous_scan, "html", "") or ""
            old_response_sizes = [
                getattr(s, "response_size", 0) or 0
                for s in previous_scans
                if getattr(s, "response_size", None) is not None
            ]

        current_html: str = current_crawl_data.get("html", "")
        current_headers: dict = current_crawl_data.get("headers", {})
        current_size: int = current_crawl_data.get("response_size", 0) or 0
        current_endpoints: list[str] = current_crawl_data.get("endpoints", []) or []
        current_assets: list[dict] = current_crawl_data.get("assets", []) or []

        # ------------------------------------------------------------------
        # 1. Content hash comparison
        # ------------------------------------------------------------------
        if self._det_cfg.content_hash and current_html and old_html:
            try:
                old_hashes = compute_stable_hash(old_html)
                new_hashes = compute_stable_hash(current_html)
                hash_changes = detect_changes(old_hashes, new_hashes)
                for desc in hash_changes:
                    events.append(self._make_event(
                        event_type="CONTENT_CHANGE",
                        severity="LOW",
                        target=url,
                        description=desc,
                        diff_data={"old": old_hashes, "new": new_hashes},
                    ))
            except Exception as exc:
                logger.warning("Content hash analysis failed for %s: %s", url, exc)

        # ------------------------------------------------------------------
        # 2. DOM structural diff
        # ------------------------------------------------------------------
        if self._det_cfg.dom_structural_diff and current_html and old_html:
            try:
                old_dom = extract_dom_structure(old_html)
                new_dom = extract_dom_structure(current_html)
                dom_changes = diff_dom(old_dom, new_dom)
                for change in dom_changes:
                    events.append(self._make_event(
                        event_type="DOM_CHANGE",
                        severity=change["severity"],
                        target=url,
                        description=(
                            f"{change['change_type']} {change['element_type']}: "
                            f"{change['value']}"
                        ),
                        diff_data=change,
                    ))
            except Exception as exc:
                logger.warning("DOM diff failed for %s: %s", url, exc)

        # ------------------------------------------------------------------
        # 3. Endpoint inventory diff
        # ------------------------------------------------------------------
        if self._det_cfg.endpoint_inventory and (old_endpoints or current_endpoints):
            try:
                ep_delta = diff_endpoints(old_endpoints, current_endpoints)
                for added in ep_delta.get("added", []):
                    severity = _sensitivity_to_severity(added.get("sensitivity", "LOW"))
                    events.append(self._make_event(
                        event_type="ENDPOINT_NEW",
                        severity=severity,
                        target=url,
                        description=f"New endpoint discovered: {added['path']}",
                        diff_data=added,
                    ))
                for removed_path in ep_delta.get("removed", []):
                    events.append(self._make_event(
                        event_type="ENDPOINT_REMOVED",
                        severity="INFO",
                        target=url,
                        description=f"Endpoint no longer present: {removed_path}",
                        diff_data={"path": removed_path},
                    ))
            except Exception as exc:
                logger.warning("Endpoint delta failed for %s: %s", url, exc)

        # ------------------------------------------------------------------
        # 4. Asset tracking
        # ------------------------------------------------------------------
        if self._det_cfg.asset_tracking and (old_assets or current_assets):
            try:
                asset_diff = diff_assets(old_assets, current_assets)
                for new_asset in asset_diff.get("new_assets", []):
                    events.append(self._make_event(
                        event_type="ASSET_NEW",
                        severity=new_asset["severity"],
                        target=url,
                        description=(
                            f"New asset: {new_asset['url']} "
                            f"({new_asset.get('asset_type', 'unknown')})"
                        ),
                        diff_data=new_asset,
                    ))
                for changed_asset in asset_diff.get("changed_assets", []):
                    events.append(self._make_event(
                        event_type="ASSET_CHANGED",
                        severity=changed_asset["severity"],
                        target=url,
                        description=f"Asset content changed: {changed_asset['url']}",
                        diff_data=changed_asset,
                    ))
                for removed_asset in asset_diff.get("removed_assets", []):
                    events.append(self._make_event(
                        event_type="ASSET_REMOVED",
                        severity="INFO",
                        target=url,
                        description=f"Asset removed: {removed_asset['url']}",
                        diff_data=removed_asset,
                    ))
            except Exception as exc:
                logger.warning("Asset tracking failed for %s: %s", url, exc)

        # ------------------------------------------------------------------
        # 5. Response size anomaly
        # ------------------------------------------------------------------
        if self._det_cfg.response_size_anomaly and old_response_sizes:
            try:
                anomaly = compute_anomaly(current_size, old_response_sizes)
                if anomaly:
                    events.append(self._make_event(
                        event_type="SIZE_ANOMALY",
                        severity="MEDIUM",
                        target=url,
                        description=anomaly.get(
                            "description",
                            f"Response size anomaly on {url}: {current_size} bytes "
                            f"(mean={anomaly.get('mean', '?')}, "
                            f"deviation={anomaly.get('deviation_factor', '?')}σ)",
                        ),
                        diff_data=anomaly,
                    ))
            except Exception as exc:
                logger.warning("Size anomaly detection failed for %s: %s", url, exc)

        return events

    async def analyze_subdomain(
        self,
        fqdn: str,
        subdomain_id: int,
        new_data: dict,
        old_data: dict,
    ) -> list[dict]:
        """
        Detect subdomain-level changes between two verification snapshots.

        Monitors: liveness status, HTTP status code, technology stack,
        security headers, and TLS certificate fingerprint.

        Parameters
        ----------
        fqdn:
            The fully-qualified domain name.
        subdomain_id:
            Primary key in the database (reserved for future lookups).
        new_data:
            Current verification result dict.
        old_data:
            Previous verification result dict (empty dict for new subdomains).

        Returns
        -------
        List of change-event dicts.
        """
        events: list[dict] = []

        if not old_data:
            return events

        # ------------------------------------------------------------------
        # Liveness / HTTP status
        # ------------------------------------------------------------------
        old_live = old_data.get("live", False)
        new_live = new_data.get("live", False)
        old_status = old_data.get("status_code", 0) or 0
        new_status = new_data.get("status_code", 0) or 0

        if not old_live and new_live:
            events.append(self._make_event(
                "SUBDOMAIN_CAME_ALIVE",
                "MEDIUM",
                fqdn,
                f"{fqdn} is now live (HTTP {new_status})",
            ))
        elif old_live and not new_live:
            events.append(self._make_event(
                "SUBDOMAIN_WENT_DEAD",
                "LOW",
                fqdn,
                f"{fqdn} is no longer responding",
            ))
        elif old_status and new_status and old_status != new_status:
            events.append(self._make_event(
                "STATUS_CHANGE",
                "LOW",
                fqdn,
                f"HTTP status changed {old_status} → {new_status} on {fqdn}",
                {"old": old_status, "new": new_status},
            ))

        # ------------------------------------------------------------------
        # Technology stack
        # ------------------------------------------------------------------
        if self._det_cfg.technology_stack:
            try:
                tech_diff = diff_technologies(
                    old_data.get("technologies") or [],
                    new_data.get("technologies") or [],
                )
                if tech_diff["added"]:
                    added_labels = [
                        f"{t['name']} {t['version']}".strip()
                        for t in tech_diff["added"]
                    ]
                    events.append(self._make_event(
                        "TECH_ADDED",
                        "MEDIUM",
                        fqdn,
                        f"New technologies detected on {fqdn}: {', '.join(added_labels)}",
                        tech_diff,
                    ))
                if tech_diff["removed"]:
                    removed_labels = [
                        f"{t['name']} {t['version']}".strip()
                        for t in tech_diff["removed"]
                    ]
                    events.append(self._make_event(
                        "TECH_REMOVED",
                        "INFO",
                        fqdn,
                        f"Technologies removed from {fqdn}: {', '.join(removed_labels)}",
                        tech_diff,
                    ))
                for vc in tech_diff.get("version_changed", []):
                    events.append(self._make_event(
                        "TECH_VERSION_CHANGED",
                        "LOW",
                        fqdn,
                        f"{vc['name']} version changed on {fqdn}: "
                        f"{vc['old_version']} → {vc['new_version']}",
                        vc,
                    ))
            except Exception as exc:
                logger.warning("Technology diff failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Security headers
        # ------------------------------------------------------------------
        if self._det_cfg.technology_stack:
            try:
                header_diff = diff_headers(
                    old_data.get("response_headers") or {},
                    new_data.get("response_headers") or {},
                )
                if header_diff["removed"]:
                    events.append(self._make_event(
                        "SECURITY_HEADER_REMOVED",
                        "MEDIUM",
                        fqdn,
                        f"Security headers removed from {fqdn}: "
                        f"{list(header_diff['removed'].keys())}",
                        header_diff,
                    ))
                if header_diff["added"]:
                    events.append(self._make_event(
                        "SECURITY_HEADER_ADDED",
                        "INFO",
                        fqdn,
                        f"Security headers added to {fqdn}: "
                        f"{list(header_diff['added'].keys())}",
                        header_diff,
                    ))
                if header_diff["changed"]:
                    events.append(self._make_event(
                        "SECURITY_HEADER_CHANGED",
                        "LOW",
                        fqdn,
                        f"Security header values changed on {fqdn}: "
                        f"{list(header_diff['changed'].keys())}",
                        header_diff,
                    ))
            except Exception as exc:
                logger.warning("Header diff failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # TLS certificate fingerprint
        # ------------------------------------------------------------------
        old_cert = old_data.get("cert_fingerprint")
        new_cert = new_data.get("cert_fingerprint")
        if old_cert and new_cert and old_cert != new_cert:
            events.append(self._make_event(
                "CERT_CHANGE",
                "MEDIUM",
                fqdn,
                f"TLS certificate changed on {fqdn}",
                {"old_fingerprint": old_cert, "new_fingerprint": new_cert},
            ))

        return events

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_event(
        event_type: str,
        severity: str,
        target: str,
        description: str,
        diff_data: Optional[dict] = None,
    ) -> dict:
        """Build a change-event dict compatible with DatabaseManager.add_change_event."""
        return {
            "event_type": event_type,
            "severity": severity,
            "target": target,
            "description": description,
            "diff_data": diff_data,
        }


def _sensitivity_to_severity(sensitivity: str) -> str:
    """Map endpoint sensitivity label to a change-event severity level."""
    mapping = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return mapping.get(sensitivity.upper(), "LOW")
