"""
Verification manager.

Orchestrates the full verification pipeline for each discovered subdomain:
DNS resolution → HTTP probing → technology fingerprinting → takeover check →
classification, then persists the result to the database.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from ..config import AppConfig
from ..database import DatabaseManager
from .classifier import classify_subdomain
from .dns_resolver import resolve_subdomain
from .fingerprinter import fingerprint, get_cert_fingerprint, get_favicon_hash
from .http_prober import probe_subdomain
from .takeover import check_takeover

logger = logging.getLogger(__name__)

# Default concurrency cap for batch verification
_DEFAULT_SEMAPHORE = 20


class VerificationManager:
    """
    High-level coordinator for subdomain verification.

    Parameters
    ----------
    config:
        Application configuration object.
    db:
        Initialised :class:`~database.DatabaseManager` instance.
    """

    def __init__(self, config: AppConfig, db: DatabaseManager) -> None:
        self._config = config
        self._db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def verify_subdomain(
        self,
        fqdn: str,
        domain_id: int,
        discovery_technique: str,
    ) -> dict:
        """
        Run the full verification pipeline for a single subdomain.

        Steps
        -----
        1. DNS resolution (A / AAAA / CNAME)
        2. HTTP / HTTPS probing across configured ports
        3. Technology fingerprinting (headers + body)
        4. Favicon hash & TLS certificate fingerprint
        5. Subdomain takeover check
        6. Functional classification
        7. Upsert result into the database

        Parameters
        ----------
        fqdn:
            Fully-qualified domain name to verify.
        domain_id:
            Primary key of the parent domain in the database.
        discovery_technique:
            Short string describing how this subdomain was found
            (e.g. ``"ct_logs"``, ``"dns_bruteforce"``).

        Returns
        -------
        Complete verification result dict containing all collected fields.
        """
        logger.info("Verifying %s", fqdn)

        cfg_verification = self._config.verification
        cfg_scan = self._config.scan
        resolvers = self._config.enumeration.dns_resolvers

        result: dict = {
            "fqdn": fqdn,
            "domain_id": domain_id,
            "discovery_technique": discovery_technique,
            # DNS
            "a_records": [],
            "aaaa_records": [],
            "cname": None,
            "is_internal": False,
            "dns_resolved": False,
            # HTTP
            "live": False,
            "url": "",
            "status_code": 0,
            "response_size": 0,
            "page_title": "",
            "response_headers": {},
            "redirect_chain": [],
            "port": 0,
            "scheme": "",
            # Fingerprinting
            "technologies": [],
            "favicon_hash": None,
            "cert_fingerprint": None,
            # Takeover
            "takeover": None,
            # Classification
            "classification": "DEFAULT",
        }

        # ------------------------------------------------------------------
        # Step 1 – DNS resolution
        # ------------------------------------------------------------------
        try:
            dns_result = await resolve_subdomain(
                fqdn,
                resolvers=resolvers,
                timeout=cfg_scan.request_timeout_seconds,
            )
            result.update({
                "a_records": dns_result["a_records"],
                "aaaa_records": dns_result["aaaa_records"],
                "cname": dns_result["cname"],
                "is_internal": dns_result["is_internal"],
                "dns_resolved": dns_result["resolved"],
            })
        except Exception as exc:
            logger.warning("DNS resolution failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 2 – HTTP probing
        # ------------------------------------------------------------------
        http_result: dict = {}
        try:
            http_result = await probe_subdomain(
                fqdn,
                ports=cfg_verification.ports,
                timeout=cfg_scan.request_timeout_seconds,
            )
            result.update({
                "live": http_result.get("live", False),
                "url": http_result.get("url", ""),
                "status_code": http_result.get("status_code", 0),
                "response_size": http_result.get("response_size", 0),
                "page_title": http_result.get("page_title", ""),
                "response_headers": http_result.get("response_headers", {}),
                "redirect_chain": http_result.get("redirect_chain", []),
                "port": http_result.get("port", 0),
                "scheme": http_result.get("scheme", ""),
            })
        except Exception as exc:
            logger.warning("HTTP probing failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 3 – Technology fingerprinting (only if live)
        # ------------------------------------------------------------------
        body_text: str = http_result.get("body", "")
        if cfg_verification.technology_detection and result["live"]:
            try:
                techs = await fingerprint(
                    url=result["url"],
                    headers=result["response_headers"],
                    body=body_text,
                )
                result["technologies"] = techs
            except Exception as exc:
                logger.warning("Fingerprinting failed for %s: %s", fqdn, exc)

            # Favicon hash
            base_url = f"{result['scheme']}://{fqdn}:{result['port']}" if result["scheme"] else ""
            if base_url:
                try:
                    result["favicon_hash"] = await get_favicon_hash(
                        base_url,
                        timeout=cfg_scan.request_timeout_seconds,
                    )
                except Exception as exc:
                    logger.debug("Favicon hash failed for %s: %s", fqdn, exc)

            # TLS certificate fingerprint
            if result["scheme"] == "https":
                try:
                    result["cert_fingerprint"] = await get_cert_fingerprint(
                        fqdn,
                        port=result["port"],
                        timeout=cfg_scan.request_timeout_seconds,
                    )
                except Exception as exc:
                    logger.debug("Cert fingerprint failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 4 – Takeover check
        # ------------------------------------------------------------------
        if cfg_verification.takeover_check:
            try:
                takeover = await check_takeover(
                    fqdn=fqdn,
                    cname=result["cname"],
                    http_result=http_result,
                )
                result["takeover"] = takeover
            except Exception as exc:
                logger.warning("Takeover check failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 5 – Classification
        # ------------------------------------------------------------------
        try:
            result["classification"] = classify_subdomain(
                fqdn=fqdn,
                page_title=result["page_title"],
                technologies=result["technologies"],
            )
        except Exception as exc:
            logger.warning("Classification failed for %s: %s", fqdn, exc)

        # ------------------------------------------------------------------
        # Step 6 – Upsert into database
        # ------------------------------------------------------------------
        await self._persist(result)

        return result

    async def verify_batch(
        self,
        fqdns: set[str],
        domain_id: int,
        technique: str,
    ) -> list[dict]:
        """
        Verify a batch of subdomains concurrently.

        A semaphore caps the maximum number of in-flight verifications to
        avoid overwhelming the network or the target hosts.

        Parameters
        ----------
        fqdns:
            Set of fully-qualified domain names to verify.
        domain_id:
            Parent domain primary key.
        technique:
            Discovery technique label applied to all subdomains in this batch.

        Returns
        -------
        List of verification result dicts (one per FQDN).
        """
        semaphore = asyncio.Semaphore(
            getattr(self._config.scan, "concurrent_threads", _DEFAULT_SEMAPHORE)
        )

        async def _guarded(fqdn: str) -> dict:
            async with semaphore:
                try:
                    return await self.verify_subdomain(fqdn, domain_id, technique)
                except Exception as exc:
                    logger.error("Unhandled error verifying %s: %s", fqdn, exc)
                    return {"fqdn": fqdn, "error": str(exc)}

        tasks = [_guarded(fqdn) for fqdn in fqdns]
        results = await asyncio.gather(*tasks)
        return list(results)

    async def generate_change_events(
        self,
        fqdn: str,
        old_data: dict,
        new_data: dict,
    ) -> list[dict]:
        """
        Compare old and new subdomain state and produce change event dicts.

        Detected change types
        ---------------------
        - ``SUBDOMAIN_NEW``         – subdomain seen for the first time
        - ``SUBDOMAIN_CAME_ALIVE``  – was dead, now live
        - ``SUBDOMAIN_WENT_DEAD``   – was live, now dead
        - ``TAKEOVER_DETECTED``     – new takeover vulnerability found
        - ``TECH_ADDED``            – new technology detected
        - ``TECH_REMOVED``          – technology no longer detected
        - ``STATUS_CHANGE``         – HTTP status code changed
        - ``IP_CHANGE``             – resolved IP addresses changed
        - ``CERT_CHANGE``           – TLS certificate fingerprint changed

        Parameters
        ----------
        fqdn:
            The subdomain FQDN.
        old_data:
            Previous verification result dict (empty dict if first scan).
        new_data:
            Current verification result dict.

        Returns
        -------
        List of change event dicts ready for
        :meth:`~database.DatabaseManager.add_change_event`.
        """
        events: list[dict] = []

        def _event(event_type: str, severity: str, description: str, diff: dict | None = None) -> dict:
            return {
                "event_type": event_type,
                "severity": severity,
                "target": fqdn,
                "description": description,
                "diff_data": diff,
            }

        # New subdomain (no previous record)
        if not old_data:
            events.append(_event(
                "SUBDOMAIN_NEW",
                "INFO",
                f"New subdomain discovered: {fqdn}",
                {"discovery_technique": new_data.get("discovery_technique")},
            ))
            if new_data.get("takeover"):
                events.append(_event(
                    "TAKEOVER_DETECTED",
                    "HIGH",
                    f"Subdomain takeover vulnerability: {new_data['takeover']['service']} "
                    f"({new_data['takeover']['confidence']})",
                    new_data["takeover"],
                ))
            return events

        # Liveness changes
        old_live = old_data.get("live", False)
        new_live = new_data.get("live", False)
        if not old_live and new_live:
            events.append(_event(
                "SUBDOMAIN_CAME_ALIVE",
                "MEDIUM",
                f"{fqdn} is now responding to HTTP requests (HTTP {new_data.get('status_code')})",
            ))
        elif old_live and not new_live:
            events.append(_event(
                "SUBDOMAIN_WENT_DEAD",
                "LOW",
                f"{fqdn} is no longer responding to HTTP requests",
            ))

        # HTTP status code change
        old_status = old_data.get("status_code", 0)
        new_status = new_data.get("status_code", 0)
        if old_status and new_status and old_status != new_status:
            events.append(_event(
                "STATUS_CHANGE",
                "LOW",
                f"HTTP status changed from {old_status} to {new_status} on {fqdn}",
                {"old_status": old_status, "new_status": new_status},
            ))

        # IP address changes
        old_ips = set(old_data.get("a_records", []) + old_data.get("aaaa_records", []))
        new_ips = set(new_data.get("a_records", []) + new_data.get("aaaa_records", []))
        if old_ips and new_ips and old_ips != new_ips:
            added_ips = new_ips - old_ips
            removed_ips = old_ips - new_ips
            events.append(_event(
                "IP_CHANGE",
                "MEDIUM",
                f"IP addresses changed for {fqdn}: +{sorted(added_ips)} -{sorted(removed_ips)}",
                {"added": sorted(added_ips), "removed": sorted(removed_ips)},
            ))

        # Technology stack changes
        old_techs = set(old_data.get("technologies", []) or [])
        new_techs = set(new_data.get("technologies", []) or [])
        added_techs = new_techs - old_techs
        removed_techs = old_techs - new_techs
        if added_techs:
            events.append(_event(
                "TECH_ADDED",
                "LOW",
                f"New technologies detected on {fqdn}: {sorted(added_techs)}",
                {"technologies": sorted(added_techs)},
            ))
        if removed_techs:
            events.append(_event(
                "TECH_REMOVED",
                "INFO",
                f"Technologies no longer detected on {fqdn}: {sorted(removed_techs)}",
                {"technologies": sorted(removed_techs)},
            ))

        # TLS certificate fingerprint change
        old_cert = old_data.get("cert_fingerprint")
        new_cert = new_data.get("cert_fingerprint")
        if old_cert and new_cert and old_cert != new_cert:
            events.append(_event(
                "CERT_CHANGE",
                "MEDIUM",
                f"TLS certificate changed on {fqdn}",
                {"old_fingerprint": old_cert, "new_fingerprint": new_cert},
            ))

        # Takeover vulnerability appearing
        old_takeover = old_data.get("takeover")
        new_takeover = new_data.get("takeover")
        if new_takeover and not old_takeover:
            events.append(_event(
                "TAKEOVER_DETECTED",
                "HIGH",
                f"Subdomain takeover vulnerability: {new_takeover['service']} "
                f"({new_takeover['confidence']})",
                new_takeover,
            ))

        return events

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _persist(self, result: dict) -> None:
        """Upsert the verification result into the database."""
        fqdn = result["fqdn"]
        domain_id = result["domain_id"]

        # Determine status string
        if result.get("live"):
            status = "alive"
        elif result.get("dns_resolved"):
            status = "dead"
        else:
            status = "unknown"

        # Compute a simple body hash if body data was included
        body_hash: Optional[str] = result.get("body_hash")

        takeover_vulnerable = bool(result.get("takeover"))

        try:
            self._db.upsert_subdomain(
                fqdn=fqdn,
                domain_id=domain_id,
                discovery_technique=result.get("discovery_technique"),
                status=status,
                ip_addresses=(
                    result.get("a_records", []) + result.get("aaaa_records", [])
                ) or None,
                technologies=result.get("technologies") or None,
                http_status=result.get("status_code") or None,
                page_title=result.get("page_title") or None,
                classification=result.get("classification"),
                favicon_hash=result.get("favicon_hash"),
                body_hash=body_hash,
                cert_fingerprint=result.get("cert_fingerprint"),
                takeover_vulnerable=takeover_vulnerable,
            )

            # Add a snapshot scan record
            self._db.add_scan_record(
                subdomain_id=self._db.get_subdomain(fqdn).id,
                status=status,
                http_status=result.get("status_code") or None,
                response_size=result.get("response_size") or None,
                body_hash=body_hash,
                technologies=result.get("technologies") or None,
                raw_headers=result.get("response_headers") or None,
            )
        except Exception as exc:
            logger.error("Database upsert failed for %s: %s", fqdn, exc)
