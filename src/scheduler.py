"""
APScheduler-based periodic scan scheduler for the asset monitoring tool.

Loads domains from the database and from data/domains.txt / data/subdomains.txt /
data/websites.txt, runs the full enumeration + verification + change-detection
pipeline on the configured interval, dispatches notifications, and updates
domain timestamps.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.config import AppConfig
from src.database import ChangeEvent, DatabaseManager, Domain
from src.notifications.manager import NotificationManager

logger = logging.getLogger(__name__)

_DOMAINS_FILE = "data/domains.txt"


def _apply_profile_to_config(config: AppConfig, settings: dict) -> None:
    """Mutate *config* in-place to reflect the given profile settings dict."""
    enum_settings = settings.get("enumeration") or {}
    for k, v in enum_settings.items():
        if hasattr(config.enumeration.techniques, k):
            setattr(config.enumeration.techniques, k, bool(v))

    port_settings = settings.get("port_scanning") or {}
    if "enabled" in port_settings:
        config.port_scanning.enabled = bool(port_settings["enabled"])
    if port_settings.get("arguments"):
        config.port_scanning.scan_arguments = port_settings["arguments"]

    crawl_settings = settings.get("crawl") or {}
    if "max_depth" in crawl_settings:
        config.scan.max_crawl_depth = int(crawl_settings["max_depth"])
    if "max_pages" in crawl_settings:
        config.scan.max_pages_per_domain = int(crawl_settings["max_pages"])
    if "enabled" in crawl_settings:
        config.scan.crawl_enabled = bool(crawl_settings["enabled"])


_SUBDOMAINS_FILE = "data/subdomains.txt"
_WEBSITES_FILE = "data/websites.txt"


def _read_lines(path: str) -> List[str]:
    """Read non-empty, non-comment lines from a text file.

    Args:
        path: Path to the file (may not exist — returns empty list).

    Returns:
        Stripped lines that don't start with ``#``.
    """
    if not os.path.isfile(path):
        return []
    lines: List[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


class SchedManager:
    """Wraps APScheduler to run periodic full-scan jobs.

    Args:
        config:               Application configuration.
        db:                   :class:`DatabaseManager` instance.
        notification_manager: :class:`NotificationManager` for dispatching
                              alerts after each scan.
    """

    def __init__(
        self,
        config: AppConfig,
        db: DatabaseManager,
        notification_manager: NotificationManager,
    ) -> None:
        self._config = config
        self._db = db
        self._notification_manager = notification_manager
        self._scheduler = BackgroundScheduler(timezone="UTC")
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Schedule the full-scan job and start the background scheduler.

        The scan interval is taken from ``config.scan.interval_minutes``.
        """
        interval_minutes = self._config.scan.interval_minutes
        logger.info(
            "Scheduling full scan every %d minute(s)", interval_minutes
        )

        self._scheduler.add_job(
            func=self._run_scan_sync,
            trigger=IntervalTrigger(minutes=interval_minutes),
            id="full_scan",
            name="AssetMonitor full scan",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )

        self._scheduler.start()
        self._running = True
        logger.info("Scheduler started (interval=%d min)", interval_minutes)

    def stop(self) -> None:
        """Gracefully shut down the background scheduler."""
        if self._running:
            self._scheduler.shutdown(wait=True)
            self._running = False
            logger.info("Scheduler stopped")

    def reschedule(self, interval_minutes: int) -> None:
        """Update the scan interval without restarting the scheduler."""
        if not self._running:
            return
        self._scheduler.reschedule_job(
            "full_scan",
            trigger=IntervalTrigger(minutes=interval_minutes),
        )
        logger.info("Scan interval updated to %d minute(s)", interval_minutes)

    # ------------------------------------------------------------------
    # Internal bridge: APScheduler calls sync _run_scan_sync which in turn
    # drives the async run_full_scan coroutine.
    # ------------------------------------------------------------------

    def _run_scan_sync(self) -> None:
        """Synchronous wrapper so APScheduler can call the async scan."""
        try:
            asyncio.run(self.run_full_scan())
        except Exception as exc:  # noqa: BLE001
            logger.error("Unhandled error in scheduled scan: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Core async scan
    # ------------------------------------------------------------------

    async def run_full_scan(self) -> None:
        """Execute one full scan cycle across all configured targets.

        Steps:
        1. Collect root domains from the DB **and** ``domains.txt``.
        2. For each domain: run enumeration modules → verification → diff
           to generate :class:`ChangeEvent` objects.
        3. Collect known subdomains from ``subdomains.txt`` and verify them.
        4. Load websites from ``websites.txt`` → crawl → change detection.
        5. Dispatch notifications grouped by domain.
        6. Update ``domain.last_scan`` timestamps.
        7. Log a summary.
        """
        scan_start = datetime.now(tz=timezone.utc)
        logger.info("=== Full scan started at %s ===", scan_start.isoformat())

        # ----------------------------------------------------------------
        # 1. Collect root domains
        # ----------------------------------------------------------------
        db_domains: List[Domain] = self._db.get_all_domains()
        db_domain_names = {d.domain for d in db_domains}

        file_domains = _read_lines(_DOMAINS_FILE)
        for fd in file_domains:
            if fd not in db_domain_names:
                self._db.add_domain(fd)
                logger.info("Auto-added domain from domains.txt: %s", fd)

        all_domains: List[Domain] = self._db.get_all_domains()

        # ----------------------------------------------------------------
        # 2. Enumerate + verify each root domain
        # ----------------------------------------------------------------
        total_subdomains_found = 0
        all_new_events: List[ChangeEvent] = []

        for dom in all_domains:
            logger.info("Scanning domain: %s", dom.domain)
            orig_config = self._config
            try:
                if dom.profile_id:
                    profile = self._db.get_profile(dom.profile_id)
                    if profile and profile.settings:
                        import copy
                        self._config = copy.deepcopy(orig_config)
                        _apply_profile_to_config(self._config, profile.settings)
                        logger.info(
                            "Domain %s using profile %r", dom.domain, profile.name
                        )
                new_events, sub_count = await self._scan_domain(dom)
                total_subdomains_found += sub_count
                all_new_events.extend(new_events)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Error scanning domain %s: %s", dom.domain, exc, exc_info=True
                )
            finally:
                self._config = orig_config

        # ----------------------------------------------------------------
        # 3. Known subdomains from subdomains.txt
        # ----------------------------------------------------------------
        known_subs = _read_lines(_SUBDOMAINS_FILE)
        if known_subs:
            logger.info(
                "Processing %d known subdomain(s) from %s",
                len(known_subs),
                _SUBDOMAINS_FILE,
            )
            try:
                ks_events = await self._scan_known_subdomains(known_subs, all_domains)
                all_new_events.extend(ks_events)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Error scanning known subdomains: %s", exc, exc_info=True
                )

        # ----------------------------------------------------------------
        # 4. Websites from websites.txt
        # ----------------------------------------------------------------
        websites = _read_lines(_WEBSITES_FILE)
        if websites and self._config.scan.crawl_enabled:
            logger.info(
                "Processing %d website(s) from %s", len(websites), _WEBSITES_FILE
            )
            try:
                ws_events = await self._scan_websites(websites)
                all_new_events.extend(ws_events)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Error scanning websites: %s", exc, exc_info=True
                )

        # ----------------------------------------------------------------
        # 5. Port scanning
        # ----------------------------------------------------------------
        try:
            from src.scanning.manager import PortScanManager

            psm = PortScanManager(self._config, self._db)
            port_events = await psm.scan_all()
            all_new_events.extend(port_events)
        except ImportError:
            logger.debug("scanning module not available — skipping port scan")
        except Exception as exc:  # noqa: BLE001
            logger.error("Port scanning failed: %s", exc, exc_info=True)

        # ----------------------------------------------------------------
        # 6. Dispatch notifications
        # ----------------------------------------------------------------
        events_by_domain = self._group_events_by_domain(
            all_new_events, all_domains
        )

        for dom_name, dom_events in events_by_domain.items():
            if dom_events:
                try:
                    await self._notification_manager.dispatch(dom_events, dom_name)
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Notification dispatch error for %s: %s", dom_name, exc
                    )

        # ----------------------------------------------------------------
        # 6. Update domain.last_scan timestamps
        # ----------------------------------------------------------------
        now = datetime.now(tz=timezone.utc)
        with self._db.get_session() as session:
            for dom in all_domains:
                from sqlalchemy import update as _update
                from src.database import Domain as _Domain

                session.execute(
                    _update(_Domain)
                    .where(_Domain.id == dom.id)
                    .values(last_scan=now)
                )

        # ----------------------------------------------------------------
        # 7. Summary
        # ----------------------------------------------------------------
        elapsed = (datetime.now(tz=timezone.utc) - scan_start).total_seconds()
        logger.info(
            "=== Full scan complete in %.1fs — domains=%d, subdomains_found=%d, "
            "new_events=%d ===",
            elapsed,
            len(all_domains),
            total_subdomains_found,
            len(all_new_events),
        )

    # ------------------------------------------------------------------
    # Internal scan helpers
    # ------------------------------------------------------------------

    async def _scan_domain(
        self, dom: Domain
    ) -> tuple[List[ChangeEvent], int]:
        """Run enumeration and verification for a single root domain.

        Imports the enumeration and verification modules lazily to avoid
        circular dependencies and to allow each module to be optional.

        Returns:
            ``(new_events, subdomain_count)``
        """
        new_events: List[ChangeEvent] = []
        subdomain_count = 0

        cfg = self._config
        techniques = cfg.enumeration.techniques

        discovered_fqdns: set[str] = set()

        # CT logs
        if techniques.certificate_transparency:
            try:
                from src.enumeration.ct_logs import enumerate_ct_logs

                ct_fqdns = await enumerate_ct_logs(dom.domain)
                discovered_fqdns.update(ct_fqdns)
                logger.debug(
                    "CT logs found %d FQDNs for %s", len(ct_fqdns), dom.domain
                )
            except ImportError:
                logger.debug("ct_logs module not available — skipping")
            except Exception as exc:  # noqa: BLE001
                logger.warning("CT log enumeration failed for %s: %s", dom.domain, exc)

        # Passive DNS
        if techniques.passive_dns:
            try:
                from src.enumeration.passive_dns import aggregate_passive_dns

                pdns_fqdns = await aggregate_passive_dns(
                    dom.domain, cfg.api_keys.model_dump()
                )
                discovered_fqdns.update(pdns_fqdns)
                logger.debug(
                    "Passive DNS found %d FQDNs for %s",
                    len(pdns_fqdns),
                    dom.domain,
                )
            except ImportError:
                logger.debug("passive_dns module not available — skipping")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Passive DNS enumeration failed for %s: %s", dom.domain, exc
                )

        # Wayback Machine
        if techniques.wayback_machine:
            try:
                from src.enumeration.wayback import enumerate_wayback

                wb_fqdns = await enumerate_wayback(dom.domain)
                discovered_fqdns.update(wb_fqdns)
                logger.debug(
                    "Wayback found %d FQDNs for %s", len(wb_fqdns), dom.domain
                )
            except ImportError:
                logger.debug("wayback module not available — skipping")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Wayback enumeration failed for %s: %s", dom.domain, exc
                )

        # DNS records (MX, NS, CNAME, A)
        if techniques.dns_records:
            try:
                from src.enumeration.dns_records import enumerate_dns_records

                dr_fqdns = await enumerate_dns_records(dom.domain)
                discovered_fqdns.update(dr_fqdns)
                logger.debug(
                    "DNS records found %d FQDNs for %s", len(dr_fqdns), dom.domain
                )
            except ImportError:
                logger.debug("dns_records module not available — skipping")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "DNS records enumeration failed for %s: %s", dom.domain, exc
                )

        # DNS bruteforce
        if techniques.dns_bruteforce:
            try:
                from src.enumeration.dns_bruteforce import bruteforce_dns

                bf_fqdns = await bruteforce_dns(
                    dom.domain,
                    wordlist_path=cfg.enumeration.wordlist_path,
                    resolvers=cfg.enumeration.dns_resolvers,
                    max_concurrent=cfg.enumeration.max_dns_concurrent,
                )
                discovered_fqdns.update(bf_fqdns)
                logger.debug(
                    "DNS bruteforce found %d FQDNs for %s",
                    len(bf_fqdns),
                    dom.domain,
                )
            except ImportError:
                logger.debug("dns_bruteforce module not available — skipping")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "DNS bruteforce failed for %s: %s", dom.domain, exc
                )

        # Verify all discovered FQDNs: probe liveness, fingerprint, update DB
        if discovered_fqdns:
            try:
                from src.verification.manager import VerificationManager

                vm = VerificationManager(cfg, self._db)

                # Snapshot old state before verification mutates the DB
                old_states: dict[str, dict] = {}
                for fqdn in discovered_fqdns:
                    ex = self._db.get_subdomain(fqdn)
                    if ex:
                        old_states[fqdn] = {
                            "live": ex.status == "alive",
                            "a_records": list(ex.ip_addresses or []),
                            "aaaa_records": [],
                            "status_code": ex.http_status or 0,
                            "technologies": ex.technologies or [],
                            "cert_fingerprint": ex.cert_fingerprint,
                            "takeover": (
                                {"service": "unknown", "confidence": "unknown"}
                                if ex.takeover_vulnerable else None
                            ),
                        }

                # verify_batch probes each FQDN and upserts results into the DB
                results = await vm.verify_batch(
                    discovered_fqdns, dom.id, "enumeration"
                )
                subdomain_count = len([r for r in results if "error" not in r])

                # Generate and persist typed change events
                for res in results:
                    fqdn = res.get("fqdn", "")
                    if not fqdn or "error" in res:
                        continue
                    old = old_states.get(fqdn, {})
                    ev_data_list = await vm.generate_change_events(fqdn, old, res)
                    for ev_data in ev_data_list:
                        ev = self._db.add_change_event(**ev_data)
                        new_events.append(ev)

            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Verification failed for %s: %s", dom.domain, exc, exc_info=True
                )

        return new_events, subdomain_count

    async def _scan_known_subdomains(
        self,
        fqdns: List[str],
        all_domains: List[Domain],
    ) -> List[ChangeEvent]:
        """Upsert known subdomains and probe them, emitting change events."""
        new_events: List[ChangeEvent] = []

        # Map each FQDN to a parent domain
        domain_map = {d.domain: d for d in all_domains}

        for fqdn in fqdns:
            parent: Optional[Domain] = None
            for dom_name, dom_obj in domain_map.items():
                if fqdn.endswith(f".{dom_name}") or fqdn == dom_name:
                    parent = dom_obj
                    break

            if parent is None:
                # Create a synthetic root domain for orphan FQDNs
                parts = fqdn.split(".")
                root = ".".join(parts[-2:]) if len(parts) >= 2 else fqdn
                parent = self._db.add_domain(root)
                domain_map[root] = parent

            _, is_new = self._db.upsert_subdomain(
                fqdn=fqdn,
                domain_id=parent.id,
                discovery_technique="known-subdomains-file",
            )
            if is_new:
                ev = self._db.add_change_event(
                    event_type="NEW_SUBDOMAIN",
                    severity="MEDIUM",
                    target=fqdn,
                    description=(
                        f"Known subdomain added to monitoring: {fqdn}"
                    ),
                )
                new_events.append(ev)

        return new_events

    async def _scan_websites(self, urls: List[str]) -> List[ChangeEvent]:
        """Verify website URLs and generate change events."""
        import urllib.parse

        from src.verification.manager import VerificationManager

        new_events: List[ChangeEvent] = []
        vm = VerificationManager(self._config, self._db)

        for raw_url in urls:
            try:
                url = raw_url if raw_url.startswith(("http://", "https://")) else "https://" + raw_url
                hostname = urllib.parse.urlparse(url).hostname or ""
                if not hostname:
                    logger.warning("Cannot parse hostname from website URL: %s", raw_url)
                    continue

                # Find or create a parent domain for this hostname
                parts = hostname.split(".")
                root = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
                domain = self._db.get_domain(root) or self._db.add_domain(root)

                # Capture old state before verification
                ex = self._db.get_subdomain(hostname)
                old_state: dict = {}
                if ex:
                    old_state = {
                        "live": ex.status == "alive",
                        "a_records": list(ex.ip_addresses or []),
                        "aaaa_records": [],
                        "status_code": ex.http_status or 0,
                        "technologies": ex.technologies or [],
                        "cert_fingerprint": ex.cert_fingerprint,
                        "takeover": (
                            {"service": "unknown", "confidence": "unknown"}
                            if ex.takeover_vulnerable else None
                        ),
                    }

                result = await vm.verify_subdomain(hostname, domain.id, "website")
                ev_data_list = await vm.generate_change_events(hostname, old_state, result)
                for ev_data in ev_data_list:
                    ev = self._db.add_change_event(**ev_data)
                    new_events.append(ev)

            except Exception as exc:  # noqa: BLE001
                logger.warning("Website scan failed for %s: %s", raw_url, exc)

        return new_events

    def _group_events_by_domain(
        self,
        events: List[ChangeEvent],
        domains: List[Domain],
    ) -> dict[str, List[ChangeEvent]]:
        """Group change events by their root domain name.

        Events whose target doesn't match any known domain are placed under
        an ``"unknown"`` key.
        """
        grouped: dict[str, List[ChangeEvent]] = {
            d.domain: [] for d in domains
        }
        grouped["unknown"] = []

        for ev in events:
            matched = False
            for dom in domains:
                if ev.target == dom.domain or ev.target.endswith(
                    f".{dom.domain}"
                ):
                    grouped[dom.domain].append(ev)
                    matched = True
                    break
            if not matched:
                grouped["unknown"].append(ev)

        # Remove empty buckets
        return {k: v for k, v in grouped.items() if v}

    async def run_domain_scan(
        self,
        domain_name: str,
        technique_overrides: Optional[dict] = None,
    ) -> tuple[int, int]:
        """Run enumeration + verification for a single domain (web-triggered).

        Args:
            domain_name:         Root domain to scan. Added to DB if not present.
            technique_overrides: Optional dict of technique flag overrides, e.g.
                                 ``{"dns_bruteforce": False}``.  Applied on top of
                                 the global config for this scan only.

        Returns:
            ``(subdomains_found, events_generated)``
        """
        import copy

        domain = self._db.add_domain(domain_name)

        orig_config = self._config
        if domain.profile_id or technique_overrides:
            self._config = copy.deepcopy(orig_config)
            # Apply domain profile first, then technique_overrides on top
            if domain.profile_id:
                profile = self._db.get_profile(domain.profile_id)
                if profile and profile.settings:
                    _apply_profile_to_config(self._config, profile.settings)
                    logger.info("Using profile %r for domain %s", profile.name, domain_name)
            if technique_overrides:
                techniques = self._config.enumeration.techniques
                for k, v in technique_overrides.items():
                    if hasattr(techniques, k):
                        setattr(techniques, k, bool(v))

        try:
            events, sub_count = await self._scan_domain(domain)
        finally:
            self._config = orig_config

        if events:
            try:
                await self._notification_manager.dispatch(events, domain_name)
            except Exception as exc:  # noqa: BLE001
                logger.error("Notification dispatch error for %s: %s", domain_name, exc)

        from sqlalchemy import update as _update
        from src.database import Domain as _Domain
        with self._db.get_session() as session:
            session.execute(
                _update(_Domain)
                .where(_Domain.id == domain.id)
                .values(last_scan=datetime.now(tz=timezone.utc))
            )

        logger.info(
            "Domain scan complete for %s: %d subdomains, %d events",
            domain_name, sub_count, len(events),
        )
        return sub_count, len(events)
