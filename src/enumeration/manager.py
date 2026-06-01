"""Enumeration orchestrator — runs all configured techniques and merges results."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from loguru import logger

from .ct_logs import enumerate_ct_logs
from .dns_bruteforce import bruteforce_dns
from .dns_records import enumerate_dns_records
from .js_analysis import enumerate_js_subdomains
from .passive_dns import aggregate_passive_dns
from .reverse_ip import enumerate_reverse_ip
from .ssl_san import extract_ssl_sans
from .wayback import enumerate_wayback
from .zone_transfer import attempt_zone_transfer

if TYPE_CHECKING:
    # Avoid circular imports at runtime; these types must exist in the wider project.
    from ..config import AppConfig  # type: ignore[import]
    from ..database import DatabaseManager  # type: ignore[import]


class EnumerationManager:
    """Orchestrates all subdomain enumeration techniques.

    Each technique is independently wrapped in a ``try/except`` so that a
    failure in one provider never prevents the others from running.
    """

    def __init__(self, config: "AppConfig", db: "DatabaseManager") -> None:
        self.config = config
        self.db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, domain: str) -> set[str]:
        """Run all enabled enumeration techniques and return merged results.

        Reads enabled technique names from ``config.enumeration.techniques``.
        Supported technique names (case-insensitive):

        * ``ct_logs``
        * ``dns_bruteforce``
        * ``passive_dns``
        * ``wayback``
        * ``ssl_san``
        * ``dns_records``
        * ``js_analysis``
        * ``zone_transfer``
        * ``reverse_ip``

        Args:
            domain: Target domain to enumerate.

        Returns:
            Fully deduplicated set of discovered subdomains.
        """
        enabled: list[str] = [
            t.lower() for t in getattr(self.config.enumeration, "techniques", [])
        ]

        logger.info(
            f"EnumerationManager: starting {len(enabled)} technique(s) for {domain}: "
            + ", ".join(enabled)
        )

        # Run all enabled techniques concurrently
        tasks: dict[str, asyncio.Task] = {}
        async with asyncio.TaskGroup() as tg:
            for technique in enabled:
                coro = self._run_technique(technique, domain)
                tasks[technique] = tg.create_task(coro, name=technique)

        all_subdomains: set[str] = set()
        for technique, task in tasks.items():
            result: set[str] = task.result() or set()
            logger.info(
                f"EnumerationManager: [{technique}] contributed {len(result)} subdomain(s)"
            )
            all_subdomains.update(result)

        # ── Expansion passes (depend on initial results) ────────────────────
        if "ssl_san" in enabled:
            ssl_new = await self._safe(
                "ssl_san (expansion)",
                extract_ssl_sans(
                    all_subdomains,
                    domain,
                    timeout=getattr(self.config.enumeration, "timeout", 10),
                ),
            )
            logger.info(
                f"EnumerationManager: [ssl_san expansion] contributed {len(ssl_new)} subdomain(s)"
            )
            all_subdomains.update(ssl_new)

        if "reverse_ip" in enabled:
            rev_new = await self._safe(
                "reverse_ip (expansion)",
                enumerate_reverse_ip(
                    all_subdomains,
                    domain,
                    timeout=getattr(self.config.enumeration, "timeout", 10),
                ),
            )
            logger.info(
                f"EnumerationManager: [reverse_ip expansion] contributed {len(rev_new)} subdomain(s)"
            )
            all_subdomains.update(rev_new)

        logger.info(
            f"EnumerationManager: enumeration complete — "
            f"{len(all_subdomains)} unique subdomain(s) found for {domain}"
        )
        return all_subdomains

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_technique(self, technique: str, domain: str) -> set[str]:
        """Dispatch to the appropriate enumeration function.

        Returns an empty set if the technique name is unknown or if an
        unhandled exception occurs.
        """
        cfg = self.config.enumeration
        timeout: int = getattr(cfg, "timeout", 10)
        resolvers: list[str] = getattr(cfg, "resolvers", ["8.8.8.8", "1.1.1.1"])

        logger.info(f"EnumerationManager: [{technique}] starting for {domain}")

        match technique:
            case "ct_logs":
                return await self._safe(
                    technique,
                    enumerate_ct_logs(domain, timeout=timeout),
                )

            case "dns_bruteforce":
                wordlist: str = getattr(cfg, "wordlist_path", "")
                if not wordlist:
                    logger.warning(
                        "EnumerationManager: [dns_bruteforce] skipped — no wordlist_path configured"
                    )
                    return set()
                return await self._safe(
                    technique,
                    bruteforce_dns(
                        domain,
                        wordlist_path=wordlist,
                        resolvers=resolvers,
                        max_concurrent=getattr(cfg, "dns_concurrency", 50),
                        timeout=timeout,
                    ),
                )

            case "passive_dns":
                api_keys: dict = getattr(cfg, "api_keys", {})
                return await self._safe(
                    technique,
                    aggregate_passive_dns(domain, api_keys=api_keys, timeout=timeout),
                )

            case "wayback":
                return await self._safe(
                    technique,
                    enumerate_wayback(domain, timeout=max(timeout, 30)),
                )

            case "ssl_san":
                # Initial pass with empty seed — real expansion happens post-merge
                logger.debug(
                    "EnumerationManager: [ssl_san] initial pass skipped; "
                    "expansion runs after other techniques complete"
                )
                return set()

            case "dns_records":
                return await self._safe(
                    technique,
                    enumerate_dns_records(domain, resolvers=resolvers, timeout=timeout),
                )

            case "js_analysis":
                base_url: str = getattr(cfg, "base_url", f"https://{domain}")
                return await self._safe(
                    technique,
                    enumerate_js_subdomains(domain, base_url=base_url, timeout=timeout),
                )

            case "zone_transfer":
                _success, subdomains = await self._safe_zone_transfer(domain, timeout)
                return subdomains

            case "reverse_ip":
                # Initial pass with empty seed — expansion runs after merge
                logger.debug(
                    "EnumerationManager: [reverse_ip] initial pass skipped; "
                    "expansion runs after other techniques complete"
                )
                return set()

            case _:
                logger.warning(
                    f"EnumerationManager: unknown technique '{technique}' — skipping"
                )
                return set()

    @staticmethod
    async def _safe(technique: str, coro) -> set[str]:
        """Await *coro* and return its result; log and return empty set on error."""
        try:
            result = await coro
            return result or set()
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"EnumerationManager: [{technique}] failed with {type(exc).__name__}: {exc}"
            )
            return set()

    @staticmethod
    async def _safe_zone_transfer(
        domain: str, timeout: int
    ) -> tuple[bool, set[str]]:
        """Safely attempt zone transfer, absorbing all exceptions."""
        try:
            return await attempt_zone_transfer(domain, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"EnumerationManager: [zone_transfer] failed with "
                f"{type(exc).__name__}: {exc}"
            )
            return False, set()
