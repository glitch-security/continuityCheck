"""Certificate Transparency log enumeration via crt.sh.

Two complementary queries are run concurrently:
  - %.{domain}  — wildcard: catches every cert whose SAN/CN matches a subdomain
  - {domain}    — exact:    catches apex-domain certs whose SAN list includes
                             subdomains (e.g. a cert for example.com with SANs
                             api.example.com, app.example.com, ...)

Both name_value (SANs, multi-line) and common_name are parsed so no subdomains
are missed regardless of how the CA encoded them.
"""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx
from loguru import logger

_BASE = "https://crt.sh/"
_MAX_RETRIES = 3


def _extract_names(entry: dict, domain: str) -> set[str]:
    """Pull all valid subdomains out of a single crt.sh JSON entry."""
    found: set[str] = set()
    candidates: list[str] = []

    # name_value may contain multiple SANs separated by newlines
    name_value: Optional[str] = entry.get("name_value")
    if name_value:
        candidates.extend(name_value.splitlines())

    # common_name is a separate field that occasionally differs from name_value
    common_name: Optional[str] = entry.get("common_name")
    if common_name:
        candidates.append(common_name)

    suffix = f".{domain}"
    for raw in candidates:
        name = raw.strip().lower()
        if not name:
            continue
        # Strip leading wildcard (*.sub.example.com → sub.example.com)
        if name.startswith("*."):
            name = name[2:]
        if name == domain or name.endswith(suffix):
            found.add(name)

    return found


async def _query_crt(
    client: httpx.AsyncClient,
    query: str,
    domain: str,
    label: str,
) -> set[str]:
    """Run a single crt.sh query with retry/backoff; return extracted subdomains."""
    params = {"q": query, "output": "json", "deduplicate": "Y"}
    subdomains: set[str] = set()

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            logger.debug(f"CT logs [{label}]: querying crt.sh (attempt {attempt}/{_MAX_RETRIES})")
            response = await client.get(_BASE, params=params)
            response.raise_for_status()

            entries = response.json()
            if not isinstance(entries, list):
                logger.warning(f"CT logs [{label}]: unexpected response type {type(entries)}")
                return subdomains

            for entry in entries:
                subdomains.update(_extract_names(entry, domain))

            logger.debug(f"CT logs [{label}]: {len(entries)} cert records → {len(subdomains)} subdomains")
            return subdomains

        except httpx.HTTPStatusError as exc:
            logger.warning(
                f"CT logs [{label}]: HTTP {exc.response.status_code} "
                f"on attempt {attempt}/{_MAX_RETRIES}"
            )
        except (httpx.RequestError, ValueError) as exc:
            logger.warning(
                f"CT logs [{label}]: request error on attempt {attempt}/{_MAX_RETRIES}: {exc}"
            )

        if attempt < _MAX_RETRIES:
            backoff = 2 ** (attempt - 1)
            logger.debug(f"CT logs [{label}]: waiting {backoff}s before retry")
            await asyncio.sleep(backoff)

    logger.error(f"CT logs [{label}]: all {_MAX_RETRIES} attempts failed")
    return subdomains


async def enumerate_ct_logs(domain: str, timeout: int = 15) -> set[str]:
    """Query crt.sh for Certificate Transparency log entries for *domain*.

    Runs two concurrent queries:
    - ``%.{domain}`` — standard wildcard query for all subdomain certs
    - ``{domain}``   — apex query to capture SANs on root-domain certs

    Both ``name_value`` (SANs) and ``common_name`` fields are parsed.

    Args:
        domain: Root domain to enumerate (e.g. ``example.com``).
        timeout: Per-request HTTP timeout in seconds.

    Returns:
        Deduplicated set of subdomains discovered in CT logs.
    """
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        wildcard_task = asyncio.create_task(
            _query_crt(client, f"%.{domain}", domain, "wildcard")
        )
        apex_task = asyncio.create_task(
            _query_crt(client, domain, domain, "apex")
        )
        wildcard_results, apex_results = await asyncio.gather(
            wildcard_task, apex_task, return_exceptions=True
        )

    subdomains: set[str] = set()

    if isinstance(wildcard_results, set):
        subdomains.update(wildcard_results)
    else:
        logger.error(f"CT logs [wildcard] raised exception: {wildcard_results}")

    if isinstance(apex_results, set):
        subdomains.update(apex_results)
    else:
        logger.error(f"CT logs [apex] raised exception: {apex_results}")

    logger.info(f"CT logs: {len(subdomains)} unique subdomains found for {domain}")
    return subdomains
