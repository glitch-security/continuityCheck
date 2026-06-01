"""Passive DNS enumeration from multiple public providers."""

from typing import Optional

import httpx
from bs4 import BeautifulSoup
from loguru import logger


def _filter_by_domain(names: set[str], domain: str) -> set[str]:
    """Return only names that are subdomains of or equal to *domain*."""
    result: set[str] = set()
    for name in names:
        name = name.strip().lower().rstrip(".")
        if name == domain or name.endswith(f".{domain}"):
            result.add(name)
    return result


async def hackertarget(domain: str, timeout: int = 10) -> set[str]:
    """Query HackerTarget hostsearch API.

    Args:
        domain: Target domain.
        timeout: Request timeout in seconds.

    Returns:
        Set of subdomains discovered.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            if response.status_code == 429:
                logger.warning(f"HackerTarget: rate limited for {domain}")
                return subdomains
            response.raise_for_status()
            for line in response.text.splitlines():
                parts = line.split(",")
                if parts:
                    hostname = parts[0].strip().lower()
                    if hostname:
                        subdomains.add(hostname)
    except httpx.HTTPStatusError as exc:
        logger.warning(f"HackerTarget: HTTP {exc.response.status_code} for {domain}")
    except httpx.RequestError as exc:
        logger.warning(f"HackerTarget: request error for {domain}: {exc}")

    return _filter_by_domain(subdomains, domain)


async def virustotal(domain: str, api_key: str, timeout: int = 10) -> set[str]:
    """Query VirusTotal subdomains API with pagination.

    Args:
        domain: Target domain.
        api_key: VirusTotal API key.
        timeout: Request timeout in seconds.

    Returns:
        Set of subdomains discovered.
    """
    subdomains: set[str] = set()
    url: Optional[str] = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            while url:
                response = await client.get(url, headers=headers)
                if response.status_code == 429:
                    logger.warning(f"VirusTotal: rate limited for {domain}")
                    break
                response.raise_for_status()
                data = response.json()
                for item in data.get("data", []):
                    item_id: Optional[str] = item.get("id")
                    if item_id:
                        subdomains.add(item_id.strip().lower())
                # Pagination cursor
                url = data.get("links", {}).get("next")
    except httpx.HTTPStatusError as exc:
        logger.warning(f"VirusTotal: HTTP {exc.response.status_code} for {domain}")
    except httpx.RequestError as exc:
        logger.warning(f"VirusTotal: request error for {domain}: {exc}")
    except ValueError as exc:
        logger.warning(f"VirusTotal: JSON parse error for {domain}: {exc}")

    return _filter_by_domain(subdomains, domain)


async def alienvault(domain: str, timeout: int = 10) -> set[str]:
    """Query AlienVault OTX passive DNS.

    Args:
        domain: Target domain.
        timeout: Request timeout in seconds.

    Returns:
        Set of subdomains discovered.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            if response.status_code == 429:
                logger.warning(f"AlienVault: rate limited for {domain}")
                return subdomains
            response.raise_for_status()
            data = response.json()
            for record in data.get("passive_dns", []):
                hostname: Optional[str] = record.get("hostname")
                if hostname:
                    subdomains.add(hostname.strip().lower())
    except httpx.HTTPStatusError as exc:
        logger.warning(f"AlienVault: HTTP {exc.response.status_code} for {domain}")
    except httpx.RequestError as exc:
        logger.warning(f"AlienVault: request error for {domain}: {exc}")
    except ValueError as exc:
        logger.warning(f"AlienVault: JSON parse error for {domain}: {exc}")

    return _filter_by_domain(subdomains, domain)


async def rapiddns(domain: str, timeout: int = 10) -> set[str]:
    """Scrape RapidDNS for subdomains.

    Args:
        domain: Target domain.
        timeout: Request timeout in seconds.

    Returns:
        Set of subdomains discovered.
    """
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subdomains: set[str] = set()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; asset-monitor/1.0)"},
            follow_redirects=True,
        ) as client:
            response = await client.get(url)
            if response.status_code == 429:
                logger.warning(f"RapidDNS: rate limited for {domain}")
                return subdomains
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            # RapidDNS renders results in a <table>; first column is the subdomain
            for table in soup.find_all("table"):
                for row in table.find_all("tr"):
                    cells = row.find_all("td")
                    if cells:
                        candidate = cells[0].get_text(strip=True).lower()
                        if candidate:
                            subdomains.add(candidate)
    except httpx.HTTPStatusError as exc:
        logger.warning(f"RapidDNS: HTTP {exc.response.status_code} for {domain}")
    except httpx.RequestError as exc:
        logger.warning(f"RapidDNS: request error for {domain}: {exc}")

    return _filter_by_domain(subdomains, domain)


async def aggregate_passive_dns(
    domain: str,
    api_keys: dict,
    timeout: int = 10,
) -> set[str]:
    """Call all passive DNS providers and merge deduplicated results.

    Args:
        domain: Target domain.
        api_keys: Dictionary of provider name -> API key. Expected keys:
                  ``virustotal`` (optional; provider skipped if absent).
        timeout: Request timeout in seconds for each provider.

    Returns:
        Deduplicated set of subdomains across all providers, filtered to the
        target domain suffix.
    """
    import asyncio

    results: list[set[str]] = []

    providers = [
        ("HackerTarget", hackertarget(domain, timeout)),
        ("AlienVault", alienvault(domain, timeout)),
        ("RapidDNS", rapiddns(domain, timeout)),
    ]

    vt_key: Optional[str] = api_keys.get("virustotal")
    if vt_key:
        providers.append(("VirusTotal", virustotal(domain, vt_key, timeout)))
    else:
        logger.debug("Passive DNS: VirusTotal skipped (no API key provided)")

    async def run_provider(name: str, coro) -> set[str]:
        try:
            found = await coro
            logger.info(f"Passive DNS [{name}]: {len(found)} subdomains for {domain}")
            return found
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Passive DNS [{name}]: unexpected error for {domain}: {exc}")
            return set()

    gathered = await asyncio.gather(
        *[run_provider(name, coro) for name, coro in providers]
    )

    merged: set[str] = set()
    for s in gathered:
        merged.update(s)

    merged = _filter_by_domain(merged, domain)
    logger.info(f"Passive DNS: {len(merged)} total unique subdomains for {domain}")
    return merged
