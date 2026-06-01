"""Wayback Machine CDX API subdomain enumeration."""

import json
from urllib.parse import urlparse

import httpx
from loguru import logger


async def enumerate_wayback(domain: str, timeout: int = 30) -> set[str]:
    """Enumerate subdomains discovered in Wayback Machine CDX archives.

    Streams the CDX JSON response to handle large result sets without loading
    the entire payload into memory at once.

    Args:
        domain: Target domain.
        timeout: HTTP request timeout in seconds.

    Returns:
        Deduplicated set of hostnames ending in ``.{domain}`` found across
        archived URLs.
    """
    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*"
        f"&output=json"
        f"&fl=original"
        f"&collapse=urlkey"
        f"&limit=10000"
    )
    subdomains: set[str] = set()

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            logger.debug(f"Wayback: fetching CDX data for {domain}")
            async with client.stream("GET", url) as response:
                response.raise_for_status()

                # Accumulate raw bytes; CDX returns a JSON array of arrays
                chunks: list[bytes] = []
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    chunks.append(chunk)

            raw = b"".join(chunks)

        try:
            entries = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(f"Wayback: JSON parse error for {domain}: {exc}")
            return subdomains

        # First row is a header ["original"] when output=json
        first_row_skipped = False
        for row in entries:
            if not first_row_skipped:
                first_row_skipped = True
                # Skip header row ["original"]
                if row and str(row[0]).lower() == "original":
                    continue

            if not row:
                continue

            raw_url: str = str(row[0])
            try:
                parsed = urlparse(raw_url)
                hostname = parsed.hostname or ""
            except Exception:  # noqa: BLE001
                continue

            hostname = hostname.lower().rstrip(".")
            if hostname and hostname.endswith(f".{domain}"):
                subdomains.add(hostname)

    except httpx.HTTPStatusError as exc:
        logger.warning(f"Wayback: HTTP {exc.response.status_code} for {domain}")
    except httpx.RequestError as exc:
        logger.warning(f"Wayback: request error for {domain}: {exc}")

    logger.info(f"Wayback: found {len(subdomains)} subdomains for {domain}")
    return subdomains
