"""Certificate Transparency log enumeration via crt.sh."""

import asyncio
from typing import Optional

import httpx
from loguru import logger


async def enumerate_ct_logs(domain: str, timeout: int = 15) -> set[str]:
    """Query crt.sh for certificate transparency log entries for a domain.

    Args:
        domain: Target domain to enumerate subdomains for.
        timeout: HTTP request timeout in seconds.

    Returns:
        Deduplicated set of subdomains found in CT logs.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    max_retries = 3
    subdomains: set[str] = set()

    for attempt in range(1, max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                logger.debug(f"CT logs: querying crt.sh for {domain} (attempt {attempt}/{max_retries})")
                response = await client.get(url)
                response.raise_for_status()
                entries = response.json()

            for entry in entries:
                name_value: Optional[str] = entry.get("name_value")
                if not name_value:
                    continue
                # Handle multi-line entries (multiple SANs in one cert record)
                for line in name_value.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # Strip leading wildcard
                    if line.startswith("*."):
                        line = line[2:]
                    # Filter: only keep subdomains of target domain
                    if line == domain or line.endswith(f".{domain}"):
                        subdomains.add(line.lower())

            logger.info(f"CT logs: found {len(subdomains)} subdomains for {domain}")
            return subdomains

        except httpx.HTTPStatusError as exc:
            logger.warning(
                f"CT logs: HTTP {exc.response.status_code} on attempt {attempt}/{max_retries} for {domain}"
            )
        except (httpx.RequestError, ValueError) as exc:
            logger.warning(f"CT logs: request error on attempt {attempt}/{max_retries} for {domain}: {exc}")

        if attempt < max_retries:
            backoff = 2 ** (attempt - 1)  # 1s, 2s, 4s
            logger.debug(f"CT logs: waiting {backoff}s before retry")
            await asyncio.sleep(backoff)

    logger.error(f"CT logs: all {max_retries} attempts failed for {domain}, returning partial results")
    return subdomains
