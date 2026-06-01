"""TLS certificate Subject Alternative Name (SAN) extraction."""

import asyncio
import ssl
from typing import Optional

from loguru import logger


def _extract_sans_from_cert(cert: dict) -> list[str]:
    """Extract SAN DNS names from a decoded certificate dict (ssl.getpeercert format)."""
    sans: list[str] = []
    for field_name, value in cert.get("subjectAltName", []):
        if field_name.upper() == "DNS":
            sans.append(value)
    return sans


async def _get_sans_for_host(
    host: str,
    port: int = 443,
    timeout: int = 10,
) -> list[str]:
    """Open a TLS connection to *host*:*port* and return its SAN list.

    Certificate verification is intentionally disabled so we can inspect
    certificates even when they are self-signed or expired.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        conn = asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        # Retrieve the peer certificate in decoded form; DER=False → dict
        ssl_obj: Optional[ssl.SSLObject] = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            writer.close()
            await writer.wait_closed()
            return []
        cert = ssl_obj.getpeercert(binary_form=False)
        writer.close()
        await writer.wait_closed()
        if cert is None:
            return []
        return _extract_sans_from_cert(cert)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
        return []
    except Exception:  # noqa: BLE001
        return []


async def extract_ssl_sans(
    subdomains: set[str],
    domain: str,
    timeout: int = 10,
) -> set[str]:
    """Expand the known subdomain set by inspecting TLS certificates.

    For each subdomain in *subdomains*, attempts a TLS connection on port 443,
    reads the SAN list from the certificate, and returns any *new* entries that
    belong to *domain* (wildcards stripped, verification disabled).

    Args:
        subdomains: Already-known subdomains (used as input hosts and to avoid
                    re-reporting known entries).
        domain: Target domain used for filtering.
        timeout: Per-host TLS connection timeout in seconds.

    Returns:
        Set of newly discovered subdomains not present in *subdomains*.
    """
    sem = asyncio.Semaphore(20)
    new_subdomains: set[str] = set()
    lock = asyncio.Lock()

    async def probe(host: str) -> None:
        async with sem:
            sans = await _get_sans_for_host(host, timeout=timeout)
            for san in sans:
                san = san.strip().lower()
                # Strip wildcard prefix
                if san.startswith("*."):
                    san = san[2:]
                if not san:
                    continue
                if san == domain or san.endswith(f".{domain}"):
                    async with lock:
                        if san not in subdomains:
                            new_subdomains.add(san)

    tasks = [probe(host) for host in subdomains]
    await asyncio.gather(*tasks)

    logger.info(
        f"SSL SANs: discovered {len(new_subdomains)} new subdomains for {domain} "
        f"(from {len(subdomains)} probed hosts)"
    )
    return new_subdomains
