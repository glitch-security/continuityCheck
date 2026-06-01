"""Reverse IP lookup for subdomain expansion, skipping CDN-hosted IPs."""

import asyncio
import ipaddress
from typing import Optional

import dns.asyncresolver
import dns.exception
import httpx
from loguru import logger

# ---------------------------------------------------------------------------
# Known CDN CIDR blocks (Cloudflare, Akamai, Fastly, AWS CloudFront)
# Kept reasonably current as of early 2025; extend as needed.
# ---------------------------------------------------------------------------
CDN_CIDR_BLOCKS: list[str] = [
    # Cloudflare
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
    # Akamai (representative ranges)
    "23.32.0.0/11",
    "23.64.0.0/14",
    "23.192.0.0/11",
    "104.64.0.0/10",
    "184.24.0.0/13",
    "2.16.0.0/13",
    "96.16.0.0/15",
    "96.6.0.0/15",
    # Fastly
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",
    # AWS CloudFront
    "120.52.22.96/27",
    "205.251.192.0/19",
    "205.251.249.0/24",
    "54.230.0.0/16",
    "54.239.128.0/18",
    "99.86.0.0/16",
    "130.176.0.0/16",
    "64.252.64.0/18",
    "204.246.172.0/24",
    "204.246.164.0/22",
    "204.246.168.0/22",
    "70.132.0.0/18",
    "13.32.0.0/15",
    "13.224.0.0/14",
    "13.35.0.0/16",
    "204.246.174.0/23",
    "204.246.176.0/20",
    "204.246.176.0/21",
]

# Pre-parse CIDR networks once at import time for fast membership tests
_CDN_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
for _cidr in CDN_CIDR_BLOCKS:
    try:
        _CDN_NETWORKS.append(ipaddress.ip_network(_cidr, strict=False))
    except ValueError:
        pass


async def is_cdn_ip(ip: str) -> bool:
    """Return True if *ip* falls within any known CDN CIDR block.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        True if the address belongs to a CDN range.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for network in _CDN_NETWORKS:
        try:
            if addr in network:
                return True
        except TypeError:
            continue
    return False


async def reverse_ip_lookup(ip: str, timeout: int = 10) -> set[str]:
    """Query HackerTarget reverse IP API for co-hosted hostnames.

    Args:
        ip: Target IP address.
        timeout: HTTP request timeout in seconds.

    Returns:
        Set of hostnames sharing the same IP according to HackerTarget.
    """
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    hostnames: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            if response.status_code == 429:
                logger.warning(f"Reverse IP: rate limited by HackerTarget for {ip}")
                return hostnames
            response.raise_for_status()
            for line in response.text.splitlines():
                host = line.strip().lower()
                if host and not host.startswith("no ") and "error" not in host:
                    hostnames.add(host)
    except httpx.HTTPStatusError as exc:
        logger.warning(f"Reverse IP: HTTP {exc.response.status_code} for {ip}")
    except httpx.RequestError as exc:
        logger.warning(f"Reverse IP: request error for {ip}: {exc}")
    return hostnames


async def _resolve_to_ip(host: str, timeout: int) -> Optional[str]:
    """Resolve *host* to its first IPv4 address, or None on failure."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = float(timeout)
    try:
        answer = await resolver.resolve(host, "A")
        for rdata in answer:
            return str(rdata.address)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        pass
    except Exception:  # noqa: BLE001
        pass
    return None


async def enumerate_reverse_ip(
    subdomains: set[str],
    domain: str,
    timeout: int = 10,
) -> set[str]:
    """Expand the known subdomain set via reverse IP lookups on non-CDN hosts.

    For each subdomain, resolves its IP, skips addresses hosted on CDN
    infrastructure, then queries HackerTarget for co-hosted hostnames.

    Args:
        subdomains: Already-known subdomains to use as seed hosts.
        domain: Target domain used for filtering results.
        timeout: Per-request timeout in seconds.

    Returns:
        Set of newly discovered subdomains ending in ``.{domain}`` not already
        present in *subdomains*.
    """
    new_subdomains: set[str] = set()
    seen_ips: set[str] = set()
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(10)  # Be gentle with HackerTarget

    async def process_host(host: str) -> None:
        async with sem:
            ip = await _resolve_to_ip(host, timeout)
            if not ip:
                return

            async with lock:
                if ip in seen_ips:
                    return
                seen_ips.add(ip)

            on_cdn = await is_cdn_ip(ip)
            if on_cdn:
                logger.debug(f"Reverse IP: {host} ({ip}) is a CDN IP — skipping")
                return

            logger.debug(f"Reverse IP: looking up co-hosted names for {ip} (from {host})")
            cohosted = await reverse_ip_lookup(ip, timeout)
            for hostname in cohosted:
                hostname = hostname.lower().rstrip(".")
                if hostname == domain or hostname.endswith(f".{domain}"):
                    async with lock:
                        if hostname not in subdomains:
                            new_subdomains.add(hostname)

    tasks = [process_host(host) for host in subdomains]
    await asyncio.gather(*tasks)

    logger.info(
        f"Reverse IP: discovered {len(new_subdomains)} new subdomains for {domain} "
        f"(checked {len(seen_ips)} unique IPs)"
    )
    return new_subdomains
