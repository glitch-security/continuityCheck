"""
DNS resolver for subdomain verification.

Queries A, AAAA, and CNAME records using dnspython, rotates through a list of
resolvers, and classifies results as internal (RFC-1918) or external.
"""

from __future__ import annotations

import asyncio
import ipaddress
import itertools
import logging
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC-1918 private networks
# ---------------------------------------------------------------------------
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_internal_ip(address: str) -> bool:
    """Return True when *address* belongs to a private/loopback range."""
    try:
        ip = ipaddress.ip_address(address)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _make_resolver(nameserver: str, timeout: int) -> dns.asyncresolver.Resolver:
    """Build a configured async resolver pointing at a single nameserver."""
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


async def resolve_subdomain(
    fqdn: str,
    resolvers: list[str],
    timeout: int = 3,
) -> dict:
    """
    Resolve a fully-qualified domain name using the provided resolvers.

    Rotates through *resolvers* in a round-robin fashion for each record type.
    On NXDOMAIN the result carries ``resolved=False`` and empty record lists.

    Parameters
    ----------
    fqdn:
        The fully-qualified domain name to resolve (e.g. ``api.example.com``).
    resolvers:
        Non-empty list of DNS resolver IP addresses to use.
    timeout:
        Per-query timeout in seconds.

    Returns
    -------
    dict with keys:
        - ``fqdn``          (str)  – the queried name
        - ``a_records``     (list[str]) – IPv4 addresses
        - ``aaaa_records``  (list[str]) – IPv6 addresses
        - ``cname``         (str | None) – canonical name target, stripped of trailing dot
        - ``is_internal``   (bool) – True when any resolved IP is RFC-1918
        - ``resolved``      (bool) – False on NXDOMAIN / all-resolvers-failed
    """
    if not resolvers:
        raise ValueError("resolvers must contain at least one entry")

    result: dict = {
        "fqdn": fqdn,
        "a_records": [],
        "aaaa_records": [],
        "cname": None,
        "is_internal": False,
        "resolved": False,
    }

    resolver_cycle = itertools.cycle(resolvers)

    async def _query(rdtype: str) -> list[str]:
        """Query *rdtype* against the next resolver in the cycle.  Returns raw values."""
        nameserver = next(resolver_cycle)
        resolver = _make_resolver(nameserver, timeout)
        try:
            answer = await resolver.resolve(fqdn, rdtype)
            return [rdata.to_text() for rdata in answer]
        except dns.resolver.NXDOMAIN:
            raise
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return []
        except Exception as exc:  # pragma: no cover
            logger.debug("Unexpected DNS error querying %s %s: %s", fqdn, rdtype, exc)
            return []

    # ---- A records ----
    try:
        a_raw = await _query("A")
        result["a_records"] = a_raw
    except dns.resolver.NXDOMAIN:
        # Authoritative NXDOMAIN — no further queries needed
        return result

    # ---- AAAA records ----
    try:
        aaaa_raw = await _query("AAAA")
        result["aaaa_records"] = aaaa_raw
    except dns.resolver.NXDOMAIN:
        pass  # May have A records but no AAAA

    # ---- CNAME records ----
    try:
        cname_raw = await _query("CNAME")
        if cname_raw:
            # dnspython returns the target with a trailing dot; strip it
            result["cname"] = cname_raw[0].rstrip(".")
    except dns.resolver.NXDOMAIN:
        pass

    # Determine resolved / internal flags
    all_ips = result["a_records"] + result["aaaa_records"]
    if all_ips or result["cname"]:
        result["resolved"] = True
    if any(_is_internal_ip(ip) for ip in all_ips):
        result["is_internal"] = True

    return result
