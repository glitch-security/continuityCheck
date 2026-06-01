"""DNS record enumeration (MX, NS, TXT, SOA) for target domain."""

import re

import dns.asyncresolver
import dns.exception
import dns.rdatatype
from loguru import logger


async def enumerate_dns_records(
    domain: str,
    resolvers: list[str],
    timeout: int = 5,
) -> set[str]:
    """Enumerate MX, NS, TXT, and SOA records and extract FQDNs belonging to *domain*.

    Args:
        domain: Target domain.
        resolvers: List of DNS resolver IP addresses.
        timeout: Per-query lifetime in seconds.

    Returns:
        Deduplicated set of FQDNs ending in ``.{domain}`` extracted from DNS records.
    """
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = resolvers
    resolver.lifetime = float(timeout)

    found: set[str] = set()

    def _normalise(name: str) -> str:
        return name.strip().lower().rstrip(".")

    def _keep(name: str) -> bool:
        return name == domain or name.endswith(f".{domain}")

    # ── MX records ─────────────────────────────────────────────────────────────
    try:
        answer = await resolver.resolve(domain, "MX")
        for rdata in answer:
            mx_host = _normalise(str(rdata.exchange))
            if mx_host and _keep(mx_host):
                found.add(mx_host)
        logger.debug(f"DNS records: MX resolved for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.debug(f"DNS records: no MX records for {domain}")
    except dns.exception.Timeout:
        logger.warning(f"DNS records: MX query timed out for {domain}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"DNS records: MX error for {domain}: {exc}")

    # ── NS records ─────────────────────────────────────────────────────────────
    try:
        answer = await resolver.resolve(domain, "NS")
        for rdata in answer:
            ns_host = _normalise(str(rdata.target))
            if ns_host and _keep(ns_host):
                found.add(ns_host)
        logger.debug(f"DNS records: NS resolved for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.debug(f"DNS records: no NS records for {domain}")
    except dns.exception.Timeout:
        logger.warning(f"DNS records: NS query timed out for {domain}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"DNS records: NS error for {domain}: {exc}")

    # ── TXT records ────────────────────────────────────────────────────────────
    # Pattern matches any token that looks like *.domain or domain itself
    _fqdn_pattern = re.compile(
        r"(?:^|[\s:=])([a-zA-Z0-9\-_]+(?:\.[a-zA-Z0-9\-_]+)*\."
        + re.escape(domain)
        + r")\b",
        re.IGNORECASE,
    )
    try:
        answer = await resolver.resolve(domain, "TXT")
        for rdata in answer:
            txt_value = " ".join(
                part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            )
            for match in _fqdn_pattern.finditer(txt_value):
                candidate = _normalise(match.group(1))
                if candidate and _keep(candidate):
                    found.add(candidate)
        logger.debug(f"DNS records: TXT resolved for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.debug(f"DNS records: no TXT records for {domain}")
    except dns.exception.Timeout:
        logger.warning(f"DNS records: TXT query timed out for {domain}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"DNS records: TXT error for {domain}: {exc}")

    # ── SOA record ─────────────────────────────────────────────────────────────
    try:
        answer = await resolver.resolve(domain, "SOA")
        for rdata in answer:
            primary_ns = _normalise(str(rdata.mname))
            if primary_ns and _keep(primary_ns):
                found.add(primary_ns)
        logger.debug(f"DNS records: SOA resolved for {domain}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.debug(f"DNS records: no SOA record for {domain}")
    except dns.exception.Timeout:
        logger.warning(f"DNS records: SOA query timed out for {domain}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"DNS records: SOA error for {domain}: {exc}")

    logger.info(f"DNS records: found {len(found)} FQDNs in DNS records for {domain}")
    return found
