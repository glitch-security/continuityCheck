"""DNS zone transfer (AXFR) attempt for security assessment."""

import dns.asyncresolver
import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone
from loguru import logger


async def attempt_zone_transfer(
    domain: str,
    timeout: int = 10,
) -> tuple[bool, set[str]]:
    """Attempt AXFR (zone transfer) against each authoritative nameserver.

    Zone transfers that succeed are a security finding: they expose the entire
    DNS zone to any requester.

    Args:
        domain: Target domain.
        timeout: Per-nameserver connection timeout in seconds.

    Returns:
        A 2-tuple of:
        - ``True`` if at least one nameserver allowed the zone transfer.
        - A set of subdomain FQDNs extracted from the transferred zone records.
          Empty if no transfer succeeded.
    """
    import asyncio

    subdomains: set[str] = set()

    # 1. Retrieve NS records to identify authoritative nameservers
    nameservers: list[str] = []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = float(timeout)
        ns_answer = await resolver.resolve(domain, "NS")
        for rdata in ns_answer:
            ns_host = str(rdata.target).rstrip(".")
            nameservers.append(ns_host)
        logger.debug(f"Zone transfer: NS records for {domain}: {nameservers}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        logger.warning(f"Zone transfer: no NS records found for {domain}")
        return False, subdomains
    except dns.exception.Timeout:
        logger.warning(f"Zone transfer: NS query timed out for {domain}")
        return False, subdomains
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Zone transfer: NS lookup error for {domain}: {exc}")
        return False, subdomains

    if not nameservers:
        logger.warning(f"Zone transfer: no nameservers resolved for {domain}")
        return False, subdomains

    transfer_succeeded = False

    for ns in nameservers:
        logger.debug(f"Zone transfer: attempting AXFR of {domain} from {ns}")
        try:
            # dns.query.xfr is a synchronous generator; run in executor to avoid
            # blocking the event loop
            loop = asyncio.get_event_loop()

            def _do_axfr():
                records: set[str] = set()
                try:
                    xfr = dns.query.xfr(ns, domain, timeout=float(timeout))
                    zone = dns.zone.from_xfr(xfr)
                    for name in zone.nodes:
                        fqdn = str(name)
                        if fqdn == "@":
                            continue
                        full = f"{fqdn}.{domain}".lower().rstrip(".")
                        if full == domain or full.endswith(f".{domain}"):
                            records.add(full)
                except dns.exception.FormError:
                    # AXFR refused / malformed response
                    pass
                except Exception:  # noqa: BLE001
                    pass
                return records

            ns_records: set[str] = await loop.run_in_executor(None, _do_axfr)

            if ns_records:
                transfer_succeeded = True
                subdomains.update(ns_records)
                logger.warning(
                    f"Zone transfer: SECURITY FINDING — AXFR succeeded on {ns} for {domain}! "
                    f"Extracted {len(ns_records)} records."
                )
            else:
                logger.info(f"Zone transfer: AXFR refused or empty from {ns} for {domain}")

        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Zone transfer: unexpected error from {ns} for {domain}: {exc}")

    if not transfer_succeeded:
        logger.info(f"Zone transfer: no nameserver allowed AXFR for {domain}")

    return transfer_succeeded, subdomains
