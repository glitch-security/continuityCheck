"""DNS bruteforce subdomain enumeration with wildcard detection."""

import asyncio
import secrets
from pathlib import Path

import dns.asyncresolver
import dns.exception
from loguru import logger


async def _resolve_fqdn(
    fqdn: str,
    resolvers: list[str],
    timeout: int,
    resolver_index: int,
) -> bool:
    """Attempt to resolve an FQDN using a rotating resolver list.

    Returns True if the name resolves to at least one address.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [resolvers[resolver_index % len(resolvers)]]
    resolver.lifetime = float(timeout)
    try:
        await resolver.resolve(fqdn, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False
    except dns.exception.Timeout:
        return False
    except Exception:  # noqa: BLE001
        return False


async def bruteforce_dns(
    domain: str,
    wordlist_path: str,
    resolvers: list[str],
    max_concurrent: int = 50,
    timeout: int = 3,
) -> set[str]:
    """Bruteforce DNS subdomains from a wordlist.

    Wildcard DNS is detected first. If a wildcard exists all resolutions still
    proceed, but a warning is emitted and callers should treat results as
    potentially noisy.

    Args:
        domain: Target domain.
        wordlist_path: Path to a newline-delimited wordlist file.
        resolvers: List of DNS resolver IP addresses to rotate through.
        max_concurrent: Maximum number of concurrent resolution tasks.
        timeout: Per-query timeout in seconds.

    Returns:
        Set of FQDNs that resolved successfully.
    """
    if not resolvers:
        resolvers = ["8.8.8.8", "1.1.1.1"]

    # --- Wildcard detection ---
    wildcard_probe = f"{secrets.token_hex(8)}.{domain}"
    wildcard_detected = await _resolve_fqdn(wildcard_probe, resolvers, timeout, 0)
    if wildcard_detected:
        logger.warning(
            f"DNS bruteforce: wildcard DNS detected for {domain} "
            f"(probe {wildcard_probe} resolved). Results may contain false positives."
        )

    # --- Read wordlist ---
    words: list[str] = []
    wordlist = Path(wordlist_path)
    if not wordlist.exists():
        logger.error(f"DNS bruteforce: wordlist not found at {wordlist_path}")
        return set()

    with wordlist.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            words.append(word)

    logger.info(f"DNS bruteforce: loaded {len(words)} words from {wordlist_path}")

    # --- Resolution loop ---
    sem = asyncio.Semaphore(max_concurrent)
    found: set[str] = set()
    attempt_count = 0
    lock = asyncio.Lock()

    async def resolve_word(word: str, index: int) -> None:
        nonlocal attempt_count
        fqdn = f"{word}.{domain}"
        async with sem:
            resolved = await _resolve_fqdn(fqdn, resolvers, timeout, index)
            async with lock:
                attempt_count += 1
                if attempt_count % 100 == 0:
                    logger.debug(
                        f"DNS bruteforce: {attempt_count}/{len(words)} attempts, "
                        f"{len(found)} found so far"
                    )
                if resolved:
                    found.add(fqdn)
                    if wildcard_detected:
                        logger.debug(
                            f"DNS bruteforce: {fqdn} resolved (wildcard active — may be false positive)"
                        )

    tasks = [resolve_word(word, idx) for idx, word in enumerate(words)]
    await asyncio.gather(*tasks)

    if wildcard_detected:
        logger.warning(
            f"DNS bruteforce: completed with wildcard DNS active — "
            f"{len(found)} results for {domain} may include false positives"
        )
    else:
        logger.info(f"DNS bruteforce: found {len(found)} subdomains for {domain}")

    return found
