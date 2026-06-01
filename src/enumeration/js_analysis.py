"""JavaScript file analysis for subdomain discovery."""

import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger


def _build_patterns(domain: str) -> list[re.Pattern]:
    escaped = re.escape(domain)
    return [
        re.compile(
            r"https?://([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\." + escaped + r")",
            re.IGNORECASE,
        ),
        re.compile(
            r"""[\"']([a-zA-Z0-9\-]+\.""" + escaped + r""")[\"']""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:api_url|baseURL|endpoint|host|origin)\s*[=:]\s*[\"']([^\"']+)[\"']""",
            re.IGNORECASE,
        ),
    ]


def _extract_from_text(text: str, patterns: list[re.Pattern], domain: str) -> set[str]:
    found: set[str] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            candidate = match.group(1).strip().lower()
            # Remove scheme if present (third pattern may capture full URLs)
            if "://" in candidate:
                parsed = urlparse(candidate)
                candidate = parsed.hostname or ""
            candidate = candidate.rstrip(".")
            if candidate and (candidate == domain or candidate.endswith(f".{domain}")):
                found.add(candidate)
    return found


async def enumerate_js_subdomains(
    domain: str,
    base_url: str,
    timeout: int = 10,
) -> set[str]:
    """Discover subdomains by analysing JavaScript files linked from *base_url*.

    Fetches *base_url*, collects all ``<script src="...">`` URLs, downloads each
    JS file (and its ``.map`` source map if accessible), then applies regex
    patterns to detect subdomain references.

    Args:
        domain: Target domain used for pattern building and filtering.
        base_url: Starting HTML page URL.
        timeout: HTTP request timeout in seconds.

    Returns:
        Deduplicated set of subdomains ending in ``.{domain}`` found in JS files.
    """
    patterns = _build_patterns(domain)
    found: set[str] = set()

    headers = {"User-Agent": "Mozilla/5.0 (compatible; asset-monitor/1.0)"}

    async with httpx.AsyncClient(
        timeout=timeout,
        headers=headers,
        follow_redirects=True,
    ) as client:
        # 1. Fetch base HTML page
        try:
            resp = await client.get(base_url)
            resp.raise_for_status()
            html = resp.text
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.warning(f"JS analysis: failed to fetch base URL {base_url}: {exc}")
            return found

        # 2. Parse <script src="..."> tags
        soup = BeautifulSoup(html, "html.parser")
        js_urls: list[str] = []
        for tag in soup.find_all("script", src=True):
            src: str = tag["src"]
            if src:
                absolute = urljoin(base_url, src)
                js_urls.append(absolute)

        logger.debug(f"JS analysis: found {len(js_urls)} script tags on {base_url}")

        # 3. Download and analyse each JS file (and its .map)
        urls_to_fetch: list[str] = []
        for js_url in js_urls:
            urls_to_fetch.append(js_url)
            urls_to_fetch.append(js_url + ".map")

        for url in urls_to_fetch:
            try:
                js_resp = await client.get(url)
                if js_resp.status_code == 404:
                    continue
                js_resp.raise_for_status()
                js_text = js_resp.text
                matches = _extract_from_text(js_text, patterns, domain)
                if matches:
                    logger.debug(
                        f"JS analysis: {len(matches)} candidate(s) found in {url}"
                    )
                    found.update(matches)
            except (httpx.RequestError, httpx.HTTPStatusError):
                # Most .map fetches will 404 or fail — expected
                continue

    logger.info(f"JS analysis: found {len(found)} subdomains for {domain} via {base_url}")
    return found
