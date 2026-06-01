"""
JavaScript file analyzer.

Downloads JavaScript files, attempts to retrieve source maps, and extracts
API endpoints, routes, hardcoded URLs, GraphQL operations, and environment
variable references via regex pattern matching.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# fetch/axios/$.ajax/XMLHttpRequest URL arguments
_API_ENDPOINT_PATTERNS: list[re.Pattern] = [
    # fetch("...", ...) or fetch('...')
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch|request))\s*\(\s*[`"']([^`"']+)[`"']""", re.IGNORECASE),
    # axios({ url: "..." })
    re.compile(r"""url\s*:\s*[`"']([^`"']+)[`"']""", re.IGNORECASE),
    # XMLHttpRequest .open("GET", "...")
    re.compile(r"""\.open\s*\(\s*[`"']\w+[`"']\s*,\s*[`"']([^`"']+)[`"']""", re.IGNORECASE),
    # $http.get / $http.post
    re.compile(r"""\$http\.(?:get|post|put|delete|patch)\s*\(\s*[`"']([^`"']+)[`"']""", re.IGNORECASE),
    # HTTP method strings that look like paths
    re.compile(r"""(?:path|endpoint|route|url|api_url|apiUrl|base_url|baseUrl)\s*[=:]\s*[`"']([/][^`"'\s]+)[`"']""", re.IGNORECASE),
]

# React Router / Vue Router / Angular route definitions
_ROUTE_PATTERNS: list[re.Pattern] = [
    # React Router: path="/..."  path={"/..."}
    re.compile(r"""path\s*[=:]\s*[`"'{]?\s*[`"']([/][^`"']+)[`"']""", re.IGNORECASE),
    # Vue Router: { path: '/...' }
    re.compile(r"""path\s*:\s*[`"']([/][^`"']+)[`"']""", re.IGNORECASE),
    # Angular routes: { path: '...' }
    re.compile(r"""[\{,]\s*path\s*:\s*[`"']([^`"']*)[`"']""", re.IGNORECASE),
    # Express-style: router.get('/...') or app.use('/...')
    re.compile(r"""(?:router|app)\.(?:get|post|put|delete|patch|use)\s*\(\s*[`"']([/][^`"']+)[`"']""", re.IGNORECASE),
]

# Hardcoded full URLs  (http:// or https://)
_HARDCODED_URL_PATTERN = re.compile(
    r"""[`"'](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)[`"']"""
)

# GraphQL query / mutation / subscription keywords
_GRAPHQL_PATTERN = re.compile(
    r"""\b(?:query|mutation|subscription)\s+\w+\s*[({]""",
    re.IGNORECASE,
)

# process.env.FOO or import.meta.env.FOO or window.__ENV__.FOO
_ENV_VAR_PATTERNS: list[re.Pattern] = [
    re.compile(r"""process\.env\.([A-Z][A-Z0-9_]*)"""),
    re.compile(r"""import\.meta\.env\.([A-Z][A-Z0-9_]*)"""),
    re.compile(r"""window\.__ENV__\.[`"']?([A-Z][A-Z0-9_]*)[`"']?"""),
    re.compile(r"""process\.env\[[`"']([A-Z][A-Z0-9_]*)[`"']\]"""),
]

# Minimum path-like string to avoid noise
_PATH_LIKE = re.compile(r"""^/[a-zA-Z0-9\-_./?=&%#:@+,]{1,512}$""")


def _looks_like_path(s: str) -> bool:
    return bool(_PATH_LIKE.match(s))


async def analyze_js_file(url: str, domain: str, timeout: int = 10) -> dict:
    """
    Download and analyze a JavaScript file for security-relevant content.

    The function also attempts to download ``url + ".map"`` to obtain the
    original source map (currently logged but not deeply analyzed).

    Parameters
    ----------
    url:
        Absolute URL of the JavaScript file.
    domain:
        The root domain being monitored (used to distinguish internal vs
        external URLs in the results).
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    dict with keys:
        - ``url``            (str)
        - ``endpoints``      (list[str])  – API endpoints and paths
        - ``routes``         (list[str])  – front-end route definitions
        - ``external_urls``  (list[str])  – full URLs pointing to external hosts
        - ``graphql_found``  (bool)
        - ``env_vars``       (list[str])  – referenced environment variable names
        - ``source_map_found`` (bool)
    """
    result: dict = {
        "url": url,
        "endpoints": [],
        "routes": [],
        "external_urls": [],
        "graphql_found": False,
        "env_vars": [],
        "source_map_found": False,
    }

    js_content: Optional[str] = None
    source_map_content: Optional[str] = None

    async with httpx.AsyncClient(
        verify=False,
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
    ) as client:
        # Fetch main JS file
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                js_content = resp.text
        except Exception as exc:
            logger.debug("Failed to fetch JS file %s: %s", url, exc)
            return result

        # Attempt to fetch source map
        try:
            map_resp = await client.get(url + ".map")
            if map_resp.status_code == 200 and map_resp.content:
                source_map_content = map_resp.text
                result["source_map_found"] = True
                logger.info("Source map found for %s", url)
        except Exception:
            pass

    if not js_content:
        return result

    # Combine JS + source map content for analysis
    content = js_content
    if source_map_content:
        content = content + "\n" + source_map_content

    endpoints: set[str] = set()
    routes: set[str] = set()
    external_urls: set[str] = set()
    env_vars: set[str] = set()

    # API endpoints
    for pattern in _API_ENDPOINT_PATTERNS:
        for m in pattern.finditer(content):
            val = m.group(1).strip()
            if _looks_like_path(val):
                endpoints.add(val)
            elif val.startswith("http"):
                external_urls.add(val)

    # Routes
    for pattern in _ROUTE_PATTERNS:
        for m in pattern.finditer(content):
            val = m.group(1).strip()
            if val and (val.startswith("/") or not val.startswith("http")):
                routes.add(val if val.startswith("/") else "/" + val)

    # Hardcoded full URLs
    for m in _HARDCODED_URL_PATTERN.finditer(content):
        val = m.group(1)
        # Only include URLs that are NOT from the target domain
        if domain.lower() not in val.lower():
            external_urls.add(val)

    # GraphQL check
    if _GRAPHQL_PATTERN.search(content):
        result["graphql_found"] = True

    # Environment variables
    for pattern in _ENV_VAR_PATTERNS:
        for m in pattern.finditer(content):
            env_vars.add(m.group(1))

    result["endpoints"] = sorted(endpoints)
    result["routes"] = sorted(routes)
    result["external_urls"] = sorted(external_urls)
    result["env_vars"] = sorted(env_vars)

    return result
