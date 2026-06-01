"""
BFS web crawler for asset and endpoint discovery.

Crawls a web application using breadth-first search, extracting links,
scripts, forms, and external resources up to a configurable depth.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import urllib.parse
from typing import Optional

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

_DEFAULT_UA = (
    "Mozilla/5.0 (compatible; AssetMonitor/1.0; +https://github.com/asset-monitor)"
)


class BFSCrawler:
    """
    Breadth-first web crawler.

    Parameters
    ----------
    base_url:
        The starting URL for the crawl (e.g. ``https://example.com``).
    max_depth:
        Maximum link-following depth (default 3).
    max_pages:
        Upper bound on the total number of pages to crawl (default 500).
    timeout:
        Per-request timeout in seconds (default 10).
    respect_robots:
        When ``True``, parse ``/robots.txt`` and skip disallowed paths.
    user_agent:
        Override the default ``User-Agent`` header.
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 500,
        timeout: int = 10,
        respect_robots: bool = False,
        user_agent: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.respect_robots = respect_robots
        self.user_agent = user_agent or _DEFAULT_UA

        parsed = urllib.parse.urlparse(self.base_url)
        self.base_netloc: str = parsed.netloc

        self._visited: set[str] = set()
        self._disallowed_paths: list[str] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def crawl(self) -> dict:
        """
        Execute the BFS crawl starting from :attr:`base_url`.

        Returns
        -------
        dict with keys:
            - ``pages``          (list[dict]) – one record per crawled page
            - ``assets``         (list[dict]) – deduplicated asset records
            - ``endpoints``      (list[str])  – unique URL paths discovered
            - ``forms``          (list[dict]) – all forms found across pages
            - ``external_links`` (list[str])  – links pointing outside the base domain
        """
        if self.respect_robots:
            await self._load_robots()

        pages: list[dict] = []
        assets_map: dict[str, dict] = {}  # url → asset dict
        all_endpoints: set[str] = set()
        all_forms: list[dict] = []
        external_links: set[str] = set()

        # BFS queue entries: (url, depth)
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((self.base_url, 0))
        self._visited.add(self.base_url)

        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": self.user_agent},
        ) as client:
            while not queue.empty() and len(pages) < self.max_pages:
                url, depth = await queue.get()

                page_data = await self._fetch_page(client, url)
                if page_data is None:
                    continue

                pages.append(page_data)
                all_endpoints.add(urllib.parse.urlparse(url).path or "/")

                # Collect forms
                for form in page_data.get("forms", []):
                    all_forms.append(form)

                # Collect assets (scripts, stylesheets, images)
                for asset in page_data.get("_raw_assets", []):
                    asset_url = asset["url"]
                    if asset_url not in assets_map:
                        assets_map[asset_url] = asset

                # Enqueue discovered links
                if depth < self.max_depth:
                    for link in page_data.get("links", []):
                        if not link:
                            continue
                        normalized = self._normalize_url(url, link)
                        if normalized is None:
                            continue
                        parsed_link = urllib.parse.urlparse(normalized)
                        if parsed_link.netloc == self.base_netloc:
                            if normalized not in self._visited:
                                if not self._is_disallowed(parsed_link.path):
                                    self._visited.add(normalized)
                                    await queue.put((normalized, depth + 1))
                        else:
                            external_links.add(normalized)

        # Clean up internal raw data before returning
        final_pages: list[dict] = []
        for p in pages:
            clean = {k: v for k, v in p.items() if not k.startswith("_")}
            final_pages.append(clean)

        return {
            "pages": final_pages,
            "assets": list(assets_map.values()),
            "endpoints": sorted(all_endpoints),
            "forms": all_forms,
            "external_links": sorted(external_links),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _fetch_page(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> Optional[dict]:
        """Fetch *url* and extract structural data. Returns None on error."""
        try:
            response = await client.get(url)
        except Exception as exc:
            logger.debug("Crawl fetch error for %s: %s", url, exc)
            return None

        content_type = response.headers.get("content-type", "")
        body_bytes = response.content
        body_text = body_bytes.decode("utf-8", errors="replace")
        body_hash = hashlib.sha256(body_bytes).hexdigest()

        links: list[str] = []
        scripts: list[str] = []
        forms: list[dict] = []
        raw_assets: list[dict] = []
        title = ""

        if "html" in content_type:
            try:
                soup = BeautifulSoup(body_text, "html.parser")
            except Exception:
                soup = None

            if soup:
                title_tag = soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else ""

                # Links
                for tag in soup.find_all(["a", "link", "area"]):
                    href = tag.get("href", "")
                    if href:
                        links.append(href)
                    # Stylesheets as assets
                    rel = tag.get("rel", [])
                    if isinstance(rel, list):
                        rel = " ".join(rel)
                    if "stylesheet" in rel:
                        normalized = self._normalize_url(url, href)
                        if normalized:
                            raw_assets.append({"url": normalized, "asset_type": "css", "content_hash": None})

                # Script src values
                for tag in soup.find_all("script"):
                    src = tag.get("src", "")
                    if src:
                        scripts.append(src)
                        normalized = self._normalize_url(url, src)
                        if normalized:
                            raw_assets.append({"url": normalized, "asset_type": "js", "content_hash": None})

                # Images
                for tag in soup.find_all("img"):
                    src = tag.get("src", "")
                    if src:
                        normalized = self._normalize_url(url, src)
                        if normalized:
                            raw_assets.append({"url": normalized, "asset_type": "image", "content_hash": None})

                # Forms
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action", "")
                    method = (form_tag.get("method", "GET") or "GET").upper()
                    inputs: list[dict] = []
                    for inp in form_tag.find_all(["input", "select", "textarea"]):
                        inputs.append({
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                            "required": inp.has_attr("required"),
                        })
                    forms.append({
                        "action": action,
                        "method": method,
                        "page_url": url,
                        "inputs": inputs,
                    })

                # Also collect all href / src / action attributes for endpoints
                for tag in soup.find_all(True):
                    for attr in ("src", "action", "data-url", "data-src"):
                        val = tag.get(attr, "")
                        if val and val not in links:
                            links.append(val)

        return {
            "url": url,
            "status_code": response.status_code,
            "content_type": content_type,
            "response_size": len(body_bytes),
            "body_hash": body_hash,
            "title": title,
            "headers": dict(response.headers),
            "links": links,
            "scripts": scripts,
            "forms": forms,
            "_raw_assets": raw_assets,
        }

    def _normalize_url(self, base: str, href: str) -> Optional[str]:
        """Resolve *href* relative to *base* and return absolute URL or None."""
        if not href:
            return None
        href = href.strip()
        # Skip anchors, mailto, tel, javascript
        if href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            return None
        try:
            absolute = urllib.parse.urljoin(base, href)
            # Strip fragment
            parsed = urllib.parse.urlparse(absolute)
            clean = parsed._replace(fragment="")
            return urllib.parse.urlunparse(clean)
        except Exception:
            return None

    def _is_disallowed(self, path: str) -> bool:
        """Return True when *path* matches a Disallow entry from robots.txt."""
        for disallowed in self._disallowed_paths:
            if path.startswith(disallowed):
                return True
        return False

    async def _load_robots(self) -> None:
        """Fetch and parse robots.txt, populating :attr:`_disallowed_paths`."""
        robots_url = f"{self.base_url}/robots.txt"
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(self.timeout),
            ) as client:
                resp = await client.get(robots_url)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                self._disallowed_paths.append(path)
        except Exception as exc:
            logger.debug("Failed to load robots.txt from %s: %s", robots_url, exc)
