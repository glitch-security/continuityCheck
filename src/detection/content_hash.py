"""
Stable content hashing for change detection.

Strips known-dynamic patterns (CSRF tokens, nonces, timestamps, analytics IDs)
before computing hashes so that trivial re-renders do not generate false-positive
change events.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from typing import Optional

from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Dynamic patterns to strip before hashing
# ---------------------------------------------------------------------------
# Each pattern matches content that changes between page loads without
# reflecting a meaningful content change.
# ---------------------------------------------------------------------------

DYNAMIC_PATTERNS: list[re.Pattern] = [
    # CSRF / nonce tokens in meta tags
    re.compile(r'<meta[^>]+(?:name=["\'](?:csrf-token|_csrf|nonce)["\'])[^>]*>', re.IGNORECASE),
    # Hidden CSRF input fields
    re.compile(r'<input[^>]+(?:name=["\'](?:_token|csrf_token|authenticity_token|__RequestVerificationToken)["\'])[^>]*/?>',
               re.IGNORECASE),
    # Nonce attributes in script/style tags
    re.compile(r'\s+nonce=["\'][^"\']*["\']', re.IGNORECASE),
    # UNIX epoch timestamps (10-13 digit numbers in strings)
    re.compile(r'"(?:timestamp|ts|_t|time|t)"\s*:\s*\d{10,13}'),
    # ISO8601 date/time strings
    re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?'),
    # Session IDs in cookies or URLs
    re.compile(r'(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sessionid)=[A-Za-z0-9%+/=_-]{8,}',
               re.IGNORECASE),
    # Google Analytics / GTM IDs
    re.compile(r'(?:UA-\d+-\d+|GTM-[A-Z0-9]+|G-[A-Z0-9]+)', re.IGNORECASE),
    # Facebook pixel IDs
    re.compile(r'fbq\s*\(\s*["\']init["\']\s*,\s*["\']?\d+["\']?'),
    # Ad script nonce / random IDs in ad iframes
    re.compile(r'googletag\.pubads\(\)\.refresh\(\[.*?\]\)', re.DOTALL),
    # Cache-busting query parameters (e.g. ?v=12345 or ?cb=98765)
    re.compile(r'[?&](?:v|ver|version|cb|cachebust|_)=\d+', re.IGNORECASE),
    # Inline script blocks with only dynamic variable assignments
    re.compile(r'var\s+\w+\s*=\s*\d{10,13}\s*;'),
    # window.__INITIAL_STATE__ or window.__REDUX_STATE__ blobs (large JSON)
    re.compile(r'window\.__(?:INITIAL|REDUX|APP|NEXT_DATA)_[A-Z_]+__\s*=\s*\{.*?\};', re.DOTALL),
]


def _strip_dynamic(html: str) -> str:
    """Apply all :data:`DYNAMIC_PATTERNS` to *html* and return the result."""
    for pattern in DYNAMIC_PATTERNS:
        html = pattern.sub("", html)
    return html


def compute_stable_hash(html_content: str) -> dict:
    """
    Compute three complementary hashes of an HTML page.

    The hashes ignore known-volatile content to reduce false-positive change
    detection while still catching meaningful mutations.

    Parameters
    ----------
    html_content:
        Raw HTML string from an HTTP response.

    Returns
    -------
    dict with keys:
        - ``full_hash``   (str) – SHA-256 of the dynamic-stripped full HTML
        - ``text_hash``   (str) – SHA-256 of all visible text content
        - ``links_hash``  (str) – SHA-256 of all sorted href/src values
    """
    stripped = _strip_dynamic(html_content)

    full_hash = hashlib.sha256(stripped.encode("utf-8", errors="replace")).hexdigest()

    # Text-only hash via BeautifulSoup
    try:
        soup = BeautifulSoup(stripped, "html.parser")
        text = soup.get_text(separator=" ", strip=True)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text).strip()
    except Exception:
        text = re.sub(r"<[^>]+>", " ", stripped)
        text = re.sub(r"\s+", " ", text).strip()
    text_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    # Links hash — collect all href and src attribute values, sort them
    try:
        soup2 = BeautifulSoup(stripped, "html.parser")
        hrefs = [tag.get("href", "") for tag in soup2.find_all(href=True)]
        srcs = [tag.get("src", "") for tag in soup2.find_all(src=True)]
    except Exception:
        href_matches = re.findall(r'href=["\']([^"\']+)["\']', stripped, re.IGNORECASE)
        src_matches = re.findall(r'src=["\']([^"\']+)["\']', stripped, re.IGNORECASE)
        hrefs = href_matches
        srcs = src_matches

    all_links = sorted(filter(None, hrefs + srcs))
    links_str = "\n".join(all_links)
    links_hash = hashlib.sha256(links_str.encode("utf-8", errors="replace")).hexdigest()

    return {
        "full_hash": full_hash,
        "text_hash": text_hash,
        "links_hash": links_hash,
    }


def detect_changes(old_hashes: dict, new_hashes: dict) -> list[str]:
    """
    Compare two sets of page hashes and describe what changed.

    Parameters
    ----------
    old_hashes:
        Hash dict from a previous :func:`compute_stable_hash` call.
    new_hashes:
        Hash dict from the current :func:`compute_stable_hash` call.

    Returns
    -------
    List of human-readable change description strings.  Empty list means
    no significant changes were detected.
    """
    changes: list[str] = []

    _DESCRIPTIONS = {
        "full_hash": "Full page content has changed",
        "text_hash": "Visible page text has changed",
        "links_hash": "Page links or asset references have changed",
    }

    for key, description in _DESCRIPTIONS.items():
        old_val = old_hashes.get(key)
        new_val = new_hashes.get(key)
        if old_val and new_val and old_val != new_val:
            changes.append(description)

    return changes
