"""
Asset inventory tracker.

Compares old and new asset lists to detect newly added, modified, and removed
assets.  Classifies changes by severity with special attention to JavaScript
files from external domains (supply-chain risk).
"""

from __future__ import annotations

import urllib.parse


def _extract_domain(url: str) -> str:
    """Return the netloc component of *url*, or empty string on failure."""
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except Exception:
        return ""


def diff_assets(
    old_assets: list[dict],
    new_assets: list[dict],
) -> dict:
    """
    Compare two asset lists and categorise the differences.

    Each asset dict must contain at minimum:
        - ``url``          (str)  – absolute URL of the asset
        - ``asset_type``   (str)  – e.g. ``"js"``, ``"css"``, ``"image"``
        - ``content_hash`` (str | None)

    Severity rules
    --------------
    - New JS file from an **external domain** → ``CRITICAL`` (supply-chain risk)
    - Changed JS file hash                    → ``HIGH``
    - New JS file from the same domain        → ``MEDIUM``
    - New non-JS asset                        → ``LOW``
    - Removed asset                           → ``INFO``

    Parameters
    ----------
    old_assets:
        Assets recorded in the previous scan.
    new_assets:
        Assets recorded in the current scan.

    Returns
    -------
    dict with keys:
        - ``new_assets``     (list[dict]) – ``{url, asset_type, severity}``
        - ``changed_assets`` (list[dict]) – ``{url, old_hash, new_hash, severity}``
        - ``removed_assets`` (list[dict]) – ``{url, asset_type}``
    """
    old_map: dict[str, dict] = {a["url"]: a for a in old_assets}
    new_map: dict[str, dict] = {a["url"]: a for a in new_assets}

    old_urls = set(old_map.keys())
    new_urls = set(new_map.keys())

    # Determine the "home" domain from the first old or new asset with a
    # recognisable URL.  This is used to distinguish internal vs external assets.
    home_domain: str = ""
    for asset in list(old_assets) + list(new_assets):
        netloc = _extract_domain(asset.get("url", ""))
        if netloc:
            home_domain = netloc
            break

    # ------------------------------------------------------------------
    # New assets
    # ------------------------------------------------------------------
    new_asset_records: list[dict] = []
    for url in sorted(new_urls - old_urls):
        asset = new_map[url]
        atype = (asset.get("asset_type") or "").lower()
        asset_domain = _extract_domain(url)

        if atype == "js":
            if home_domain and asset_domain and asset_domain != home_domain:
                severity = "CRITICAL"
            else:
                severity = "MEDIUM"
        else:
            severity = "LOW"

        new_asset_records.append({
            "url": url,
            "asset_type": asset.get("asset_type"),
            "severity": severity,
        })

    # ------------------------------------------------------------------
    # Changed assets (URL present in both, hash differs)
    # ------------------------------------------------------------------
    changed_records: list[dict] = []
    for url in sorted(old_urls & new_urls):
        old_hash = old_map[url].get("content_hash")
        new_hash = new_map[url].get("content_hash")

        # Skip if either hash is absent (can't compare)
        if old_hash is None or new_hash is None:
            continue
        if old_hash == new_hash:
            continue

        atype = (new_map[url].get("asset_type") or "").lower()
        severity = "HIGH" if atype == "js" else "MEDIUM"

        changed_records.append({
            "url": url,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "severity": severity,
        })

    # ------------------------------------------------------------------
    # Removed assets
    # ------------------------------------------------------------------
    removed_records: list[dict] = [
        {
            "url": url,
            "asset_type": old_map[url].get("asset_type"),
        }
        for url in sorted(old_urls - new_urls)
    ]

    return {
        "new_assets": new_asset_records,
        "changed_assets": changed_records,
        "removed_assets": removed_records,
    }
