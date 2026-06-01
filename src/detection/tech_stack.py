"""
Technology stack and security header differ.

Detects additions and removals in the detected technology list and monitors
changes to security-relevant HTTP response headers.
"""

from __future__ import annotations

# Security headers that are specifically monitored
_SECURITY_HEADERS: set[str] = {
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-xss-protection",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "feature-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
}


def diff_technologies(
    old_techs: list[str],
    new_techs: list[str],
) -> dict:
    """
    Compare two technology lists and return added / removed entries.

    Parameters
    ----------
    old_techs:
        Technologies detected in a previous scan.
    new_techs:
        Technologies detected in the current scan.

    Returns
    -------
    dict with keys:
        - ``added``   (list[str])
        - ``removed`` (list[str])
    """
    old_set = set(old_techs or [])
    new_set = set(new_techs or [])
    return {
        "added": sorted(new_set - old_set),
        "removed": sorted(old_set - new_set),
    }


def diff_headers(
    old_headers: dict,
    new_headers: dict,
) -> dict:
    """
    Compare security-relevant HTTP headers between two scans.

    Only headers in the :data:`_SECURITY_HEADERS` set are considered.
    All header names are normalised to lowercase.

    Parameters
    ----------
    old_headers:
        ``{header_name: value}`` dict from a previous scan.
    new_headers:
        ``{header_name: value}`` dict from the current scan.

    Returns
    -------
    dict with keys:
        - ``added``   (dict)  – headers present now but not before
        - ``removed`` (dict)  – headers that were present before but are gone
        - ``changed`` (dict)  – headers present in both but with different values;
                                value is ``{old: str, new: str}``
    """
    old_sec = {
        k.lower(): v
        for k, v in (old_headers or {}).items()
        if k.lower() in _SECURITY_HEADERS
    }
    new_sec = {
        k.lower(): v
        for k, v in (new_headers or {}).items()
        if k.lower() in _SECURITY_HEADERS
    }

    old_keys = set(old_sec.keys())
    new_keys = set(new_sec.keys())

    added: dict = {k: new_sec[k] for k in (new_keys - old_keys)}
    removed: dict = {k: old_sec[k] for k in (old_keys - new_keys)}
    changed: dict = {}

    for key in old_keys & new_keys:
        if old_sec[key] != new_sec[key]:
            changed[key] = {"old": old_sec[key], "new": new_sec[key]}

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
    }
