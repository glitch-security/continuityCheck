"""
Endpoint inventory differ.

Compares two lists of URL paths (or full URLs) to identify newly added or
removed endpoints, and classifies added endpoints by security sensitivity.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Sensitivity classification patterns
# ---------------------------------------------------------------------------
# Ordered from most specific (CRITICAL / HIGH) to least specific.
# The first matching pattern wins.
# ---------------------------------------------------------------------------

_HIGH_PATTERNS: list[re.Pattern] = [
    re.compile(r"^/admin", re.IGNORECASE),
    re.compile(r"^/login", re.IGNORECASE),
    re.compile(r"^/auth", re.IGNORECASE),
    re.compile(r"^/oauth", re.IGNORECASE),
    re.compile(r"^/sso", re.IGNORECASE),
    re.compile(r"^/api(?:/|$)", re.IGNORECASE),
    re.compile(r"^/upload", re.IGNORECASE),
    re.compile(r"^/export", re.IGNORECASE),
    re.compile(r"^/backup", re.IGNORECASE),
    re.compile(r"^/\.env", re.IGNORECASE),
    re.compile(r"^/\.git", re.IGNORECASE),
    re.compile(r"^/config", re.IGNORECASE),
    re.compile(r"^/console", re.IGNORECASE),
    re.compile(r"^/panel", re.IGNORECASE),
    re.compile(r"^/manager", re.IGNORECASE),
    re.compile(r"^/phpmyadmin", re.IGNORECASE),
    re.compile(r"^/webmin", re.IGNORECASE),
    re.compile(r"^/cpanel", re.IGNORECASE),
    re.compile(r"^/reset[-_]?password", re.IGNORECASE),
    re.compile(r"^/forgot[-_]?password", re.IGNORECASE),
    re.compile(r"^/register", re.IGNORECASE),
    re.compile(r"^/signup", re.IGNORECASE),
]

_MEDIUM_PATTERNS: list[re.Pattern] = [
    # /api/v1/... style versioned API paths
    re.compile(r"^/api/v\d+/", re.IGNORECASE),
    # GraphQL endpoints
    re.compile(r"^/graphql", re.IGNORECASE),
    re.compile(r"^/gql", re.IGNORECASE),
    # Swagger / OpenAPI
    re.compile(r"^/swagger", re.IGNORECASE),
    re.compile(r"^/openapi", re.IGNORECASE),
    re.compile(r"^/api-docs", re.IGNORECASE),
    # Profile / account
    re.compile(r"^/profile", re.IGNORECASE),
    re.compile(r"^/account", re.IGNORECASE),
    # File downloads
    re.compile(r"^/download", re.IGNORECASE),
    re.compile(r"^/files", re.IGNORECASE),
]


def _classify_endpoint(path: str) -> str:
    """Return the sensitivity classification for a URL *path*."""
    for pattern in _HIGH_PATTERNS:
        if pattern.search(path):
            return "HIGH"
    for pattern in _MEDIUM_PATTERNS:
        if pattern.search(path):
            return "MEDIUM"
    return "LOW"


def diff_endpoints(
    old_endpoints: list[str],
    new_endpoints: list[str],
) -> dict:
    """
    Identify added and removed URL paths between two endpoint inventories.

    Parameters
    ----------
    old_endpoints:
        Endpoint paths from the previous scan.
    new_endpoints:
        Endpoint paths from the current scan.

    Returns
    -------
    dict with keys:
        - ``added``   (list[dict]) – each dict: ``{path, sensitivity}``
        - ``removed`` (list[str])  – paths no longer present
    """
    old_set = set(old_endpoints)
    new_set = set(new_endpoints)

    added_raw = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)

    added: list[dict] = [
        {"path": p, "sensitivity": _classify_endpoint(p)}
        for p in added_raw
    ]

    return {
        "added": added,
        "removed": removed,
    }
