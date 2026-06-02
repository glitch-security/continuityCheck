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


def _normalize_techs(techs: list) -> list[dict]:
    """Normalise a mixed list of str or dict tech entries to list[dict]."""
    result: list[dict] = []
    for t in techs or []:
        if isinstance(t, dict):
            result.append({"name": t.get("name", ""), "version": t.get("version", "") or ""})
        elif isinstance(t, str):
            result.append({"name": t, "version": ""})
    return result


def diff_technologies(
    old_techs: list,
    new_techs: list,
) -> dict:
    """
    Compare two technology lists and return added / removed / version-changed entries.

    Accepts both the legacy ``list[str]`` format and the current
    ``list[dict]`` format (``{"name": str, "version": str}``).

    Returns
    -------
    dict with keys:
        - ``added``           (list[dict]) – techs present now but not before
        - ``removed``         (list[dict]) – techs that were present before but are gone
        - ``version_changed`` (list[dict]) – same tech, different version;
                                             each entry: ``{name, old_version, new_version}``
    """
    old_list = _normalize_techs(old_techs)
    new_list = _normalize_techs(new_techs)

    old_map = {t["name"]: t["version"] for t in old_list}
    new_map = {t["name"]: t["version"] for t in new_list}

    old_names = set(old_map)
    new_names = set(new_map)

    added = [{"name": n, "version": new_map[n]} for n in sorted(new_names - old_names)]
    removed = [{"name": n, "version": old_map[n]} for n in sorted(old_names - new_names)]

    version_changed: list[dict] = []
    for name in sorted(old_names & new_names):
        ov, nv = old_map[name], new_map[name]
        if ov and nv and ov != nv:
            version_changed.append({"name": name, "old_version": ov, "new_version": nv})

    return {
        "added": added,
        "removed": removed,
        "version_changed": version_changed,
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
