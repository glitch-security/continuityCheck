"""
JSON-backed persistent store for website monitoring targets.

Stores each website URL alongside per-URL technique flags in
``data/websites.json``.  Automatically migrates from the legacy
``data/websites.txt`` plain-text format on first access.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_STORE_PATH = "data/websites.json"
_LEGACY_PATH = "data/websites.txt"

DEFAULT_TECHNIQUES: dict = {
    "crawl": True,
    "js_analysis": True,
    "security_files": True,
    "screenshot": False,
}


def read_websites() -> list[dict]:
    """Return all monitored websites as a list of dicts.

    Each dict has:
      - ``url``        (str)
      - ``techniques`` (dict) — per-URL technique flags

    Migrates from legacy ``websites.txt`` if ``websites.json`` does not exist.
    """
    if not os.path.isfile(_STORE_PATH):
        _migrate_from_txt()

    if not os.path.isfile(_STORE_PATH):
        return []

    try:
        with open(_STORE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            logger.warning("websites.json has unexpected format — resetting")
            return []
        # Ensure every entry has a complete techniques dict
        for entry in data:
            if "techniques" not in entry or not isinstance(entry["techniques"], dict):
                entry["techniques"] = dict(DEFAULT_TECHNIQUES)
            else:
                for k, v in DEFAULT_TECHNIQUES.items():
                    entry["techniques"].setdefault(k, v)
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read websites.json: %s", exc)
        return []


def write_websites(websites: list[dict]) -> None:
    """Persist the website list to ``data/websites.json``."""
    os.makedirs("data", exist_ok=True)
    try:
        with open(_STORE_PATH, "w", encoding="utf-8") as fh:
            json.dump(websites, fh, indent=2)
    except OSError as exc:
        logger.error("Failed to write websites.json: %s", exc)


def add_website(url: str, techniques: Optional[dict] = None) -> dict:
    """Add a website to the store (no-op if already present).

    Returns the stored entry dict.
    """
    websites = read_websites()
    for entry in websites:
        if entry.get("url") == url:
            # Already present — update techniques if provided
            if techniques:
                entry["techniques"].update(techniques)
                write_websites(websites)
            return entry

    techs = dict(DEFAULT_TECHNIQUES)
    if techniques:
        techs.update(techniques)
    entry = {"url": url, "techniques": techs}
    websites.append(entry)
    write_websites(websites)
    return entry


def remove_website(url: str) -> bool:
    """Remove a website by URL. Returns True if the entry was found and removed."""
    websites = read_websites()
    filtered = [w for w in websites if w.get("url") != url]
    if len(filtered) == len(websites):
        return False
    write_websites(filtered)
    return True


def update_techniques(url: str, techniques: dict) -> bool:
    """Update the technique flags for an existing website. Returns True on success."""
    websites = read_websites()
    for entry in websites:
        if entry.get("url") == url:
            entry["techniques"].update(techniques)
            write_websites(websites)
            return True
    return False


# ---------------------------------------------------------------------------
# Migration helper
# ---------------------------------------------------------------------------

def _migrate_from_txt() -> None:
    """One-shot migration: import URLs from websites.txt into websites.json."""
    if not os.path.isfile(_LEGACY_PATH):
        return
    urls: list[str] = []
    try:
        with open(_LEGACY_PATH, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    except OSError as exc:
        logger.warning("Could not read legacy websites.txt: %s", exc)
        return

    if not urls:
        return

    websites = [{"url": u, "techniques": dict(DEFAULT_TECHNIQUES)} for u in urls]
    write_websites(websites)
    logger.info(
        "Migrated %d website(s) from websites.txt → websites.json", len(urls)
    )
