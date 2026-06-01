"""
DOM structural differ.

Parses HTML pages into a structural summary (forms, scripts, iframes, nav
links, input fields, headings) and compares two summaries to produce a list
of labelled change events.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup


def extract_dom_structure(html: str) -> dict:
    """
    Parse *html* and extract structural elements relevant to security monitoring.

    Parameters
    ----------
    html:
        Raw HTML string.

    Returns
    -------
    dict with keys:
        - ``forms``        (list[dict]) – ``{action, method, inputs}``
        - ``scripts``      (list[str])  – external script src values
        - ``nav_links``    (list[str])  – href values found in <nav> elements
        - ``input_fields`` (list[str])  – ``name`` attributes of all <input>s
        - ``iframes``      (list[str])  – src attributes of <iframe> elements
        - ``headings``     (list[str])  – text of h1-h6 elements
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return {
            "forms": [],
            "scripts": [],
            "nav_links": [],
            "input_fields": [],
            "iframes": [],
            "headings": [],
        }

    # Forms
    forms: list[dict] = []
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "GET").upper().strip()
        inputs: list[str] = []
        for inp in form.find_all(["input", "select", "textarea"]):
            name = (inp.get("name") or inp.get("id") or "").strip()
            itype = (inp.get("type") or "text").lower().strip()
            if name:
                inputs.append(f"{name}[{itype}]")
        forms.append({
            "action": action,
            "method": method,
            "inputs": sorted(inputs),
        })

    # External scripts (src attributes only)
    scripts: list[str] = []
    for script in soup.find_all("script"):
        src = (script.get("src") or "").strip()
        if src:
            scripts.append(src)

    # Navigation links (<nav> elements or role="navigation")
    nav_links: list[str] = []
    nav_containers = soup.find_all(["nav"]) + soup.find_all(attrs={"role": "navigation"})
    for nav in nav_containers:
        for a in nav.find_all("a", href=True):
            href = a["href"].strip()
            if href and href not in nav_links:
                nav_links.append(href)

    # All input field names
    input_fields: list[str] = []
    for inp in soup.find_all("input"):
        name = (inp.get("name") or "").strip()
        if name and name not in input_fields:
            input_fields.append(name)

    # Iframes
    iframes: list[str] = []
    for iframe in soup.find_all("iframe"):
        src = (iframe.get("src") or "").strip()
        if src:
            iframes.append(src)

    # Headings
    headings: list[str] = []
    for tag in soup.find_all(re.compile(r"^h[1-6]$")):
        text = tag.get_text(strip=True)
        if text:
            headings.append(text)

    return {
        "forms": forms,
        "scripts": scripts,
        "nav_links": nav_links,
        "input_fields": input_fields,
        "iframes": iframes,
        "headings": headings,
    }


# Map element types to their severity and a human-readable label
_SEVERITY_MAP: dict[str, dict] = {
    "forms":        {"new": "HIGH",   "removed": "MEDIUM", "label": "form"},
    "scripts":      {"new": "MEDIUM", "removed": "LOW",    "label": "external script"},
    "nav_links":    {"new": "LOW",    "removed": "INFO",   "label": "nav link"},
    "input_fields": {"new": "MEDIUM", "removed": "INFO",   "label": "input field"},
    "iframes":      {"new": "HIGH",   "removed": "LOW",    "label": "iframe"},
    "headings":     {"new": "INFO",   "removed": "INFO",   "label": "heading"},
}


def _key_for_form(form: dict) -> str:
    """Build a stable string key for a form dict to enable set-based diffing."""
    inputs_str = ",".join(sorted(form.get("inputs", [])))
    return f"{form.get('action', '')}|{form.get('method', '')}|{inputs_str}"


def diff_dom(old: dict, new: dict) -> list[dict]:
    """
    Compare two DOM structure dicts and produce a list of change records.

    Parameters
    ----------
    old:
        DOM structure from a previous scan (output of :func:`extract_dom_structure`).
    new:
        DOM structure from the current scan.

    Returns
    -------
    List of change dicts, each with keys:
        - ``change_type``  (str) – ``"NEW"`` or ``"REMOVED"``
        - ``element_type`` (str) – e.g. ``"form"``, ``"external script"``
        - ``value``        (str) – the changed element (src URL, form key, etc.)
        - ``severity``     (str) – ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``, ``"INFO"``
    """
    changes: list[dict] = []

    for field, severity_cfg in _SEVERITY_MAP.items():
        label = severity_cfg["label"]
        old_items = old.get(field, [])
        new_items = new.get(field, [])

        if field == "forms":
            old_set = {_key_for_form(f) for f in old_items}
            new_set = {_key_for_form(f) for f in new_items}
        else:
            old_set = set(old_items)
            new_set = set(new_items)

        for item in new_set - old_set:
            changes.append({
                "change_type": "NEW",
                "element_type": label,
                "value": item,
                "severity": severity_cfg["new"],
            })

        for item in old_set - new_set:
            changes.append({
                "change_type": "REMOVED",
                "element_type": label,
                "value": item,
                "severity": severity_cfg["removed"],
            })

    return changes
