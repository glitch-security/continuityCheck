"""
Subdomain classifier.

Classifies a subdomain into a functional category based on its hostname
parts, page title, and detected technologies.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Classification rules
# ---------------------------------------------------------------------------
# Maps a class name to a list of keywords to search for in the FQDN parts and
# the page title (case-insensitive substring / word-boundary match).
# ---------------------------------------------------------------------------

CLASSIFICATION_RULES: dict[str, list[str]] = {
    "ADMIN": [
        "admin",
        "panel",
        "manager",
        "dashboard",
        "control",
        "cpanel",
        "phpmyadmin",
        "webmin",
    ],
    "API": [
        "api",
        "gateway",
        "service",
        "microservice",
        "rest",
        "graphql",
        "gql",
        "endpoint",
    ],
    "AUTH": [
        "auth",
        "login",
        "sso",
        "identity",
        "oauth",
        "saml",
        "idp",
        "ldap",
        "okta",
        "keycloak",
    ],
    "DEV": [
        "dev",
        "development",
        "test",
        "testing",
        "staging",
        "uat",
        "qa",
        "sandbox",
        "beta",
        "demo",
    ],
    "MAIL": [
        "mail",
        "smtp",
        "imap",
        "pop3",
        "webmail",
        "roundcube",
        "mx",
        "postfix",
    ],
    "MONITORING": [
        "grafana",
        "kibana",
        "prometheus",
        "zabbix",
        "nagios",
        "datadog",
        "splunk",
        "elk",
    ],
    "STORAGE": [
        "s3",
        "storage",
        "backup",
        "files",
        "cdn",
        "assets",
        "media",
        "static",
        "uploads",
    ],
    "VPN": [
        "vpn",
        "remote",
        "access",
        "openvpn",
        "wireguard",
        "tunnel",
    ],
}

DEFAULT_CLASS = "DEFAULT"


def _tokenize(text: str) -> list[str]:
    """Split *text* on non-alphanumeric characters and return lowercase tokens."""
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def classify_subdomain(
    fqdn: str,
    page_title: str = "",
    technologies: list[str] | None = None,
) -> str:
    """
    Classify a subdomain into a functional category.

    The function extracts tokens from the FQDN labels (everything left of the
    registered domain) and from the page title, then checks each token against
    the keyword lists in :data:`CLASSIFICATION_RULES`.

    The first matching rule (in definition order) wins.  If no rule matches,
    :data:`DEFAULT_CLASS` (``"DEFAULT"``) is returned.

    Parameters
    ----------
    fqdn:
        Fully-qualified domain name (e.g. ``staging-api.example.com``).
    page_title:
        Optional page title string from HTTP probing.
    technologies:
        Optional list of detected technology names (reserved for future
        technology-based classification rules).

    Returns
    -------
    A classification label such as ``"API"``, ``"DEV"``, or ``"DEFAULT"``.
    """
    if technologies is None:
        technologies = []

    # Build a combined token set from the FQDN labels and page title
    fqdn_tokens = set(_tokenize(fqdn))
    title_tokens = set(_tokenize(page_title))
    all_tokens = fqdn_tokens | title_tokens

    for class_name, keywords in CLASSIFICATION_RULES.items():
        for keyword in keywords:
            # Keyword itself may contain multiple tokens (e.g. "phpmyadmin")
            kw_tokens = set(_tokenize(keyword))
            if kw_tokens & all_tokens:
                return class_name

    return DEFAULT_CLASS
