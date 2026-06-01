"""
Subdomain takeover detector.

Checks CNAME records and HTTP response bodies against known patterns for
services that are vulnerable to subdomain takeover.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Takeover signature database
# ---------------------------------------------------------------------------
# Each entry describes a service that may be vulnerable when:
#   - The subdomain's CNAME points to a known dangling hostname, AND/OR
#   - The HTTP response body contains known unclaimed-resource messages
# ---------------------------------------------------------------------------

TAKEOVER_SIGNATURES: list[dict] = [
    {
        "service": "GitHub Pages",
        "cname_contains": ["github.io"],
        "body_contains": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "status_codes": [404],
    },
    {
        "service": "AWS S3",
        "cname_contains": ["s3.amazonaws.com", "s3-website"],
        "body_contains": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "<Code>NoSuchBucket</Code>",
        ],
        "status_codes": [404],
    },
    {
        "service": "Heroku",
        "cname_contains": ["herokudns.com", "herokuapp.com"],
        "body_contains": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "status_codes": [404],
    },
    {
        "service": "Fastly",
        "cname_contains": ["fastly.net"],
        "body_contains": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "status_codes": [404, 500],
    },
    {
        "service": "Azure",
        "cname_contains": [
            "azurewebsites.net",
            "cloudapp.net",
            "trafficmanager.net",
            "blob.core.windows.net",
        ],
        "body_contains": [
            "404 Web Site not found",
            "Microsoft Azure App Service - Error 404",
        ],
        "status_codes": [404],
    },
    {
        "service": "Bitbucket",
        "cname_contains": ["bitbucket.io"],
        "body_contains": [
            "Repository not found",
        ],
        "status_codes": [404],
    },
    {
        "service": "Shopify",
        "cname_contains": ["myshopify.com", "shops.myshopify.com"],
        "body_contains": [
            "Sorry, this shop is currently unavailable.",
            "Only one step left!",
        ],
        "status_codes": [404],
    },
    {
        "service": "Tumblr",
        "cname_contains": ["tumblr.com"],
        "body_contains": [
            "There's nothing here.",
            "Whatever you were looking for doesn't currently exist",
        ],
        "status_codes": [404],
    },
    {
        "service": "Ghost",
        "cname_contains": ["ghost.io"],
        "body_contains": [
            "The thing you were looking for is no longer here",
        ],
        "status_codes": [404],
    },
    {
        "service": "Helpscout",
        "cname_contains": ["helpscoutdocs.com"],
        "body_contains": [
            "No settings were found for this company:",
        ],
        "status_codes": [404],
    },
    {
        "service": "Zendesk",
        "cname_contains": ["zendesk.com"],
        "body_contains": [
            "Help Center Closed",
            "Oops, this help center no longer exists",
        ],
        "status_codes": [404],
    },
    {
        "service": "Unbounce",
        "cname_contains": ["unbouncepages.com"],
        "body_contains": [
            "The requested URL was not found on this server.",
        ],
        "status_codes": [404, 410],
    },
    {
        "service": "Surge.sh",
        "cname_contains": ["surge.sh"],
        "body_contains": [
            "project not found",
            "doesn't exist",
        ],
        "status_codes": [404],
    },
    {
        "service": "Netlify",
        "cname_contains": ["netlify.app", "netlify.com"],
        "body_contains": [
            "Not Found - Request ID:",
            "netlify.com/404",
        ],
        "status_codes": [404],
    },
    {
        "service": "Vercel",
        "cname_contains": ["vercel.app", "now.sh"],
        "body_contains": [
            "The deployment could not be found on Vercel",
            "This deployment has been disabled",
        ],
        "status_codes": [404],
    },
]


def _matches_cname(cname: str, patterns: list[str]) -> bool:
    """Return True when *cname* contains any of the given *patterns*."""
    lower = cname.lower()
    return any(p.lower() in lower for p in patterns)


def _matches_body(body: str, patterns: list[str]) -> bool:
    """Return True when *body* contains any of the given *patterns* (case-insensitive)."""
    lower = body.lower()
    return any(p.lower() in lower for p in patterns)


async def check_takeover(
    fqdn: str,
    cname: Optional[str],
    http_result: dict,
) -> Optional[dict]:
    """
    Check whether a subdomain is vulnerable to takeover.

    The check first looks for a CNAME match (HIGH confidence), then for a
    body-only match without a corroborating CNAME (MEDIUM confidence).

    Parameters
    ----------
    fqdn:
        The fully-qualified domain name under investigation.
    cname:
        The CNAME target returned by DNS resolution, or *None*.
    http_result:
        The dict returned by :func:`~verification.http_prober.probe_subdomain`.

    Returns
    -------
    dict with keys ``{fqdn, service, confidence, evidence}`` when a potential
    takeover is detected, or *None* when the host appears safe.
    """
    status_code: int = http_result.get("status_code", 0)
    # Try to get response body from http_result (populated by caller if needed)
    body: str = http_result.get("body", "")

    for sig in TAKEOVER_SIGNATURES:
        service: str = sig["service"]
        cname_patterns: list[str] = sig["cname_contains"]
        body_patterns: list[str] = sig["body_contains"]
        vuln_status_codes: list[int] = sig["status_codes"]

        cname_match = cname and _matches_cname(cname, cname_patterns)
        body_match = body and _matches_body(body, body_patterns)
        status_match = status_code in vuln_status_codes

        if cname_match and (body_match or status_match):
            evidence_parts: list[str] = [f"CNAME points to {cname}"]
            if body_match:
                # Identify which body string was found
                for bp in body_patterns:
                    if bp.lower() in body.lower():
                        evidence_parts.append(f'body contains "{bp}"')
                        break
            if status_match:
                evidence_parts.append(f"HTTP {status_code}")

            return {
                "fqdn": fqdn,
                "service": service,
                "confidence": "HIGH",
                "evidence": "; ".join(evidence_parts),
            }

        if cname_match and not body:
            # We have a matching CNAME but no body to verify — report as MEDIUM
            return {
                "fqdn": fqdn,
                "service": service,
                "confidence": "MEDIUM",
                "evidence": f"CNAME points to {cname} (no body verification possible)",
            }

        if body_match and status_match and not cname:
            # No CNAME evidence, but body + status code both match
            for bp in body_patterns:
                if bp.lower() in body.lower():
                    found_bp = bp
                    break
            else:
                found_bp = body_patterns[0]

            return {
                "fqdn": fqdn,
                "service": service,
                "confidence": "MEDIUM",
                "evidence": f'body contains "{found_bp}"; HTTP {status_code}',
            }

    return None
