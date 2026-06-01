"""
Security file checker.

Probes a list of well-known sensitive paths on a web server and classifies
findings by severity.  Special handling is applied to robots.txt (Disallow
extraction), Swagger/OpenAPI specs, exposed Git repositories, and .env files.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

SECURITY_PATHS: list[str] = [
    "/robots.txt",
    "/.well-known/security.txt",
    "/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/graphql",
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/package.json",
    "/composer.json",
    "/wp-config.php.bak",
    "/backup.sql",
]

# Maximum number of bytes to store as a content preview
_PREVIEW_BYTES = 512

# Paths that indicate CRITICAL severity when accessible
_CRITICAL_PATHS: set[str] = {
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/wp-config.php.bak",
    "/backup.sql",
}

# Paths that indicate HIGH severity
_HIGH_PATHS: set[str] = {
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v1/api-docs",
    "/v2/api-docs",
    "/graphql",
    "/config.json",
    "/composer.json",
}

# Paths that indicate MEDIUM severity
_MEDIUM_PATHS: set[str] = {
    "/package.json",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
}


def _classify_severity(path: str) -> str:
    """Return the severity label for a given security file path."""
    if path in _CRITICAL_PATHS:
        return "CRITICAL"
    if path in _HIGH_PATHS:
        return "HIGH"
    if path in _MEDIUM_PATHS:
        return "MEDIUM"
    return "INFO"


def _parse_disallow(robots_body: str) -> list[str]:
    """Extract Disallow paths from robots.txt content."""
    disallow_paths: list[str] = []
    for line in robots_body.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("disallow:"):
            path = stripped[len("disallow:"):].strip()
            # Strip inline comments
            path = path.split("#", 1)[0].strip()
            if path and path != "/":
                disallow_paths.append(path)
    return disallow_paths


async def check_security_files(
    base_url: str,
    timeout: int = 10,
) -> dict:
    """
    Check for the presence of sensitive files and directories.

    Parameters
    ----------
    base_url:
        Scheme + host root URL (e.g. ``https://example.com``).  A trailing
        slash is acceptable and will be stripped.
    timeout:
        Per-request HTTP timeout in seconds.

    Returns
    -------
    dict with keys:
        - ``found``           (list[dict]) – accessible paths with metadata
        - ``disallow_paths``  (list[str])  – paths from robots.txt Disallow

    Each item in ``found`` has:
        - ``path``            (str)
        - ``status_code``     (int)
        - ``severity``        (str)   – CRITICAL / HIGH / MEDIUM / INFO
        - ``content_preview`` (str)   – first 512 chars of response body
    """
    base = base_url.rstrip("/")
    found: list[dict] = []
    disallow_paths: list[str] = []

    async with httpx.AsyncClient(
        verify=False,
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
    ) as client:
        for path in SECURITY_PATHS:
            url = base + path
            try:
                response = await client.get(url)
            except Exception as exc:
                logger.debug("Security file check failed for %s: %s", url, exc)
                continue

            # Only report paths that returned a successful or auth-gated response
            if response.status_code not in (200, 401, 403):
                continue

            # For 401/403, still flag the existence of the resource
            body_text = response.text
            preview = body_text[:_PREVIEW_BYTES]
            severity = _classify_severity(path)

            record: dict = {
                "path": path,
                "status_code": response.status_code,
                "severity": severity,
                "content_preview": preview,
            }

            # Special: parse robots.txt Disallow entries
            if path == "/robots.txt" and response.status_code == 200:
                disallow_paths = _parse_disallow(body_text)
                record["disallow_count"] = len(disallow_paths)

            # Special: flag Swagger/OpenAPI as HIGH (already set above) and
            # verify the content actually looks like an API spec
            if path in ("/swagger.json", "/openapi.json", "/api-docs", "/v1/api-docs", "/v2/api-docs"):
                if response.status_code == 200:
                    # Confirm it really looks like an API spec
                    if '"swagger"' not in body_text.lower() and '"openapi"' not in body_text.lower():
                        severity = "MEDIUM"
                        record["severity"] = severity
                        record["note"] = "Path exists but content may not be an API spec"

            # Special: .git/HEAD — bump to CRITICAL and flag clearly
            if path == "/.git/HEAD" and response.status_code == 200:
                if "ref:" in body_text or body_text.strip():
                    record["note"] = "Git repository exposed — source code may be downloadable"

            # Special: .env files — look for key=value pairs
            if path.startswith("/.env") and response.status_code == 200:
                env_key_count = len(re.findall(r"^[A-Z_][A-Z0-9_]*\s*=", body_text, re.MULTILINE))
                if env_key_count:
                    record["note"] = f"Environment file contains ~{env_key_count} key=value entries"

            found.append(record)

    return {
        "found": found,
        "disallow_paths": disallow_paths,
    }
