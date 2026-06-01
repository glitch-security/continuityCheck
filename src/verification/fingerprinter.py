"""
Technology fingerprinter.

Detects web technologies from HTTP response headers, body content, cookies,
and meta tags.  Also retrieves favicon hashes and TLS certificate fingerprints.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import socket
import ssl
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Technology signature database
# ---------------------------------------------------------------------------
# Each rule has:
#   type:        "header" | "body" | "cookie" | "meta"
#   pattern:     regex string (case-insensitive)
#   header_name: (only for type="header") the HTTP header to inspect
# ---------------------------------------------------------------------------

TECH_SIGNATURES: dict[str, list[dict]] = {
    "WordPress": [
        {"type": "body", "pattern": r"/wp-content/"},
        {"type": "body", "pattern": r"/wp-includes/"},
        {"type": "body", "pattern": r"wp-json"},
        {"type": "header", "header_name": "x-powered-by", "pattern": r"WordPress"},
        {"type": "meta", "pattern": r'name=["\']generator["\'][^>]*WordPress'},
        {"type": "cookie", "pattern": r"wordpress_"},
    ],
    "Drupal": [
        {"type": "body", "pattern": r"/sites/default/files/"},
        {"type": "body", "pattern": r'Drupal\.settings'},
        {"type": "header", "header_name": "x-generator", "pattern": r"Drupal"},
        {"type": "meta", "pattern": r'name=["\']generator["\'][^>]*Drupal'},
        {"type": "cookie", "pattern": r"SESS[a-f0-9]{32}"},
    ],
    "Joomla": [
        {"type": "body", "pattern": r"/media/jui/"},
        {"type": "body", "pattern": r"/media/system/js/"},
        {"type": "body", "pattern": r"Joomla!"},
        {"type": "meta", "pattern": r'name=["\']generator["\'][^>]*Joomla'},
        {"type": "cookie", "pattern": r"[a-f0-9]{32}=\w+; path=/"},
    ],
    "Laravel": [
        {"type": "cookie", "pattern": r"laravel_session"},
        {"type": "header", "header_name": "set-cookie", "pattern": r"laravel_session"},
        {"type": "body", "pattern": r"laravel"},
        {"type": "header", "header_name": "x-powered-by", "pattern": r"PHP"},
    ],
    "Django": [
        {"type": "cookie", "pattern": r"csrftoken"},
        {"type": "header", "header_name": "set-cookie", "pattern": r"csrftoken"},
        {"type": "body", "pattern": r"csrfmiddlewaretoken"},
        {"type": "header", "header_name": "x-frame-options", "pattern": r"SAMEORIGIN"},
    ],
    "Rails": [
        {"type": "header", "header_name": "x-powered-by", "pattern": r"Phusion Passenger"},
        {"type": "header", "header_name": "x-runtime", "pattern": r"\d+\.\d+"},
        {"type": "cookie", "pattern": r"_session_id"},
        {"type": "header", "header_name": "set-cookie", "pattern": r"_\w+_session"},
    ],
    "ASP.NET": [
        {"type": "header", "header_name": "x-powered-by", "pattern": r"ASP\.NET"},
        {"type": "header", "header_name": "x-aspnet-version", "pattern": r"\d+\.\d+"},
        {"type": "header", "header_name": "x-aspnetmvc-version", "pattern": r"\d+\.\d+"},
        {"type": "cookie", "pattern": r"ASP\.NET_SessionId"},
    ],
    "PHP": [
        {"type": "header", "header_name": "x-powered-by", "pattern": r"PHP/[\d.]+"},
        {"type": "cookie", "pattern": r"PHPSESSID"},
    ],
    "Nginx": [
        {"type": "header", "header_name": "server", "pattern": r"nginx"},
    ],
    "Apache": [
        {"type": "header", "header_name": "server", "pattern": r"Apache"},
    ],
    "IIS": [
        {"type": "header", "header_name": "server", "pattern": r"Microsoft-IIS"},
        {"type": "header", "header_name": "x-powered-by", "pattern": r"ASP\.NET"},
    ],
    "Cloudflare": [
        {"type": "header", "header_name": "server", "pattern": r"cloudflare"},
        {"type": "header", "header_name": "cf-ray", "pattern": r".+"},
        {"type": "header", "header_name": "cf-cache-status", "pattern": r".+"},
        {"type": "cookie", "pattern": r"__cfduid|__cf_bm"},
    ],
    "AWS": [
        {"type": "header", "header_name": "server", "pattern": r"AmazonS3|awselb|AWSELBAuthSessionCookie"},
        {"type": "header", "header_name": "x-amz-request-id", "pattern": r".+"},
        {"type": "header", "header_name": "x-amz-id-2", "pattern": r".+"},
        {"type": "body", "pattern": r"aws-amplify|amazonaws\.com"},
    ],
    "jQuery": [
        {"type": "body", "pattern": r"jquery[.\-](\d+\.)+\d+(\.min)?\.js"},
        {"type": "body", "pattern": r"jQuery v(\d+\.)+\d+"},
    ],
    "React": [
        {"type": "body", "pattern": r"react[.\-](\d+\.)+\d+(\.min)?\.js"},
        {"type": "body", "pattern": r"__REACT_DEVTOOLS_GLOBAL_HOOK__|ReactDOM|react-dom"},
        {"type": "body", "pattern": r'data-reactroot|data-reactid'},
    ],
    "Vue": [
        {"type": "body", "pattern": r"vue[.\-](\d+\.)+\d+(\.min)?\.js"},
        {"type": "body", "pattern": r"__vue_|Vue\.config|new Vue\(|createApp\("},
    ],
    "Angular": [
        {"type": "body", "pattern": r"angular[.\-](\d+\.)+\d+(\.min)?\.js"},
        {"type": "body", "pattern": r"ng-version=|ng-app=|angular\.module\("},
        {"type": "body", "pattern": r"zone\.js"},
    ],
    "Bootstrap": [
        {"type": "body", "pattern": r"bootstrap[.\-](\d+\.)+\d+(\.min)?\.(?:js|css)"},
        {"type": "body", "pattern": r'class=["\'][^"\']*(?:navbar|container-fluid|btn-primary)'},
    ],
    "GraphQL": [
        {"type": "body", "pattern": r"__typename|__schema|__type"},
        {"type": "body", "pattern": r'"/graphql"'},
        {"type": "header", "header_name": "content-type", "pattern": r"application/graphql"},
    ],
    "Swagger": [
        {"type": "body", "pattern": r"swagger-ui|swagger\.json|swagger\.yaml"},
        {"type": "body", "pattern": r'"swagger"\s*:\s*"[23]\.0"'},
        {"type": "body", "pattern": r'"openapi"\s*:\s*"3\.'},
        {"type": "header", "header_name": "content-type", "pattern": r"application/vnd\.oai\.openapi"},
    ],
}


async def fingerprint(url: str, headers: dict, body: str) -> list[str]:
    """
    Apply all technology signatures to the given response data.

    Parameters
    ----------
    url:
        The URL of the response (currently unused but reserved for future
        URL-based signatures).
    headers:
        HTTP response headers as a dict (header names should be lowercase).
    body:
        Decoded response body text.

    Returns
    -------
    Deduplicated list of detected technology names.
    """
    detected: list[str] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    cookie_header = lower_headers.get("set-cookie", "")

    for tech, rules in TECH_SIGNATURES.items():
        matched = False
        for rule in rules:
            rtype = rule["type"]
            pattern = rule["pattern"]

            try:
                if rtype == "header":
                    header_name = rule.get("header_name", "").lower()
                    value = lower_headers.get(header_name, "")
                    matched = bool(re.search(pattern, value, re.IGNORECASE))
                elif rtype == "body":
                    matched = bool(re.search(pattern, body, re.IGNORECASE))
                elif rtype == "cookie":
                    matched = bool(re.search(pattern, cookie_header, re.IGNORECASE))
                elif rtype == "meta":
                    matched = bool(re.search(pattern, body, re.IGNORECASE))
            except re.error as exc:
                logger.warning("Invalid regex pattern for %s: %s (%s)", tech, pattern, exc)
                continue

            if matched:
                break

        if matched:
            detected.append(tech)

    return detected


async def get_favicon_hash(base_url: str, timeout: int = 5) -> Optional[str]:
    """
    Fetch ``/favicon.ico`` from *base_url* and return its MD5 hex digest.

    Parameters
    ----------
    base_url:
        Scheme + host (e.g. ``https://example.com``).  A trailing slash is
        acceptable.
    timeout:
        Request timeout in seconds.

    Returns
    -------
    MD5 hex string, or *None* if the resource is absent or the request fails.
    """
    favicon_url = base_url.rstrip("/") + "/favicon.ico"
    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
        ) as client:
            response = await client.get(favicon_url)
            if response.status_code == 200 and response.content:
                return hashlib.md5(response.content).hexdigest()
    except Exception as exc:
        logger.debug("Failed to fetch favicon from %s: %s", favicon_url, exc)
    return None


async def get_cert_fingerprint(
    fqdn: str,
    port: int = 443,
    timeout: int = 5,
) -> Optional[str]:
    """
    Retrieve the TLS certificate from *fqdn*:*port* and return its SHA-256
    fingerprint over the DER-encoded form.

    Parameters
    ----------
    fqdn:
        Hostname to connect to.
    port:
        TLS port (default 443).
    timeout:
        Connection timeout in seconds.

    Returns
    -------
    Lowercase hex SHA-256 string, or *None* if the connection fails or the
    host has no TLS.
    """
    loop = asyncio.get_event_loop()

    def _fetch_cert() -> Optional[bytes]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((fqdn, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=fqdn) as tls_sock:
                    der = tls_sock.getpeercert(binary_form=True)
                    return der
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
            return None

    try:
        der = await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_cert),
            timeout=timeout + 1,
        )
    except asyncio.TimeoutError:
        return None

    if der is None:
        return None

    return hashlib.sha256(der).hexdigest()
