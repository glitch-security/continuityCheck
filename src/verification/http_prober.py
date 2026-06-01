"""
HTTP prober for subdomain liveness detection.

Tries HTTPS then HTTP on each configured port, follows redirects, and
records the full redirect chain, page title, and response metadata.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

PORTS: list[int] = [80, 443, 8080, 8443, 8888]

# Status codes that indicate the host is "live"
_LIVE_STATUS_CODES: set[int] = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str) -> str:
    """Return the text content of the first <title> element, or empty string."""
    m = _TITLE_RE.search(html)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()


def _scheme_for_port(port: int) -> str:
    """Return the conventional scheme for a given port number."""
    return "https" if port in (443, 8443) else "http"


async def probe_subdomain(
    fqdn: str,
    ports: list[int] | None = None,
    timeout: int = 10,
) -> dict:
    """
    Probe *fqdn* for HTTP/HTTPS liveness across the supplied *ports*.

    For each port the function tries HTTPS first, then HTTP (unless the port
    is an unambiguous HTTP port, in which case only HTTP is tried).  The first
    port/scheme combination that produces a meaningful response is used as the
    canonical result.

    Parameters
    ----------
    fqdn:
        Hostname to probe (no scheme or path).
    ports:
        List of TCP ports to attempt.  Defaults to :data:`PORTS`.
    timeout:
        Per-request timeout in seconds.

    Returns
    -------
    dict with keys:
        - ``fqdn``             (str)
        - ``live``             (bool)
        - ``url``              (str)  – canonical URL that responded
        - ``status_code``      (int)
        - ``response_size``    (int)  – body length in bytes
        - ``page_title``       (str)
        - ``response_headers`` (dict)
        - ``redirect_chain``   (list[str]) – ordered list of URLs visited
        - ``port``             (int)
        - ``scheme``           (str)
    """
    if ports is None:
        ports = PORTS

    result: dict = {
        "fqdn": fqdn,
        "live": False,
        "url": "",
        "status_code": 0,
        "response_size": 0,
        "page_title": "",
        "response_headers": {},
        "redirect_chain": [],
        "port": 0,
        "scheme": "",
    }

    # Build ordered list of (scheme, port) pairs to try.
    # HTTPS is always attempted before HTTP for the same port.
    attempts: list[tuple[str, int]] = []
    for port in ports:
        if port in (443, 8443):
            attempts.append(("https", port))
        elif port in (80,):
            attempts.append(("http", port))
        else:
            # Ambiguous ports: try HTTPS first, then HTTP
            attempts.append(("https", port))
            attempts.append(("http", port))

    for scheme, port in attempts:
        url = f"{scheme}://{fqdn}:{port}"
        redirect_chain: list[str] = []

        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(timeout),
                follow_redirects=True,
                max_redirects=10,
                event_hooks={
                    "request": [
                        lambda req: redirect_chain.append(str(req.url))
                        if redirect_chain  # only subsequent hops
                        else None
                    ]
                },
            ) as client:
                # Seed the chain with the initial URL
                redirect_chain.append(url)

                response = await client.get(url)

                # Collect redirect history from httpx's built-in tracking
                full_chain: list[str] = [url]
                for hist in response.history:
                    loc = str(hist.headers.get("location", ""))
                    if loc and loc not in full_chain:
                        full_chain.append(loc)
                final_url = str(response.url)
                if final_url not in full_chain:
                    full_chain.append(final_url)

                body_bytes = response.content
                body_text = body_bytes.decode("utf-8", errors="replace")

                result["url"] = final_url
                result["status_code"] = response.status_code
                result["response_size"] = len(body_bytes)
                result["page_title"] = _extract_title(body_text)
                result["response_headers"] = dict(response.headers)
                result["redirect_chain"] = full_chain
                result["port"] = port
                result["scheme"] = scheme

                if response.status_code in _LIVE_STATUS_CODES:
                    result["live"] = True
                    return result  # First successful live response wins

                # Non-live but valid response — record it and keep trying
                # (may find a live port later)

        except httpx.TimeoutException:
            logger.debug("Timeout probing %s", url)
        except httpx.ConnectError:
            logger.debug("Connection refused probing %s", url)
        except httpx.RemoteProtocolError:
            logger.debug("Protocol error probing %s", url)
        except Exception as exc:
            logger.debug("Error probing %s: %s", url, exc)

    # If we got any response at all (even non-live status), populate result
    # with the last attempted values already stored above (they may be from a
    # non-live attempt).  The ``live`` flag remains False.
    return result
