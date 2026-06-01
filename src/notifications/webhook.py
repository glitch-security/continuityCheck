"""
Generic outbound webhook notification channel for the asset monitoring tool.

POSTs a structured JSON payload to an arbitrary HTTP endpoint, optionally
signing the request with a shared secret header.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)

_SECRET_HEADER_NAME = "X-AssetMonitor-Secret"


async def send_webhook(
    url: str,
    secret_header: str,
    events: List[Dict[str, Any]],
    domain: str,
) -> bool:
    """POST a structured JSON payload to an outbound webhook URL.

    The payload schema is::

        {
            "domain":      "example.com",
            "scan_time":   "2024-01-01T00:00:00Z",   # ISO-8601 UTC
            "event_count": 5,
            "events": [
                {
                    "event_type":  "NEW_SUBDOMAIN",
                    "severity":    "HIGH",
                    "target":      "admin.example.com",
                    "description": "...",
                    ...
                },
                ...
            ]
        }

    If ``secret_header`` is a non-empty string it is added to the request as
    the ``X-AssetMonitor-Secret`` header so the receiving endpoint can verify
    the request's authenticity.

    Args:
        url:           Destination URL.
        secret_header: Shared secret value.  Pass an empty string to omit
                       the header entirely.
        events:        List of event dicts to include in the payload.
        domain:        Root domain name.

    Returns:
        ``True`` if the server responded with a 2xx status, ``False``
        otherwise.
    """
    if not events:
        logger.debug("send_webhook: no events to send for domain %s", domain)
        return True

    scan_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload: Dict[str, Any] = {
        "domain": domain,
        "scan_time": scan_time,
        "event_count": len(events),
        "events": events,
    }

    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "AssetMonitor/1.0",
    }
    if secret_header:
        headers[_SECRET_HEADER_NAME] = secret_header

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, json=payload, headers=headers)

        if 200 <= response.status_code < 300:
            logger.info(
                "Webhook notification sent for domain %s to %s (%d events)",
                domain,
                url,
                len(events),
            )
            return True

        logger.error(
            "Webhook endpoint returned HTTP %d for domain %s: %s",
            response.status_code,
            domain,
            response.text[:200],
        )
        return False

    except httpx.HTTPError as exc:
        logger.error("Webhook HTTP error for domain %s (url=%s): %s", domain, url, exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error sending webhook notification: %s", exc)
        return False
