"""
Discord notification channel for the asset monitoring tool.

Sends rich embed messages to a Discord incoming webhook, one embed per
severity group, each colour-coded to match the severity level.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)

# Discord embed colours as 24-bit integers.
SEVERITY_COLORS: Dict[str, int] = {
    "CRITICAL": 0xFF0000,
    "HIGH": 0xFF8C00,
    "MEDIUM": 0xFFD700,
    "LOW": 0x0077FF,
    "INFO": 0x808080,
}

SEVERITY_EMOJI: Dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

# Discord limits: 6 000 chars total per message, 25 embeds per message,
# 1 024 chars per embed field value, 4 096 chars per embed description.
_EMBED_DESC_LIMIT = 4000
_DISCORD_MAX_EMBEDS = 10  # stay well under the hard limit of 25


def _group_by_severity(
    events: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        sev = event.get("severity", "INFO").upper()
        groups.setdefault(sev, []).append(event)
    return dict(
        sorted(groups.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 99))
    )


def _build_embed(
    severity: str,
    sev_events: List[Dict[str, Any]],
    domain: str,
    scan_time: str,
) -> Dict[str, Any]:
    """Build a single Discord embed dict for one severity group."""
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    color = SEVERITY_COLORS.get(severity, 0x808080)

    lines: List[str] = []
    for ev in sev_events:
        event_type = ev.get("event_type", "UNKNOWN")
        target = ev.get("target", "—")
        description = ev.get("description", "")
        if len(description) > 200:
            description = description[:197] + "…"
        lines.append(f"• **{event_type}** | `{target}`\n  {description}")

    # Truncate description block to stay within Discord's embed limit.
    body = "\n".join(lines)
    if len(body) > _EMBED_DESC_LIMIT:
        body = body[: _EMBED_DESC_LIMIT - 3] + "…"

    return {
        "title": f"{emoji} {severity} — {len(sev_events)} event{'s' if len(sev_events) != 1 else ''}",
        "description": body,
        "color": color,
        "footer": {
            "text": f"AssetMonitor • {domain} • {scan_time}",
        },
    }


async def send_discord(
    webhook_url: str,
    events: List[Dict[str, Any]],
    domain: str,
) -> bool:
    """Send grouped Discord embed notifications to an incoming webhook.

    One embed is created per severity group.  If the number of severity groups
    exceeds Discord's per-message embed cap the embeds are batched across
    multiple requests.

    Args:
        webhook_url: Discord incoming webhook URL.
        events:      List of event dicts with ``severity``, ``event_type``,
                     ``target``, and ``description`` keys.
        domain:      Root domain name used in embed footers.

    Returns:
        ``True`` if all requests succeeded, ``False`` otherwise.
    """
    if not events:
        logger.debug("send_discord: no events to send for domain %s", domain)
        return True

    scan_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    groups = _group_by_severity(events)

    embeds: List[Dict[str, Any]] = []

    # Header embed
    embeds.append(
        {
            "title": f"🛡 AssetMonitor — {domain}",
            "description": (
                f"**{len(events)}** change event{'s' if len(events) != 1 else ''} "
                f"detected at {scan_time}"
            ),
            "color": 0x5865F2,  # Discord blurple
        }
    )

    for severity, sev_events in groups.items():
        embeds.append(_build_embed(severity, sev_events, domain, scan_time))

    all_ok = True
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Batch embeds into chunks of _DISCORD_MAX_EMBEDS
            for i in range(0, len(embeds), _DISCORD_MAX_EMBEDS):
                batch = embeds[i : i + _DISCORD_MAX_EMBEDS]
                payload: Dict[str, Any] = {
                    "username": "AssetMonitor",
                    "embeds": batch,
                }
                response = await client.post(webhook_url, json=payload)

                if response.status_code in (200, 204):
                    logger.debug(
                        "Discord embed batch %d sent for domain %s",
                        i // _DISCORD_MAX_EMBEDS + 1,
                        domain,
                    )
                else:
                    logger.error(
                        "Discord webhook returned HTTP %d: %s",
                        response.status_code,
                        response.text[:300],
                    )
                    all_ok = False

    except httpx.HTTPError as exc:
        logger.error("Discord HTTP error for domain %s: %s", domain, exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error sending Discord notification: %s", exc)
        return False

    if all_ok:
        logger.info(
            "Discord notification sent for domain %s (%d events)", domain, len(events)
        )
    return all_ok
