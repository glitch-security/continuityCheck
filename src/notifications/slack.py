"""
Slack notification channel for the asset monitoring tool.

Sends Block Kit messages to a Slack incoming webhook, grouping events by
severity and colour-coding each section header.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)

# Severity → Slack accent colour (hex, no leading #) used in section context
SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "#FF0000",
    "HIGH": "#FF8C00",
    "MEDIUM": "#FFD700",
    "LOW": "#0077FF",
    "INFO": "#808080",
}

SEVERITY_EMOJI: Dict[str, str] = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":large_orange_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":large_blue_circle:",
    "INFO": ":white_circle:",
}

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def _group_by_severity(events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Return events keyed by severity, ordered CRITICAL → INFO."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        sev = event.get("severity", "INFO").upper()
        groups.setdefault(sev, []).append(event)
    return dict(
        sorted(groups.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 99))
    )


def _build_blocks(
    events: List[Dict[str, Any]],
    domain: str,
) -> List[Dict[str, Any]]:
    """Construct Slack Block Kit blocks for the given events."""
    scan_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(events)

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f":shield: AssetMonitor — {domain}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Domain:*\n{domain}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Scan time:*\n{scan_time}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Total events:*\n{total}",
                },
            ],
        },
        {"type": "divider"},
    ]

    groups = _group_by_severity(events)

    for severity, sev_events in groups.items():
        emoji = SEVERITY_EMOJI.get(severity, ":white_circle:")
        color_label = f"{emoji} *{severity}* ({len(sev_events)} event{'s' if len(sev_events) != 1 else ''})"

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": color_label,
                },
            }
        )

        # Build bullet lines — split into chunks of 10 to stay under the
        # 3 000-char Slack block text limit.
        bullet_lines: List[str] = []
        for ev in sev_events:
            event_type = ev.get("event_type", "UNKNOWN")
            target = ev.get("target", "—")
            description = ev.get("description", "")
            # Truncate very long descriptions so the block doesn't explode.
            if len(description) > 200:
                description = description[:197] + "…"
            bullet_lines.append(f"• *{event_type}* | `{target}` — {description}")

        # Each section block can hold up to ~3 000 chars; chunk by 10 events.
        chunk_size = 10
        for i in range(0, len(bullet_lines), chunk_size):
            chunk = bullet_lines[i : i + chunk_size]
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(chunk),
                    },
                }
            )

        blocks.append({"type": "divider"})

    return blocks


async def send_slack(
    webhook_url: str,
    events: List[Dict[str, Any]],
    domain: str,
) -> bool:
    """Send a grouped, colour-coded Block Kit message to a Slack webhook.

    Args:
        webhook_url: Slack incoming webhook URL.
        events:      List of event dicts; each must have at least ``severity``,
                     ``event_type``, ``target``, and ``description`` keys.
        domain:      Root domain name used in the message header.

    Returns:
        ``True`` if Slack returned HTTP 200, ``False`` otherwise.
    """
    if not events:
        logger.debug("send_slack: no events to send for domain %s", domain)
        return True

    blocks = _build_blocks(events, domain)
    payload = {
        "username": "AssetMonitor",
        "icon_emoji": ":shield:",
        "blocks": blocks,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(webhook_url, json=payload)

        if response.status_code == 200:
            logger.info(
                "Slack notification sent for domain %s (%d events)", domain, len(events)
            )
            return True

        logger.error(
            "Slack webhook returned HTTP %d: %s",
            response.status_code,
            response.text[:200],
        )
        return False

    except httpx.HTTPError as exc:
        logger.error("Slack HTTP error for domain %s: %s", domain, exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error sending Slack notification: %s", exc)
        return False
