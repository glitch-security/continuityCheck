"""
Telegram notification channel for the asset monitoring tool.

Formats events as an HTML message, groups them by severity, and posts them
to the Telegram Bot API.  Messages that exceed Telegram's 4 096-character
limit are automatically split into multiple requests.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)

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

_TELEGRAM_MAX_CHARS = 4096


def _escape_html(text: str) -> str:
    """Escape characters that have special meaning in Telegram HTML mode."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


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


def _build_html_chunks(
    events: List[Dict[str, Any]],
    domain: str,
) -> List[str]:
    """Build one or more HTML message strings, each ≤ 4 096 characters."""
    scan_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    header = (
        f"<b>🛡 AssetMonitor — {_escape_html(domain)}</b>\n"
        f"<i>Scan time: {scan_time} | {len(events)} event(s)</i>\n"
        "─────────────────────\n"
    )

    groups = _group_by_severity(events)

    # Build the full body as a list of line strings so we can split cleanly.
    lines: List[str] = []
    for severity, sev_events in groups.items():
        emoji = SEVERITY_EMOJI.get(severity, "⚪")
        lines.append(
            f"\n{emoji} <b>{_escape_html(severity)}</b> "
            f"({len(sev_events)} event{'s' if len(sev_events) != 1 else ''})"
        )
        for ev in sev_events:
            event_type = _escape_html(ev.get("event_type", "UNKNOWN"))
            target = _escape_html(ev.get("target", "—"))
            description = ev.get("description", "")
            if len(description) > 300:
                description = description[:297] + "…"
            description = _escape_html(description)
            lines.append(f"  • <code>{event_type}</code> | <code>{target}</code>")
            lines.append(f"    {description}")

    chunks: List[str] = []
    current = header
    for line in lines:
        candidate = current + line + "\n"
        if len(candidate) > _TELEGRAM_MAX_CHARS:
            # Flush the current chunk and start a new one with a continuation header.
            chunks.append(current.rstrip())
            cont_header = (
                f"<b>🛡 AssetMonitor — {_escape_html(domain)}</b> <i>(cont.)</i>\n"
                "─────────────────────\n"
            )
            current = cont_header + line + "\n"
        else:
            current = candidate

    if current.strip():
        chunks.append(current.rstrip())

    return chunks


async def send_telegram(
    bot_token: str,
    chat_id: str,
    events: List[Dict[str, Any]],
    domain: str,
) -> bool:
    """Send HTML-formatted event notifications via the Telegram Bot API.

    Messages longer than 4 096 characters are automatically split into
    multiple requests.

    Args:
        bot_token: Telegram Bot API token (from BotFather).
        chat_id:   Target chat / channel ID as a string.
        events:    List of event dicts with ``severity``, ``event_type``,
                   ``target``, and ``description`` keys.
        domain:    Root domain name used in the message header.

    Returns:
        ``True`` if all messages were delivered successfully, ``False`` if any
        request failed.
    """
    if not events:
        logger.debug("send_telegram: no events to send for domain %s", domain)
        return True

    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    chunks = _build_html_chunks(events, domain)

    all_ok = True
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            for idx, chunk in enumerate(chunks):
                payload = {
                    "chat_id": chat_id,
                    "text": chunk,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                }
                response = await client.post(api_url, json=payload)

                if response.status_code == 200:
                    logger.debug(
                        "Telegram chunk %d/%d sent for domain %s",
                        idx + 1,
                        len(chunks),
                        domain,
                    )
                else:
                    logger.error(
                        "Telegram API returned HTTP %d for chunk %d: %s",
                        response.status_code,
                        idx + 1,
                        response.text[:300],
                    )
                    all_ok = False

    except httpx.HTTPError as exc:
        logger.error("Telegram HTTP error for domain %s: %s", domain, exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error sending Telegram notification: %s", exc)
        return False

    if all_ok:
        logger.info(
            "Telegram notification sent for domain %s (%d event(s), %d message(s))",
            domain,
            len(events),
            len(chunks),
        )
    return all_ok
