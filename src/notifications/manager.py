"""
Notification manager for the asset monitoring tool.

Dispatches ChangeEvent objects to all enabled notification channels,
filters by minimum severity, and marks events as alerted in the database
after successful delivery.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from src.config import AppConfig
from src.database import ChangeEvent, DatabaseManager
from src.notifications.discord import send_discord
from src.notifications.email_notify import send_email
from src.notifications.slack import send_slack
from src.notifications.telegram import send_telegram
from src.notifications.webhook import send_webhook

logger = logging.getLogger(__name__)


def _event_to_dict(event: ChangeEvent) -> Dict[str, Any]:
    """Convert a :class:`ChangeEvent` ORM object to a plain dict."""
    return {
        "id": event.id,
        "event_type": event.event_type,
        "severity": event.severity,
        "target": event.target,
        "description": event.description,
        "diff_data": event.diff_data,
        "detected_at": (
            event.detected_at.isoformat() if event.detected_at else None
        ),
    }


class NotificationManager:
    """Orchestrates delivery of change events to all configured channels.

    Args:
        config: Application configuration (must contain a ``notifications``
                section).
        db:     :class:`DatabaseManager` used to mark events as alerted after
                successful dispatch.
    """

    SEVERITY_ORDER: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    def __init__(self, config: AppConfig, db: DatabaseManager) -> None:
        self._config = config
        self._db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def should_alert(severity: str, min_severity: str) -> bool:
        """Return ``True`` if *severity* meets or exceeds *min_severity*.

        A lower :attr:`SEVERITY_ORDER` value means higher severity, so an
        event should be alerted when its order value is ≤ the minimum's order
        value.

        Args:
            severity:     The event severity string, e.g. ``"HIGH"``.
            min_severity: The configured minimum threshold, e.g. ``"MEDIUM"``.

        Returns:
            ``True`` if the event severity is at least as severe as the
            threshold.
        """
        order = NotificationManager.SEVERITY_ORDER
        event_level = order.get(severity.upper(), 99)
        min_level = order.get(min_severity.upper(), 99)
        return event_level <= min_level

    async def dispatch(
        self,
        events: List[ChangeEvent],
        domain: str,
    ) -> None:
        """Filter, group, and dispatch change events to all enabled channels.

        For each enabled notification channel the corresponding send function
        is called.  Events are marked as alerted in the database only after at
        least one channel delivers them successfully.

        Args:
            events: Raw :class:`ChangeEvent` ORM objects (may include already-
                    alerted events — those are skipped).
            domain: The root domain these events belong to (used in message
                    headers).
        """
        notif_cfg = self._config.notifications
        min_severity = notif_cfg.min_severity

        # 1. Filter to events that haven't been alerted yet and meet severity.
        filtered: List[ChangeEvent] = [
            ev
            for ev in events
            if not ev.alerted
            and self.should_alert(ev.severity, min_severity)
        ]

        if not filtered:
            logger.debug(
                "dispatch: no events requiring notification for domain %s "
                "(min_severity=%s, total_input=%d)",
                domain,
                min_severity,
                len(events),
            )
            return

        # 2. Convert to plain dicts for the channel send functions.
        event_dicts: List[Dict[str, Any]] = [_event_to_dict(ev) for ev in filtered]
        event_ids: List[int] = [ev.id for ev in filtered if ev.id is not None]

        logger.info(
            "Dispatching %d event(s) for domain %s to notification channels",
            len(filtered),
            domain,
        )

        any_success = False

        # 3. Slack
        if notif_cfg.slack.enabled and notif_cfg.slack.webhook_url:
            ok = await self._dispatch_slack(event_dicts, domain)
            if ok:
                any_success = True
            logger.info("Slack dispatch for %s: %s", domain, "OK" if ok else "FAILED")

        # 4. Telegram
        if (
            notif_cfg.telegram.enabled
            and notif_cfg.telegram.bot_token
            and notif_cfg.telegram.chat_id
        ):
            ok = await self._dispatch_telegram(event_dicts, domain)
            if ok:
                any_success = True
            logger.info(
                "Telegram dispatch for %s: %s", domain, "OK" if ok else "FAILED"
            )

        # 5. Discord
        if notif_cfg.discord.enabled and notif_cfg.discord.webhook_url:
            ok = await self._dispatch_discord(event_dicts, domain)
            if ok:
                any_success = True
            logger.info(
                "Discord dispatch for %s: %s", domain, "OK" if ok else "FAILED"
            )

        # 6. Email
        if notif_cfg.email.enabled and notif_cfg.email.to_addresses:
            ok = await self._dispatch_email(event_dicts, domain)
            if ok:
                any_success = True
            logger.info("Email dispatch for %s: %s", domain, "OK" if ok else "FAILED")

        # 7. Generic webhook
        if notif_cfg.webhook.enabled and notif_cfg.webhook.url:
            ok = await self._dispatch_webhook(event_dicts, domain)
            if ok:
                any_success = True
            logger.info(
                "Webhook dispatch for %s: %s", domain, "OK" if ok else "FAILED"
            )

        # 8. Mark as alerted if at least one channel succeeded.
        if any_success and event_ids:
            self._db.mark_events_alerted(event_ids)
            logger.info(
                "Marked %d event(s) as alerted for domain %s",
                len(event_ids),
                domain,
            )

    # ------------------------------------------------------------------
    # Private channel dispatchers
    # ------------------------------------------------------------------

    async def _dispatch_slack(
        self, event_dicts: List[Dict[str, Any]], domain: str
    ) -> bool:
        try:
            return await send_slack(
                webhook_url=self._config.notifications.slack.webhook_url,
                events=event_dicts,
                domain=domain,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Slack dispatch error for domain %s: %s", domain, exc)
            return False

    async def _dispatch_telegram(
        self, event_dicts: List[Dict[str, Any]], domain: str
    ) -> bool:
        cfg = self._config.notifications.telegram
        try:
            return await send_telegram(
                bot_token=cfg.bot_token,
                chat_id=cfg.chat_id,
                events=event_dicts,
                domain=domain,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Telegram dispatch error for domain %s: %s", domain, exc)
            return False

    async def _dispatch_discord(
        self, event_dicts: List[Dict[str, Any]], domain: str
    ) -> bool:
        try:
            return await send_discord(
                webhook_url=self._config.notifications.discord.webhook_url,
                events=event_dicts,
                domain=domain,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Discord dispatch error for domain %s: %s", domain, exc)
            return False

    async def _dispatch_email(
        self, event_dicts: List[Dict[str, Any]], domain: str
    ) -> bool:
        email_cfg = self._config.notifications.email
        smtp_config: Dict[str, Any] = {
            "host": email_cfg.smtp_host,
            "port": email_cfg.smtp_port,
            "username": email_cfg.smtp_username,
            "password": email_cfg.smtp_password,
            "use_tls": email_cfg.use_tls,
            "from_address": email_cfg.from_address,
            "to_addresses": email_cfg.to_addresses,
        }
        try:
            return await send_email(
                smtp_config=smtp_config,
                events=event_dicts,
                domain=domain,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Email dispatch error for domain %s: %s", domain, exc)
            return False

    async def _dispatch_webhook(
        self, event_dicts: List[Dict[str, Any]], domain: str
    ) -> bool:
        cfg = self._config.notifications.webhook
        try:
            return await send_webhook(
                url=cfg.url,
                secret_header=cfg.secret,
                events=event_dicts,
                domain=domain,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Webhook dispatch error for domain %s: %s", domain, exc)
            return False
