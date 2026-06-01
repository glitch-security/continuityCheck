"""
Email notification channel for the asset monitoring tool.

Builds a styled HTML email summarising detected change events and delivers
it via aiosmtplib with STARTTLS support.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List

import aiosmtplib

logger = logging.getLogger(__name__)

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

# Background colours for severity table rows
SEVERITY_ROW_COLORS: Dict[str, str] = {
    "CRITICAL": "#ffe0e0",
    "HIGH": "#ffe8cc",
    "MEDIUM": "#fffbe0",
    "LOW": "#e0eeff",
    "INFO": "#f0f0f0",
}

SEVERITY_BADGE_COLORS: Dict[str, str] = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#2980b9",
    "INFO": "#95a5a6",
}


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _build_html_body(events: List[Dict[str, Any]], domain: str) -> str:
    """Render a complete HTML email body for the given events."""
    scan_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sorted_events = sorted(
        events,
        key=lambda e: SEVERITY_ORDER.get(e.get("severity", "INFO").upper(), 99),
    )

    rows_html = ""
    for ev in sorted_events:
        sev = ev.get("severity", "INFO").upper()
        row_bg = SEVERITY_ROW_COLORS.get(sev, "#f0f0f0")
        badge_bg = SEVERITY_BADGE_COLORS.get(sev, "#95a5a6")
        event_type = _escape_html(ev.get("event_type", "UNKNOWN"))
        target = _escape_html(ev.get("target", "—"))
        description = _escape_html(ev.get("description", ""))

        rows_html += f"""
        <tr style="background-color:{row_bg};">
          <td style="padding:8px 12px;border-bottom:1px solid #ddd;white-space:nowrap;">
            <span style="
              background-color:{badge_bg};
              color:#fff;
              padding:2px 8px;
              border-radius:4px;
              font-size:12px;
              font-weight:bold;
              font-family:monospace;
            ">{sev}</span>
          </td>
          <td style="padding:8px 12px;border-bottom:1px solid #ddd;font-family:monospace;font-size:13px;">{event_type}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #ddd;font-family:monospace;font-size:13px;">{target}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #ddd;font-size:13px;">{description}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AssetMonitor Report</title>
</head>
<body style="margin:0;padding:0;font-family:Arial,Helvetica,sans-serif;background-color:#f4f6f8;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f8;padding:24px 0;">
    <tr>
      <td align="center">
        <table width="640" cellpadding="0" cellspacing="0"
               style="background:#ffffff;border-radius:8px;overflow:hidden;
                      box-shadow:0 2px 8px rgba(0,0,0,.12);max-width:640px;">

          <!-- Header -->
          <tr>
            <td style="background-color:#1a1a2e;padding:24px 32px;">
              <h1 style="margin:0;color:#e94560;font-size:22px;letter-spacing:1px;">
                🛡 AssetMonitor
              </h1>
              <p style="margin:6px 0 0;color:#a0a8b8;font-size:14px;">
                Security Asset Change Report
              </p>
            </td>
          </tr>

          <!-- Summary banner -->
          <tr>
            <td style="background-color:#16213e;padding:16px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="color:#e0e0e0;font-size:14px;">
                    <strong style="color:#e94560;">{_escape_html(domain)}</strong>
                    &nbsp;·&nbsp; {len(events)} change event{'s' if len(events) != 1 else ''} detected
                  </td>
                  <td align="right" style="color:#a0a8b8;font-size:12px;">
                    {scan_time}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Events table -->
          <tr>
            <td style="padding:24px 32px;">
              <h2 style="margin:0 0 16px;font-size:16px;color:#1a1a2e;">
                Detected Changes
              </h2>
              <table width="100%" cellpadding="0" cellspacing="0"
                     style="border-collapse:collapse;border:1px solid #dde1e7;border-radius:6px;overflow:hidden;">
                <thead>
                  <tr style="background-color:#1a1a2e;">
                    <th style="padding:10px 12px;text-align:left;color:#e0e0e0;font-size:13px;font-weight:600;">Severity</th>
                    <th style="padding:10px 12px;text-align:left;color:#e0e0e0;font-size:13px;font-weight:600;">Type</th>
                    <th style="padding:10px 12px;text-align:left;color:#e0e0e0;font-size:13px;font-weight:600;">Target</th>
                    <th style="padding:10px 12px;text-align:left;color:#e0e0e0;font-size:13px;font-weight:600;">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {rows_html}
                </tbody>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color:#f4f6f8;padding:16px 32px;border-top:1px solid #dde1e7;">
              <p style="margin:0;font-size:12px;color:#888;text-align:center;">
                Generated by <strong>AssetMonitor</strong> at {scan_time}<br>
                This is an automated security notification — do not reply to this email.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
    return html


async def send_email(
    smtp_config: Dict[str, Any],
    events: List[Dict[str, Any]],
    domain: str,
) -> bool:
    """Send an HTML change-event report via SMTP with STARTTLS.

    Args:
        smtp_config: Dict with keys ``host``, ``port``, ``username``,
                     ``password``, ``from_address``, ``to_addresses``
                     (list of str), and optionally ``use_tls`` (bool,
                     default ``True``).
        events:      List of event dicts with ``severity``, ``event_type``,
                     ``target``, and ``description`` keys.
        domain:      Root domain name used in the subject line.

    Returns:
        ``True`` if the email was accepted by the SMTP server, ``False``
        otherwise.
    """
    if not events:
        logger.debug("send_email: no events to send for domain %s", domain)
        return True

    to_addresses: List[str] = smtp_config.get("to_addresses", [])
    if not to_addresses:
        logger.warning("send_email: no recipient addresses configured — skipping")
        return False

    from_address: str = smtp_config.get("from_address", "assetmonitor@localhost")
    subject = f"[AssetMonitor] {len(events)} changes detected on {domain}"

    html_body = _build_html_body(events, domain)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_address
    msg["To"] = ", ".join(to_addresses)
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    host: str = smtp_config.get("host", "localhost")
    port: int = int(smtp_config.get("port", 587))
    username: str = smtp_config.get("username", "")
    password: str = smtp_config.get("password", "")
    use_tls: bool = smtp_config.get("use_tls", True)

    try:
        smtp = aiosmtplib.SMTP(
            hostname=host,
            port=port,
            use_tls=False,          # We use STARTTLS, not implicit TLS
            timeout=30,
        )
        await smtp.connect()

        if use_tls:
            await smtp.starttls()

        if username and password:
            await smtp.login(username, password)

        await smtp.sendmail(from_address, to_addresses, msg.as_string())
        await smtp.quit()

        logger.info(
            "Email notification sent for domain %s to %s (%d events)",
            domain,
            ", ".join(to_addresses),
            len(events),
        )
        return True

    except aiosmtplib.SMTPException as exc:
        logger.error("SMTP error sending email for domain %s: %s", domain, exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error sending email notification: %s", exc)
        return False
