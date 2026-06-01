"""
JSON export module for the asset monitoring tool.

Queries the database and writes a structured, pretty-printed JSON report to
the specified output path.  An optional domain filter limits output to a
single root domain and its children.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from src.database import (
    Asset,
    ChangeEvent,
    DatabaseManager,
    Domain,
    Endpoint,
    Subdomain,
)

logger = logging.getLogger(__name__)


def _fmt_dt(dt: Optional[datetime]) -> Optional[str]:
    """Return ISO-8601 string with UTC suffix, or None."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.isoformat()


def _subdomain_to_dict(sub: Subdomain) -> Dict[str, Any]:
    return {
        "id": sub.id,
        "fqdn": sub.fqdn,
        "status": sub.status,
        "classification": sub.classification,
        "http_status": sub.http_status,
        "page_title": sub.page_title,
        "ip_addresses": sub.ip_addresses or [],
        "technologies": sub.technologies or [],
        "discovery_technique": sub.discovery_technique,
        "takeover_vulnerable": sub.takeover_vulnerable,
        "first_seen": _fmt_dt(sub.first_seen),
        "last_seen": _fmt_dt(sub.last_seen),
    }


def _endpoint_to_dict(ep: Endpoint, fqdn: str) -> Dict[str, Any]:
    return {
        "id": ep.id,
        "subdomain": fqdn,
        "path": ep.path,
        "method": ep.method,
        "status_code": ep.status_code,
        "content_type": ep.content_type,
        "source": ep.source,
        "parameters": ep.parameters or [],
        "first_seen": _fmt_dt(ep.first_seen),
        "last_seen": _fmt_dt(ep.last_seen),
    }


def _asset_to_dict(asset: Asset, fqdn: str) -> Dict[str, Any]:
    return {
        "id": asset.id,
        "subdomain": fqdn,
        "asset_url": asset.asset_url,
        "asset_type": asset.asset_type,
        "content_hash": asset.content_hash,
        "first_seen": _fmt_dt(asset.first_seen),
        "last_seen": _fmt_dt(asset.last_seen),
        "last_changed": _fmt_dt(asset.last_changed),
    }


def _event_to_dict(ev: ChangeEvent) -> Dict[str, Any]:
    return {
        "id": ev.id,
        "event_type": ev.event_type,
        "severity": ev.severity,
        "target": ev.target,
        "description": ev.description,
        "diff_data": ev.diff_data,
        "detected_at": _fmt_dt(ev.detected_at),
        "alerted": ev.alerted,
        "alerted_at": _fmt_dt(ev.alerted_at),
    }


async def export_json(
    db: DatabaseManager,
    output_path: str,
    domain: Optional[str] = None,
) -> None:
    """Export the full monitoring database to a pretty-printed JSON file.

    Args:
        db:          :class:`DatabaseManager` instance.
        output_path: Filesystem path for the output ``.json`` file.
        domain:      If given, restrict the export to this root domain only.
                     All subdomains, endpoints, assets, and events for other
                     domains are omitted.
    """
    exported_at = datetime.now(tz=timezone.utc).isoformat()

    with db.get_session() as session:
        # --- Root domains ------------------------------------------------
        if domain:
            domains: List[Domain] = list(
                session.scalars(
                    select(Domain).where(Domain.domain == domain)
                ).all()
            )
        else:
            domains = list(session.scalars(select(Domain)).all())

        domain_ids = {d.id for d in domains}

        # --- Subdomains --------------------------------------------------
        if domain_ids:
            subdomains: List[Subdomain] = list(
                session.scalars(
                    select(Subdomain).where(Subdomain.domain_id.in_(domain_ids))
                ).all()
            )
        else:
            subdomains = []

        subdomain_id_to_fqdn: Dict[int, str] = {
            s.id: s.fqdn for s in subdomains if s.id is not None
        }
        subdomain_ids = set(subdomain_id_to_fqdn.keys())

        # --- Endpoints ---------------------------------------------------
        if subdomain_ids:
            endpoints: List[Endpoint] = list(
                session.scalars(
                    select(Endpoint).where(Endpoint.subdomain_id.in_(subdomain_ids))
                ).all()
            )
        else:
            endpoints = []

        # --- Assets ------------------------------------------------------
        if subdomain_ids:
            assets: List[Asset] = list(
                session.scalars(
                    select(Asset).where(Asset.subdomain_id.in_(subdomain_ids))
                ).all()
            )
        else:
            assets = []

        # --- Change events -----------------------------------------------
        # Events are matched to a domain by checking whether the target FQDN
        # starts with any known subdomain FQDN or root domain name.
        all_events: List[ChangeEvent] = list(
            session.scalars(
                select(ChangeEvent).order_by(ChangeEvent.detected_at.desc())
            ).all()
        )

        if domain:
            domain_names = {d.domain for d in domains}
            fqdns = set(subdomain_id_to_fqdn.values())
            all_fqdns_and_domains = fqdns | domain_names
            change_events = [
                ev
                for ev in all_events
                if any(ev.target.endswith(f) for f in all_fqdns_and_domains)
            ]
        else:
            change_events = all_events

    # --- Summary stats ---------------------------------------------------
    live_count = sum(1 for s in subdomains if s.status == "alive")
    severity_counts: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    for ev in change_events:
        sev = (ev.severity or "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # --- Assemble domain tree -------------------------------------------
    subdomain_map: Dict[int, List[Endpoint]] = {}
    for ep in endpoints:
        subdomain_map.setdefault(ep.subdomain_id, []).append(ep)

    asset_map: Dict[int, List[Asset]] = {}
    for asset in assets:
        asset_map.setdefault(asset.subdomain_id, []).append(asset)

    domains_out: List[Dict[str, Any]] = []
    for dom in domains:
        dom_subdomains = [s for s in subdomains if s.domain_id == dom.id]
        subs_out: List[Dict[str, Any]] = []
        for sub in dom_subdomains:
            sub_dict = _subdomain_to_dict(sub)
            sub_dict["endpoints"] = [
                _endpoint_to_dict(ep, sub.fqdn)
                for ep in subdomain_map.get(sub.id, [])
            ]
            sub_dict["assets"] = [
                _asset_to_dict(a, sub.fqdn)
                for a in asset_map.get(sub.id, [])
            ]
            subs_out.append(sub_dict)

        domains_out.append(
            {
                "id": dom.id,
                "domain": dom.domain,
                "added_at": _fmt_dt(dom.added_at),
                "last_scan": _fmt_dt(dom.last_scan),
                "scan_interval_minutes": dom.scan_interval_minutes,
                "subdomains": subs_out,
            }
        )

    report: Dict[str, Any] = {
        "exported_at": exported_at,
        "tool": "AssetMonitor",
        "version": "1.0.0",
        "filter_domain": domain,
        "domains": domains_out,
        "change_events": [_event_to_dict(ev) for ev in change_events],
        "summary": {
            "total_domains": len(domains),
            "total_subdomains": len(subdomains),
            "live_subdomains": live_count,
            "total_endpoints": len(endpoints),
            "total_assets": len(assets),
            "total_events": len(change_events),
            "critical_events": severity_counts.get("CRITICAL", 0),
            "high_events": severity_counts.get("HIGH", 0),
            "medium_events": severity_counts.get("MEDIUM", 0),
            "low_events": severity_counts.get("LOW", 0),
            "info_events": severity_counts.get("INFO", 0),
        },
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    logger.info(
        "JSON report exported to %s (%d domains, %d subdomains, %d events)",
        output_path,
        len(domains),
        len(subdomains),
        len(change_events),
    )
