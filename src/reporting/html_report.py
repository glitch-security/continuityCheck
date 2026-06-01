"""
HTML report generator for the asset monitoring tool.

Uses Jinja2 with an inline dark-themed, cyber-aesthetic template to produce
a self-contained HTML report containing an executive summary, critical/high
events, subdomain inventory, endpoints, and a full change-events timeline.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from jinja2 import DictLoader, Environment, select_autoescape
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

_TOOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Jinja2 template (inline, dark cyber aesthetic)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AssetMonitor Report{% if filter_domain %} — {{ filter_domain }}{% endif %}</title>
<style>
  :root {
    --bg:       #0d0d1a;
    --bg2:      #13132a;
    --bg3:      #1a1a35;
    --accent:   #e94560;
    --accent2:  #0f3460;
    --text:     #c8ccd4;
    --text2:    #8890a0;
    --border:   #2a2a50;
    --green:    #39d353;
    --crit:     #ff3030;
    --high:     #ff8c00;
    --med:      #ffd700;
    --low:      #1e90ff;
    --info:     #808080;
    --crit-bg:  #2a0808;
    --high-bg:  #2a1800;
    --med-bg:   #2a2200;
    --low-bg:   #08142a;
    --info-bg:  #181820;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* ---------- top nav bar ---------- */
  .navbar {
    background: var(--bg2);
    border-bottom: 2px solid var(--accent);
    padding: 16px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .navbar .logo {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 2px;
    text-transform: uppercase;
  }
  .navbar .sub {
    color: var(--text2);
    font-size: 13px;
  }

  /* ---------- layout ---------- */
  .container { max-width: 1280px; margin: 0 auto; padding: 32px 24px; }

  h2 {
    font-size: 18px;
    color: var(--accent);
    border-left: 4px solid var(--accent);
    padding-left: 10px;
    margin: 32px 0 16px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  /* ---------- summary cards ---------- */
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 8px;
  }
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
  }
  .card .num {
    font-size: 36px;
    font-weight: 700;
    color: var(--accent);
    font-variant-numeric: tabular-nums;
  }
  .card .label {
    font-size: 12px;
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
  }
  .card.crit .num { color: var(--crit); }
  .card.high .num { color: var(--high); }
  .card.med  .num { color: var(--med);  }
  .card.low  .num { color: var(--low);  }

  /* ---------- tables ---------- */
  .tbl-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  thead tr { background: var(--bg3); }
  thead th {
    padding: 10px 14px;
    text-align: left;
    color: var(--text2);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  tbody tr { border-bottom: 1px solid var(--border); }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: rgba(255,255,255,.03); }
  tbody td { padding: 9px 14px; vertical-align: top; }

  /* severity row tints */
  tr.sev-CRITICAL { background: var(--crit-bg); }
  tr.sev-HIGH     { background: var(--high-bg); }
  tr.sev-MEDIUM   { background: var(--med-bg);  }
  tr.sev-LOW      { background: var(--low-bg);  }
  tr.sev-INFO     { background: var(--info-bg); }

  /* severity badges */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    font-family: monospace;
    letter-spacing: 0.5px;
  }
  .badge-CRITICAL { background: var(--crit); color: #fff; }
  .badge-HIGH     { background: var(--high); color: #000; }
  .badge-MEDIUM   { background: var(--med);  color: #000; }
  .badge-LOW      { background: var(--low);  color: #fff; }
  .badge-INFO     { background: var(--info); color: #fff; }

  /* status badges */
  .status-alive    { color: var(--green);  font-weight: 600; }
  .status-dead     { color: #666; }
  .status-unknown  { color: var(--text2); }
  .status-redirect { color: var(--med); }

  code {
    background: rgba(255,255,255,.07);
    border-radius: 3px;
    padding: 1px 5px;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 12px;
    color: #b0c4de;
  }

  /* diff data block */
  pre.diff {
    background: #0a0a18;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px;
    font-size: 11px;
    overflow-x: auto;
    color: var(--text2);
    max-height: 200px;
  }

  /* ---------- footer ---------- */
  .footer {
    margin-top: 48px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text2);
    font-size: 12px;
  }
  .footer span { color: var(--accent); font-weight: 600; }
</style>
</head>
<body>

<div class="navbar">
  <div class="logo">🛡 AssetMonitor</div>
  <div class="sub">
    Security Asset Report
    {% if filter_domain %} &mdash; <strong style="color:#e0e0e0;">{{ filter_domain }}</strong>{% endif %}
  </div>
</div>

<div class="container">

  <!-- ================================================================ -->
  <!-- EXECUTIVE SUMMARY                                                -->
  <!-- ================================================================ -->
  <h2>Executive Summary</h2>
  <div class="cards">
    <div class="card">
      <div class="num">{{ summary.total_domains }}</div>
      <div class="label">Domains</div>
    </div>
    <div class="card">
      <div class="num">{{ summary.total_subdomains }}</div>
      <div class="label">Subdomains</div>
    </div>
    <div class="card">
      <div class="num">{{ summary.live_subdomains }}</div>
      <div class="label">Live</div>
    </div>
    <div class="card">
      <div class="num">{{ summary.total_endpoints }}</div>
      <div class="label">Endpoints</div>
    </div>
    <div class="card">
      <div class="num">{{ summary.total_events }}</div>
      <div class="label">Total Events</div>
    </div>
    <div class="card crit">
      <div class="num">{{ summary.critical_events }}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card high">
      <div class="num">{{ summary.high_events }}</div>
      <div class="label">High</div>
    </div>
    <div class="card med">
      <div class="num">{{ summary.medium_events }}</div>
      <div class="label">Medium</div>
    </div>
    <div class="card low">
      <div class="num">{{ summary.low_events }}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <!-- ================================================================ -->
  <!-- CRITICAL & HIGH EVENTS                                           -->
  <!-- ================================================================ -->
  {% if critical_high_events %}
  <h2>Critical &amp; High Events</h2>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Target</th>
          <th>Description</th>
          <th>Detected At</th>
        </tr>
      </thead>
      <tbody>
        {% for ev in critical_high_events %}
        <tr class="sev-{{ ev.severity }}">
          <td><span class="badge badge-{{ ev.severity }}">{{ ev.severity }}</span></td>
          <td><code>{{ ev.event_type }}</code></td>
          <td><code>{{ ev.target }}</code></td>
          <td>{{ ev.description }}</td>
          <td style="white-space:nowrap;color:var(--text2);">{{ ev.detected_at }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- ================================================================ -->
  <!-- SUBDOMAINS INVENTORY                                             -->
  <!-- ================================================================ -->
  <h2>Subdomain Inventory ({{ subdomains|length }})</h2>
  {% if subdomains %}
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>FQDN</th>
          <th>Status</th>
          <th>Classification</th>
          <th>HTTP</th>
          <th>Technologies</th>
          <th>First Seen</th>
        </tr>
      </thead>
      <tbody>
        {% for sub in subdomains %}
        <tr>
          <td><code>{{ sub.fqdn }}</code></td>
          <td><span class="status-{{ sub.status }}">{{ sub.status }}</span></td>
          <td>{{ sub.classification or '—' }}</td>
          <td>{{ sub.http_status or '—' }}</td>
          <td>
            {% if sub.technologies %}
              {% for tech in sub.technologies[:5] %}
                <code>{{ tech }}</code>{% if not loop.last %} {% endif %}
              {% endfor %}
              {% if sub.technologies|length > 5 %}
                <span style="color:var(--text2);">+{{ sub.technologies|length - 5 }} more</span>
              {% endif %}
            {% else %}—{% endif %}
          </td>
          <td style="white-space:nowrap;color:var(--text2);">{{ sub.first_seen or '—' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <p style="color:var(--text2);padding:12px 0;">No subdomains found.</p>
  {% endif %}

  <!-- ================================================================ -->
  <!-- ENDPOINTS                                                        -->
  <!-- ================================================================ -->
  <h2>Endpoints ({{ endpoints|length }})</h2>
  {% if endpoints %}
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>Subdomain</th>
          <th>Method</th>
          <th>Path</th>
          <th>Status</th>
          <th>Source</th>
          <th>First Seen</th>
        </tr>
      </thead>
      <tbody>
        {% for ep in endpoints %}
        <tr>
          <td><code>{{ ep.subdomain }}</code></td>
          <td><code style="color:var(--accent);">{{ ep.method }}</code></td>
          <td><code>{{ ep.path }}</code></td>
          <td>{{ ep.status_code or '—' }}</td>
          <td>{{ ep.source or '—' }}</td>
          <td style="white-space:nowrap;color:var(--text2);">{{ ep.first_seen or '—' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <p style="color:var(--text2);padding:12px 0;">No endpoints recorded.</p>
  {% endif %}

  <!-- ================================================================ -->
  <!-- FULL CHANGE EVENTS                                               -->
  <!-- ================================================================ -->
  <h2>All Change Events ({{ change_events|length }})</h2>
  {% if change_events %}
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Target</th>
          <th>Description</th>
          <th>Before / After</th>
          <th>Detected At</th>
          <th>Alerted</th>
        </tr>
      </thead>
      <tbody>
        {% for ev in change_events %}
        <tr class="sev-{{ ev.severity }}">
          <td><span class="badge badge-{{ ev.severity }}">{{ ev.severity }}</span></td>
          <td><code>{{ ev.event_type }}</code></td>
          <td><code>{{ ev.target }}</code></td>
          <td>{{ ev.description }}</td>
          <td>
            {% if ev.diff_data %}
            <pre class="diff">{{ ev.diff_data | tojson(indent=2) }}</pre>
            {% else %}—{% endif %}
          </td>
          <td style="white-space:nowrap;color:var(--text2);">{{ ev.detected_at or '—' }}</td>
          <td style="text-align:center;">
            {% if ev.alerted %}
            <span style="color:var(--green);">✓</span>
            {% else %}
            <span style="color:var(--text2);">—</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <p style="color:var(--text2);padding:12px 0;">No change events recorded.</p>
  {% endif %}

  <!-- footer -->
  <div class="footer">
    Generated by <span>AssetMonitor v{{ version }}</span> &mdash; {{ generated_at }}
  </div>

</div><!-- /container -->
</body>
</html>
"""


def _fmt_dt(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.isoformat()


async def generate_report(
    db: DatabaseManager,
    output_path: str,
    domain: Optional[str] = None,
) -> None:
    """Render a self-contained HTML security report and write it to disk.

    Args:
        db:          :class:`DatabaseManager` instance.
        output_path: Filesystem path for the output ``.html`` file.
        domain:      If supplied, restrict the report to this root domain.
    """
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with db.get_session() as session:
        # Domains
        if domain:
            domains: List[Domain] = list(
                session.scalars(select(Domain).where(Domain.domain == domain)).all()
            )
        else:
            domains = list(session.scalars(select(Domain)).all())

        domain_ids = {d.id for d in domains}

        # Subdomains
        if domain_ids:
            subdomains: List[Subdomain] = list(
                session.scalars(
                    select(Subdomain)
                    .where(Subdomain.domain_id.in_(domain_ids))
                    .order_by(Subdomain.status, Subdomain.fqdn)
                ).all()
            )
        else:
            subdomains = []

        subdomain_id_to_fqdn = {
            s.id: s.fqdn for s in subdomains if s.id is not None
        }
        subdomain_ids = set(subdomain_id_to_fqdn.keys())

        # Endpoints
        if subdomain_ids:
            endpoints: List[Endpoint] = list(
                session.scalars(
                    select(Endpoint).where(Endpoint.subdomain_id.in_(subdomain_ids))
                ).all()
            )
        else:
            endpoints = []

        # Assets (for summary count)
        if subdomain_ids:
            assets: List[Asset] = list(
                session.scalars(
                    select(Asset).where(Asset.subdomain_id.in_(subdomain_ids))
                ).all()
            )
        else:
            assets = []

        # Change events
        all_events: List[ChangeEvent] = list(
            session.scalars(
                select(ChangeEvent).order_by(ChangeEvent.detected_at.desc())
            ).all()
        )

        if domain:
            domain_names = {d.domain for d in domains}
            fqdns = set(subdomain_id_to_fqdn.values())
            combined = fqdns | domain_names
            change_events = [
                ev
                for ev in all_events
                if any(ev.target.endswith(f) for f in combined)
            ]
        else:
            change_events = all_events

    # --- Summary ----------------------------------------------------------
    live_count = sum(1 for s in subdomains if s.status == "alive")
    sev_counts: Dict[str, int] = {
        k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    }
    for ev in change_events:
        sev = (ev.severity or "INFO").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    summary = {
        "total_domains": len(domains),
        "total_subdomains": len(subdomains),
        "live_subdomains": live_count,
        "total_endpoints": len(endpoints),
        "total_assets": len(assets),
        "total_events": len(change_events),
        "critical_events": sev_counts["CRITICAL"],
        "high_events": sev_counts["HIGH"],
        "medium_events": sev_counts["MEDIUM"],
        "low_events": sev_counts["LOW"],
        "info_events": sev_counts["INFO"],
    }

    # --- Template context -------------------------------------------------
    critical_high = [
        ev for ev in change_events if ev.severity.upper() in ("CRITICAL", "HIGH")
    ]

    def ev_to_ctx(ev: ChangeEvent) -> Dict[str, Any]:
        return {
            "severity": ev.severity.upper(),
            "event_type": ev.event_type,
            "target": ev.target,
            "description": ev.description,
            "diff_data": ev.diff_data,
            "detected_at": _fmt_dt(ev.detected_at),
            "alerted": ev.alerted,
        }

    def sub_to_ctx(sub: Subdomain) -> Dict[str, Any]:
        return {
            "fqdn": sub.fqdn,
            "status": sub.status,
            "classification": sub.classification,
            "http_status": sub.http_status,
            "technologies": sub.technologies or [],
            "first_seen": _fmt_dt(sub.first_seen),
        }

    def ep_to_ctx(ep: Endpoint) -> Dict[str, Any]:
        return {
            "subdomain": subdomain_id_to_fqdn.get(ep.subdomain_id, "unknown"),
            "method": ep.method,
            "path": ep.path,
            "status_code": ep.status_code,
            "source": ep.source,
            "first_seen": _fmt_dt(ep.first_seen),
        }

    env = Environment(
        loader=DictLoader({"report.html": _HTML_TEMPLATE}),
        autoescape=select_autoescape(["html"]),
    )
    # Register tojson filter so the template can serialise diff_data
    import json as _json

    env.filters["tojson"] = lambda v, indent=None: _json.dumps(v, indent=indent, default=str)

    template = env.get_template("report.html")
    html = template.render(
        filter_domain=domain,
        generated_at=generated_at,
        version=_TOOL_VERSION,
        summary=summary,
        critical_high_events=[ev_to_ctx(ev) for ev in critical_high],
        subdomains=[sub_to_ctx(s) for s in subdomains],
        endpoints=[ep_to_ctx(ep) for ep in endpoints],
        change_events=[ev_to_ctx(ev) for ev in change_events],
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info(
        "HTML report generated: %s (%d subdomains, %d events)",
        output_path,
        len(subdomains),
        len(change_events),
    )
