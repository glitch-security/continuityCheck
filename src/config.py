"""
Configuration loader for the asset monitoring tool.

Reads a YAML file and validates it with Pydantic v2 models, supplying
sensible defaults for every optional field.
"""

from __future__ import annotations

import os
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanConfig(BaseModel):
    interval_minutes: int = 360
    concurrent_threads: int = 10
    request_timeout_seconds: int = 10
    user_agent: str = (
        "Mozilla/5.0 (compatible; AssetMonitor/1.0; +https://github.com/asset-monitor)"
    )
    respect_robots_txt: bool = False
    max_crawl_depth: int = 3
    max_pages_per_domain: int = 500


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

class EnumerationTechniques(BaseModel):
    certificate_transparency: bool = True
    dns_bruteforce: bool = True
    passive_dns: bool = True
    wayback_machine: bool = True
    search_engine_dorking: bool = False
    ssl_san_extraction: bool = True
    js_analysis: bool = True
    zone_transfer: bool = True
    reverse_ip: bool = True


class EnumerationConfig(BaseModel):
    techniques: EnumerationTechniques = Field(default_factory=EnumerationTechniques)
    wordlist_path: str = "./wordlists/subdomains.txt"
    dns_resolvers: List[str] = Field(
        default_factory=lambda: [
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
            "9.9.9.9",
        ]
    )
    max_dns_concurrent: int = 50


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class VerificationConfig(BaseModel):
    ports: List[int] = Field(default_factory=lambda: [80, 443, 8080, 8443, 8888])
    takeover_check: bool = True
    technology_detection: bool = True
    screenshot: bool = False


# ---------------------------------------------------------------------------
# Change detection / monitoring
# ---------------------------------------------------------------------------

class ChangeDetectionConfig(BaseModel):
    content_hash: bool = True
    dom_structural_diff: bool = True
    endpoint_inventory: bool = True
    technology_stack: bool = True
    response_size_anomaly: bool = True
    asset_tracking: bool = True
    visual_diff: bool = False


class MonitoringConfig(BaseModel):
    change_detection: ChangeDetectionConfig = Field(
        default_factory=ChangeDetectionConfig
    )


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

class ApiKeysConfig(BaseModel):
    virustotal: str = ""
    securitytrails: str = ""
    shodan: str = ""
    censys_id: str = ""
    censys_secret: str = ""


# ---------------------------------------------------------------------------
# Notification channels
# ---------------------------------------------------------------------------

class SlackConfig(BaseModel):
    enabled: bool = False
    webhook_url: str = ""
    channel: str = "#security-alerts"
    username: str = "AssetMonitor"
    icon_emoji: str = ":shield:"


class TelegramConfig(BaseModel):
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


class DiscordConfig(BaseModel):
    enabled: bool = False
    webhook_url: str = ""
    username: str = "AssetMonitor"


class EmailConfig(BaseModel):
    enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    use_tls: bool = True
    from_address: str = ""
    to_addresses: List[str] = Field(default_factory=list)
    subject_prefix: str = "[AssetMonitor]"


class WebhookConfig(BaseModel):
    enabled: bool = False
    url: str = ""
    method: str = "POST"
    headers: dict = Field(default_factory=dict)
    secret: str = ""


class NotificationsConfig(BaseModel):
    slack: SlackConfig = Field(default_factory=SlackConfig)
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)
    discord: DiscordConfig = Field(default_factory=DiscordConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    min_severity: str = "MEDIUM"


# ---------------------------------------------------------------------------
# Root application config
# ---------------------------------------------------------------------------

class AppConfig(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    enumeration: EnumerationConfig = Field(default_factory=EnumerationConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    api_keys: ApiKeysConfig = Field(default_factory=ApiKeysConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(path: str) -> AppConfig:
    """Load and validate the application configuration from a YAML file.

    Args:
        path: Filesystem path to the YAML configuration file.

    Returns:
        A fully-validated :class:`AppConfig` instance.

    Raises:
        FileNotFoundError: If *path* does not point to an existing file.
        ValueError: If the YAML content cannot be validated against the schema.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Configuration file not found: '{path}'. "
            "Please create the file or pass the correct path with --config."
        )

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    # yaml.safe_load returns None for an empty file — treat that as empty dict.
    if raw is None:
        raw = {}

    if not isinstance(raw, dict):
        raise ValueError(
            f"Configuration file '{path}' must contain a YAML mapping at the top "
            f"level, but got {type(raw).__name__}."
        )

    return AppConfig.model_validate(raw)
