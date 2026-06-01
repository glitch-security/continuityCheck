"""
SQLAlchemy 2.x database layer for the asset monitoring tool.

All JSON fields are stored as TEXT columns and serialised/deserialised
transparently via a custom TypeDecorator so callers always work with
Python objects (dicts/lists) rather than raw JSON strings.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    select,
    update,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker
from sqlalchemy.types import TypeDecorator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return a timezone-aware UTC datetime."""
    return datetime.now(tz=timezone.utc)


class JSONEncodedValue(TypeDecorator):
    """Transparently stores Python dicts/lists as JSON text in the database.

    On write: serialises any Python object to a JSON string.
    On read:  deserialises the JSON string back to the original Python object.
    NULL database values are returned as None.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[str]:
        if value is None:
            return None
        return json.dumps(value, default=str)

    def process_result_value(self, value: Optional[str], dialect: Any) -> Any:
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value


# ---------------------------------------------------------------------------
# ORM base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    __allow_unmapped__ = True


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------

class Domain(Base):
    """A root domain that is being monitored."""

    __tablename__ = "domains"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    domain: str = Column(String(253), unique=True, nullable=False, index=True)
    added_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_scan: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    scan_interval_minutes: int = Column(Integer, default=360, nullable=False)

    subdomains: List["Subdomain"] = relationship(
        "Subdomain", back_populates="domain_ref", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Domain id={self.id} domain={self.domain!r}>"


class Subdomain(Base):
    """A discovered subdomain (FQDN) associated with a root domain."""

    __tablename__ = "subdomains"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    domain_id: int = Column(
        Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    fqdn: str = Column(String(253), unique=True, nullable=False, index=True)
    discovery_technique: Optional[str] = Column(String(64), nullable=True)
    first_seen: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    status: str = Column(String(32), default="unknown", nullable=False)

    # JSON columns
    ip_addresses: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    technologies: Optional[Any] = Column(JSONEncodedValue, nullable=True)

    http_status: Optional[int] = Column(Integer, nullable=True)
    page_title: Optional[str] = Column(Text, nullable=True)
    classification: Optional[str] = Column(String(64), nullable=True)
    favicon_hash: Optional[str] = Column(String(128), nullable=True)
    body_hash: Optional[str] = Column(String(128), nullable=True)
    headers_hash: Optional[str] = Column(String(128), nullable=True)
    cert_fingerprint: Optional[str] = Column(String(128), nullable=True)
    takeover_vulnerable: bool = Column(Boolean, default=False, nullable=False)
    notes: Optional[str] = Column(Text, nullable=True)

    domain_ref: "Domain" = relationship("Domain", back_populates="subdomains")
    scans: List["SubdomainScan"] = relationship(
        "SubdomainScan", back_populates="subdomain_ref", cascade="all, delete-orphan"
    )
    endpoints: List["Endpoint"] = relationship(
        "Endpoint", back_populates="subdomain_ref", cascade="all, delete-orphan"
    )
    assets: List["Asset"] = relationship(
        "Asset", back_populates="subdomain_ref", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Subdomain id={self.id} fqdn={self.fqdn!r} status={self.status!r}>"


class SubdomainScan(Base):
    """A point-in-time scan record for a subdomain."""

    __tablename__ = "subdomain_scans"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    subdomain_id: int = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scanned_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    status: str = Column(String(32), nullable=False, default="unknown")
    http_status: Optional[int] = Column(Integer, nullable=True)
    response_size: Optional[int] = Column(Integer, nullable=True)
    body_hash: Optional[str] = Column(String(128), nullable=True)

    # JSON columns
    technologies: Optional[Any] = Column(JSONEncodedValue, nullable=True)
    raw_headers: Optional[Any] = Column(JSONEncodedValue, nullable=True)

    subdomain_ref: "Subdomain" = relationship("Subdomain", back_populates="scans")

    def __repr__(self) -> str:
        return (
            f"<SubdomainScan id={self.id} subdomain_id={self.subdomain_id} "
            f"scanned_at={self.scanned_at}>"
        )


class Endpoint(Base):
    """A URL endpoint discovered within a subdomain."""

    __tablename__ = "endpoints"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    subdomain_id: int = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    path: str = Column(String(2048), nullable=False)
    method: str = Column(String(16), nullable=False, default="GET")
    content_type: Optional[str] = Column(String(128), nullable=True)
    status_code: Optional[int] = Column(Integer, nullable=True)
    first_seen: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    source: Optional[str] = Column(String(64), nullable=True)

    # JSON column
    parameters: Optional[Any] = Column(JSONEncodedValue, nullable=True)

    subdomain_ref: "Subdomain" = relationship("Subdomain", back_populates="endpoints")

    def __repr__(self) -> str:
        return (
            f"<Endpoint id={self.id} subdomain_id={self.subdomain_id} "
            f"method={self.method!r} path={self.path!r}>"
        )


class ChangeEvent(Base):
    """A detected change event for any monitored asset."""

    __tablename__ = "change_events"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    event_type: str = Column(String(64), nullable=False, index=True)
    severity: str = Column(String(16), nullable=False, index=True)
    target: str = Column(String(512), nullable=False)
    description: str = Column(Text, nullable=False)

    # JSON column
    diff_data: Optional[Any] = Column(JSONEncodedValue, nullable=True)

    detected_at: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    alerted: bool = Column(Boolean, default=False, nullable=False, index=True)
    alerted_at: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<ChangeEvent id={self.id} type={self.event_type!r} "
            f"severity={self.severity!r} target={self.target!r}>"
        )


class Asset(Base):
    """A static or dynamic asset (JS, CSS, image, etc.) linked to a subdomain."""

    __tablename__ = "assets"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    subdomain_id: int = Column(
        Integer,
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_url: str = Column(String(2048), nullable=False)
    asset_type: str = Column(String(64), nullable=False, default="unknown")
    content_hash: Optional[str] = Column(String(128), nullable=True)
    first_seen: datetime = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)
    last_changed: Optional[datetime] = Column(DateTime(timezone=True), nullable=True)

    subdomain_ref: "Subdomain" = relationship("Subdomain", back_populates="assets")

    def __repr__(self) -> str:
        return (
            f"<Asset id={self.id} subdomain_id={self.subdomain_id} "
            f"asset_type={self.asset_type!r} url={self.asset_url!r}>"
        )


# ---------------------------------------------------------------------------
# DatabaseManager
# ---------------------------------------------------------------------------

class DatabaseManager:
    """High-level interface for all database operations.

    All public methods open and close their own session internally unless
    a session is explicitly supplied via ``get_session()``.

    Args:
        db_path: Path to the SQLite database file, e.g. ``"./data/monitor.db"``.
                 Use ``":memory:"`` for an in-memory database (useful in tests).
    """

    def __init__(self, db_path: str) -> None:
        connect_args: Dict[str, Any] = {}
        if not db_path.startswith(":memory:"):
            # Enable WAL mode for better concurrent read/write performance.
            connect_args["check_same_thread"] = False

        self._engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args=connect_args,
            echo=False,
        )

        # Enable WAL journal mode and foreign-key enforcement for every
        # new SQLite connection.
        @event.listens_for(self._engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn: Any, _connection_record: Any) -> None:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)
        Base.metadata.create_all(self._engine)

    # ------------------------------------------------------------------
    # Session helper
    # ------------------------------------------------------------------

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        """Provide a transactional scope around a series of operations.

        Yields:
            An active :class:`sqlalchemy.orm.Session`.

        The session is committed on success and rolled back on any exception.
        It is always closed when the context manager exits.
        """
        session: Session = self._Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Domain operations
    # ------------------------------------------------------------------

    def add_domain(self, domain: str) -> Domain:
        """Add a new root domain to the database.

        If the domain already exists the existing record is returned without
        modification.

        Args:
            domain: The root domain name, e.g. ``"example.com"``.

        Returns:
            The :class:`Domain` ORM object (persisted).
        """
        with self.get_session() as session:
            existing = session.scalar(select(Domain).where(Domain.domain == domain))
            if existing is not None:
                return existing
            obj = Domain(domain=domain)
            session.add(obj)
            session.flush()
            # Refresh to populate auto-generated fields before the session closes.
            session.refresh(obj)
            return obj

    def get_domain(self, domain: str) -> Optional[Domain]:
        """Retrieve a root domain by its name.

        Args:
            domain: The root domain name to look up.

        Returns:
            The :class:`Domain` object or ``None`` if not found.
        """
        with self.get_session() as session:
            return session.scalar(select(Domain).where(Domain.domain == domain))

    def get_all_domains(self) -> List[Domain]:
        """Return all monitored root domains.

        Returns:
            A list of :class:`Domain` objects, possibly empty.
        """
        with self.get_session() as session:
            return list(session.scalars(select(Domain)).all())

    # ------------------------------------------------------------------
    # Subdomain operations
    # ------------------------------------------------------------------

    def upsert_subdomain(
        self, fqdn: str, domain_id: int, **kwargs: Any
    ) -> Tuple[Subdomain, bool]:
        """Insert or update a subdomain record.

        Args:
            fqdn: Fully qualified domain name, e.g. ``"api.example.com"``.
            domain_id: Foreign key referencing the parent :class:`Domain`.
            **kwargs: Any additional :class:`Subdomain` column values to set
                (e.g. ``status="alive"``, ``http_status=200``).

        Returns:
            A ``(subdomain, is_new)`` tuple where *is_new* is ``True`` when
            the record was inserted for the first time.
        """
        with self.get_session() as session:
            obj = session.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))
            is_new = obj is None

            if is_new:
                obj = Subdomain(fqdn=fqdn, domain_id=domain_id)
                session.add(obj)

            # Apply keyword arguments as attribute updates.
            for key, value in kwargs.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)

            # Always update last_seen timestamp.
            obj.last_seen = _utcnow()

            session.flush()
            session.refresh(obj)
            return obj, is_new

    def get_subdomain(self, fqdn: str) -> Optional[Subdomain]:
        """Retrieve a subdomain by its FQDN.

        Args:
            fqdn: The fully qualified domain name to look up.

        Returns:
            The :class:`Subdomain` object or ``None`` if not found.
        """
        with self.get_session() as session:
            return session.scalar(select(Subdomain).where(Subdomain.fqdn == fqdn))

    def get_live_subdomains(self, domain_id: int) -> List[Subdomain]:
        """Return all subdomains with status ``'alive'`` for a root domain.

        Args:
            domain_id: The primary key of the parent :class:`Domain`.

        Returns:
            A list of live :class:`Subdomain` objects.
        """
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(Subdomain).where(
                        Subdomain.domain_id == domain_id,
                        Subdomain.status == "alive",
                    )
                ).all()
            )

    # ------------------------------------------------------------------
    # Scan record operations
    # ------------------------------------------------------------------

    def add_scan_record(self, subdomain_id: int, **kwargs: Any) -> SubdomainScan:
        """Append a new scan record for a subdomain.

        Args:
            subdomain_id: FK referencing the scanned :class:`Subdomain`.
            **kwargs: Column values for the new :class:`SubdomainScan` row.

        Returns:
            The newly created :class:`SubdomainScan` object.
        """
        with self.get_session() as session:
            obj = SubdomainScan(subdomain_id=subdomain_id, **kwargs)
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    # ------------------------------------------------------------------
    # Endpoint operations
    # ------------------------------------------------------------------

    def upsert_endpoint(
        self, subdomain_id: int, path: str, method: str = "GET", **kwargs: Any
    ) -> Tuple[Endpoint, bool]:
        """Insert or update an endpoint record.

        Endpoints are uniquely identified by the combination of
        ``(subdomain_id, path, method)``.

        Args:
            subdomain_id: FK referencing the parent :class:`Subdomain`.
            path: URL path, e.g. ``"/api/v1/users"``.
            method: HTTP method (default ``"GET"``).
            **kwargs: Additional :class:`Endpoint` column values.

        Returns:
            A ``(endpoint, is_new)`` tuple.
        """
        with self.get_session() as session:
            obj = session.scalar(
                select(Endpoint).where(
                    Endpoint.subdomain_id == subdomain_id,
                    Endpoint.path == path,
                    Endpoint.method == method,
                )
            )
            is_new = obj is None

            if is_new:
                obj = Endpoint(subdomain_id=subdomain_id, path=path, method=method)
                session.add(obj)

            for key, value in kwargs.items():
                if hasattr(obj, key):
                    setattr(obj, key, value)

            obj.last_seen = _utcnow()

            session.flush()
            session.refresh(obj)
            return obj, is_new

    def get_endpoints(self, subdomain_id: int) -> List[Endpoint]:
        """Return all endpoints for a subdomain.

        Args:
            subdomain_id: The primary key of the parent :class:`Subdomain`.

        Returns:
            A list of :class:`Endpoint` objects.
        """
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(Endpoint).where(Endpoint.subdomain_id == subdomain_id)
                ).all()
            )

    # ------------------------------------------------------------------
    # Change event operations
    # ------------------------------------------------------------------

    def add_change_event(
        self,
        event_type: str,
        severity: str,
        target: str,
        description: str,
        diff_data: Optional[Any] = None,
    ) -> ChangeEvent:
        """Record a newly detected change event.

        Args:
            event_type: Short event category, e.g. ``"NEW_SUBDOMAIN"``.
            severity: ``"INFO"``, ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``,
                      or ``"CRITICAL"``.
            target: The FQDN or URL that changed.
            description: Human-readable description of what changed.
            diff_data: Arbitrary dict/list with structured diff information.

        Returns:
            The persisted :class:`ChangeEvent` object.
        """
        with self.get_session() as session:
            obj = ChangeEvent(
                event_type=event_type,
                severity=severity,
                target=target,
                description=description,
                diff_data=diff_data,
            )
            session.add(obj)
            session.flush()
            session.refresh(obj)
            return obj

    def get_unalerted_events(self) -> List[ChangeEvent]:
        """Return all change events that have not yet been sent as alerts.

        Returns:
            A list of :class:`ChangeEvent` objects with ``alerted=False``,
            ordered oldest-first.
        """
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(ChangeEvent)
                    .where(ChangeEvent.alerted == False)  # noqa: E712
                    .order_by(ChangeEvent.detected_at)
                ).all()
            )

    def mark_events_alerted(self, event_ids: List[int]) -> None:
        """Mark a batch of change events as alerted.

        Args:
            event_ids: Primary keys of the :class:`ChangeEvent` rows to update.
        """
        if not event_ids:
            return
        now = _utcnow()
        with self.get_session() as session:
            session.execute(
                update(ChangeEvent)
                .where(ChangeEvent.id.in_(event_ids))
                .values(alerted=True, alerted_at=now)
            )

    # ------------------------------------------------------------------
    # Asset operations
    # ------------------------------------------------------------------

    def upsert_asset(
        self,
        subdomain_id: int,
        asset_url: str,
        asset_type: str,
        content_hash: Optional[str],
    ) -> Tuple[Asset, bool]:
        """Insert or update an asset record, tracking content-hash changes.

        Assets are uniquely identified by ``(subdomain_id, asset_url)``.

        Args:
            subdomain_id: FK referencing the parent :class:`Subdomain`.
            asset_url: Absolute URL of the asset.
            asset_type: MIME category or file extension hint, e.g. ``"js"``.
            content_hash: Hash of the asset body (``None`` if unavailable).

        Returns:
            A ``(asset, changed)`` tuple where *changed* is ``True`` when the
            ``content_hash`` differs from the previously stored value.
        """
        now = _utcnow()
        with self.get_session() as session:
            obj = session.scalar(
                select(Asset).where(
                    Asset.subdomain_id == subdomain_id,
                    Asset.asset_url == asset_url,
                )
            )

            if obj is None:
                obj = Asset(
                    subdomain_id=subdomain_id,
                    asset_url=asset_url,
                    asset_type=asset_type,
                    content_hash=content_hash,
                    last_seen=now,
                )
                session.add(obj)
                session.flush()
                session.refresh(obj)
                return obj, False  # brand-new asset — not a "change" per se

            changed = obj.content_hash != content_hash
            obj.asset_type = asset_type
            obj.last_seen = now

            if changed:
                obj.content_hash = content_hash
                obj.last_changed = now

            session.flush()
            session.refresh(obj)
            return obj, changed

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_recent_events(self, hours: int = 24) -> List[ChangeEvent]:
        """Return change events detected within the last *hours* hours.

        Args:
            hours: Look-back window in hours (default 24).

        Returns:
            A list of :class:`ChangeEvent` objects ordered newest-first.
        """
        from datetime import timedelta

        cutoff = _utcnow() - timedelta(hours=hours)
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(ChangeEvent)
                    .where(ChangeEvent.detected_at >= cutoff)
                    .order_by(ChangeEvent.detected_at.desc())
                ).all()
            )

    def get_events_by_severity(self, severity: str) -> List[ChangeEvent]:
        """Return all change events matching a specific severity level.

        Args:
            severity: One of ``"INFO"``, ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``,
                      ``"CRITICAL"`` (case-insensitive).

        Returns:
            A list of matching :class:`ChangeEvent` objects, newest-first.
        """
        with self.get_session() as session:
            return list(
                session.scalars(
                    select(ChangeEvent)
                    .where(ChangeEvent.severity == severity.upper())
                    .order_by(ChangeEvent.detected_at.desc())
                ).all()
            )
