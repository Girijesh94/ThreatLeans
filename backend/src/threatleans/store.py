"""Durable SOC records and transactions shared by the API and ingestion worker."""

import hashlib
import secrets
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import get_settings


def now():
    return datetime.now(UTC)


def uid():
    return secrets.token_hex(12)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    csrf: Mapped[str] = mapped_column(String(64))
    expires: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(180), primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    url: Mapped[str] = mapped_column(Text)
    text: Mapped[str] = mapped_column(Text)
    facts: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256: Mapped[str] = mapped_column(String(64))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    owner: Mapped[str] = mapped_column(String(80), index=True)
    question: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="running")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    review_status: Mapped[str] = mapped_column(String(30), default="none")
    review_note: Mapped[str] = mapped_column(Text, default="")
    reviewer: Mapped[str] = mapped_column(String(80), default="")


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Ingestion(Base):
    __tablename__ = "ingestions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    source: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30))
    count: Mapped[int] = mapped_column(default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


settings = get_settings()
settings.resolved_data_dir.joinpath("runtime").mkdir(parents=True, exist_ok=True)
engine = create_engine(
    settings.resolved_database_url,
    connect_args={"check_same_thread": False} if settings.resolved_database_url.startswith("sqlite") else {},
    pool_pre_ping=True,
)
DB = sessionmaker(engine, expire_on_commit=False)


def initialize():
    Base.metadata.create_all(engine)


def digest(value: str):
    return hashlib.sha256(value.encode()).hexdigest()


def audit(actor, action, detail=None):
    with DB.begin() as db:
        db.add(Audit(actor=actor, action=action, detail=detail or {}))


def documents():
    with DB() as db:
        return list(db.scalars(select(Document).order_by(Document.id)))
