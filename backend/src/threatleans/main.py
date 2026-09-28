import asyncio
import json
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import Counter, Histogram, generate_latest
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .auth import bootstrap, current, hasher, login, require_admin
from .config import ROOT, get_settings
from .gateway import providers
from .ingest import FEEDS, ingest_source
from .pipeline import investigate
from .retrieval import retriever
from .store import (
    DB,
    Audit,
    Document,
    Ingestion,
    Investigation,
    Session,
    User,
    audit,
    digest,
    initialize,
)

settings = get_settings()
queries = Counter("threatleans_queries_total", "Completed investigations", ["status"])
latency = Histogram("threatleans_query_seconds", "Investigation duration")
limits = defaultdict(deque)
ingest_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(app):
    initialize()
    bootstrap()
    await asyncio.to_thread(retriever.refresh)
    yield


app = FastAPI(title="ThreatLeans SOC API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


@app.middleware("http")
async def headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'"
    )
    if request.url.path in {"/docs", "/redoc"}:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; frame-ancestors 'none'"
        )
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"
    return response


def rate_limit(key, maximum, window=60):
    queue = limits[key]
    tick = time.monotonic()
    while queue and queue[0] < tick - window:
        queue.popleft()
    if len(queue) >= maximum:
        raise HTTPException(429, "Too many requests. Try again shortly.")
    queue.append(tick)


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class UserCreate(Credentials):
    role: Literal["admin", "analyst", "reviewer"] = "analyst"


class Query(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    provider: Literal["evidence", "openai", "anthropic", "ollama"] = "evidence"
    online: bool = False
    share_external: bool = False


class Review(BaseModel):
    status: Literal["pending", "approved", "rejected"]
    note: str = Field(default="", max_length=4000)


@app.get("/api/health")
def health():
    with DB() as db:
        count = db.scalar(select(func.count()).select_from(Document))
    return {
        "status": "ok",
        "name": "ThreatLeans",
        "documents": count,
        "retrieval_mode": retriever.mode,
        "dense_error": retriever.error,
        "auth_required": settings.auth_required,
    }


@app.get("/api/public/demo")
async def public_demo(example: Literal["vulnerability", "technique", "group"] = "vulnerability"):
    # Public samples are fixed public entities: no saved cases, private questions or AI calls.
    question = {"vulnerability": "CVE-2021-44228", "technique": "T1566", "group": "G0016"}[example]
    return await investigate(question, provider="evidence", online=False)


@app.post("/api/auth/login")
def sign_in(body: Credentials, request: Request, response: Response):
    rate_limit("login:" + (request.client.host if request.client else "unknown"), 10, 300)
    token, profile = login(body.username, body.password)
    response.set_cookie(
        "threatleans_session",
        token,
        httponly=True,
        samesite="strict",
        max_age=28800,
        secure=settings.cookie_secure or request.url.scheme == "https",
    )
    return profile


@app.get("/api/auth/me")
def me(profile=Depends(current)):
    return profile


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, profile=Depends(current)):
    with DB.begin() as db:
        sess = db.get(Session, digest(request.cookies.get("threatleans_session", "")))
        if sess:
            db.delete(sess)
    response.delete_cookie("threatleans_session")
    audit(profile["username"], "logout")
    return {"ok": True}


@app.get("/api/overview")
def overview(profile=Depends(current)):
    with DB() as db:
        counts = dict(db.execute(select(Document.kind, func.count()).group_by(Document.kind)).all())
        sources = dict(db.execute(select(Document.source, func.count()).group_by(Document.source)).all())
        pending = db.scalar(
            select(func.count()).select_from(Investigation).where(Investigation.review_status == "pending")
        )
        recent = db.scalars(
            select(Investigation)
            .where(Investigation.owner == profile["username"])
            .order_by(Investigation.created_at.desc())
            .limit(5)
        ).all()
    return {
        "counts": counts,
        "sources": sources,
        "pending_reviews": pending,
        "recent": [serialize(i) for i in recent],
        "retrieval_mode": retriever.mode,
        "providers": providers(),
    }


def serialize(i):
    return {
        "id": i.id,
        "owner": i.owner,
        "question": i.question,
        "status": i.status,
        "created_at": i.created_at.isoformat(),
        "review_status": i.review_status,
        "review_note": i.review_note,
        "reviewer": i.reviewer,
        "result": i.result,
    }


@app.post("/api/investigate")
async def run_query(body: Query, profile=Depends(current)):
    rate_limit("query:" + profile["username"], 15)
    if body.provider in {"openai", "anthropic"} and not body.share_external:
        raise HTTPException(
            400, "Confirm sharing this question and public evidence with the external AI provider"
        )
    with DB.begin() as db:
        inv = Investigation(owner=profile["username"], question=body.question)
        db.add(inv)
    start = time.monotonic()
    try:
        await asyncio.to_thread(retriever.ensure_fresh)
        result = await asyncio.wait_for(
            investigate(body.question, body.provider, body.online), timeout=settings.query_deadline_seconds
        )
        with DB.begin() as db:
            saved = db.get(Investigation, inv.id)
            saved.result, saved.status = result, result["status"]
            if result["status"] != "supported":
                saved.review_status = "pending"
        queries.labels(result["status"]).inc()
    except Exception as exc:
        with DB.begin() as db:
            saved = db.get(Investigation, inv.id)
            saved.status, saved.review_status = "failed", "pending"
            saved.result = {
                "error": "Investigation did not complete; retry or request review.",
                "error_type": type(exc).__name__,
            }
        raise HTTPException(503, "Investigation timed out or failed. It has been saved for review.") from exc
    finally:
        latency.observe(time.monotonic() - start)
    audit(
        profile["username"],
        "investigation",
        {"id": inv.id, "provider": body.provider, "status": result["status"]},
    )
    with DB() as db:
        return serialize(db.get(Investigation, inv.id))


@app.get("/api/library")
def library(q: str = "", kind: str = "", source: str = "", page: int = 1, profile=Depends(current)):
    page = max(1, min(page, 10000))
    with DB() as db:
        stmt = select(Document)
        if q:
            stmt = stmt.where(
                (Document.title.ilike("%" + q[:200] + "%")) | (Document.text.ilike("%" + q[:200] + "%"))
            )
        if kind:
            stmt = stmt.where(Document.kind == kind)
        if source:
            stmt = stmt.where(Document.source == source)
        total = db.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = db.scalars(stmt.order_by(Document.id).offset((page - 1) * 30).limit(30)).all()
    return {
        "total": total,
        "page": page,
        "items": [
            {
                "id": d.id,
                "title": d.title,
                "kind": d.kind,
                "source": d.source,
                "url": d.url,
                "text": d.text,
                "facts": d.facts,
                "fetched_at": d.fetched_at.isoformat(),
                "sha256": d.sha256,
            }
            for d in rows
        ],
    }


@app.get("/api/history")
def history(profile=Depends(current)):
    with DB() as db:
        rows = db.scalars(
            select(Investigation)
            .where(Investigation.owner == profile["username"])
            .order_by(Investigation.created_at.desc())
            .limit(100)
        ).all()
    return [serialize(i) for i in rows]


@app.get("/api/reviews")
def reviews(profile=Depends(current)):
    if profile["role"] not in {"admin", "reviewer"}:
        raise HTTPException(403, "Reviewer access required")
    with DB() as db:
        rows = db.scalars(
            select(Investigation)
            .where(Investigation.review_status != "none")
            .order_by(Investigation.created_at.desc())
            .limit(100)
        ).all()
    return [serialize(i) for i in rows]


@app.post("/api/investigations/{identifier}/review")
def review(identifier: str, body: Review, profile=Depends(current)):
    with DB.begin() as db:
        inv = db.get(Investigation, identifier)
        if not inv:
            raise HTTPException(404, "Investigation not found")
        if body.status == "pending":
            if inv.owner != profile["username"] and profile["role"] not in {"admin", "reviewer"}:
                raise HTTPException(403, "Access denied")
        elif profile["role"] not in {"admin", "reviewer"}:
            raise HTTPException(403, "Reviewer access required")
        inv.review_status, inv.review_note = body.status, body.note
        inv.reviewer = profile["username"] if body.status != "pending" else ""
    audit(profile["username"], "review", {"id": identifier, "status": body.status, "note": body.note})
    return {"ok": True}


@app.get("/api/investigations/{identifier}/export")
def export(identifier: str, profile=Depends(current)):
    with DB() as db:
        inv = db.get(Investigation, identifier)
        if not inv:
            raise HTTPException(404, "Investigation not found")
        if inv.owner != profile["username"] and profile["role"] not in {"admin", "reviewer"}:
            raise HTTPException(403, "Access denied")
        content = json.dumps(serialize(inv), indent=2, ensure_ascii=False)
    audit(profile["username"], "export", {"id": identifier})
    return Response(
        content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="threatleans-{identifier}.json"'},
    )


@app.get("/api/sources")
def sources(profile=Depends(current)):
    with DB() as db:
        rows = db.scalars(select(Ingestion).order_by(Ingestion.created_at.desc()).limit(30)).all()
        totals = dict(db.execute(select(Document.source, func.count()).group_by(Document.source)).all())
    return {
        "feeds": [{"id": k, "url": v} for k, v in FEEDS.items()],
        "totals": totals,
        "runs": [
            {
                "id": r.id,
                "source": r.source,
                "status": r.status,
                "count": r.count,
                "error": r.error,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }


@app.post("/api/sources/{source}/refresh")
async def refresh(source: str, profile=Depends(current)):
    require_admin(profile)
    if source not in FEEDS:
        raise HTTPException(404, "Unknown source")
    if ingest_lock.locked():
        raise HTTPException(409, "Another source refresh is running")
    async with ingest_lock:
        try:
            result = await ingest_source(source)
            await asyncio.to_thread(retriever.refresh)
        except Exception as exc:
            raise HTTPException(502, "Feed refresh failed; inspect the source run log") from exc
    audit(profile["username"], "source_refresh", result)
    return result


@app.get("/api/settings")
def config(profile=Depends(current)):
    return {
        "providers": providers(),
        "auth_required": settings.auth_required,
        "retrieval_mode": retriever.mode,
        "dense_enabled": settings.dense_enabled,
        "dense_error": retriever.error,
        "embedding_model": settings.embedding_model,
        "history_retention_days": settings.history_retention_days,
        "deployment": "shared SOC" if settings.auth_required else "local workspace",
    }


@app.get("/api/admin/users")
def users(profile=Depends(current)):
    require_admin(profile)
    with DB() as db:
        return [
            {"id": u.id, "username": u.username, "role": u.role, "active": u.active}
            for u in db.scalars(select(User).order_by(User.username))
        ]


@app.post("/api/admin/users")
def create_user(body: UserCreate, profile=Depends(current)):
    require_admin(profile)
    if len(body.password) < 12:
        raise HTTPException(400, "Password must have at least 12 characters")
    with DB.begin() as db:
        if db.scalar(select(User).where(User.username == body.username)):
            raise HTTPException(409, "Username already exists")
        db.add(User(username=body.username, password_hash=hasher.hash(body.password), role=body.role))
    audit(profile["username"], "user_created", {"username": body.username, "role": body.role})
    return {"ok": True}


@app.post("/api/admin/users/{identifier}/disable")
def disable_user(identifier: str, profile=Depends(current)):
    require_admin(profile)
    with DB.begin() as db:
        user = db.get(User, identifier)
        if not user:
            raise HTTPException(404, "Account not found")
        if user.username == profile["username"]:
            raise HTTPException(400, "You cannot disable your own account")
        user.active = False
    audit(profile["username"], "user_disabled", {"id": identifier})
    return {"ok": True}


@app.get("/api/admin/audit")
def audit_log(profile=Depends(current)):
    require_admin(profile)
    with DB() as db:
        return [
            {"actor": a.actor, "action": a.action, "detail": a.detail, "created_at": a.created_at.isoformat()}
            for a in db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(200))
        ]


@app.get("/api/metrics")
def metrics(profile=Depends(current)):
    require_admin(profile)
    return Response(generate_latest(), media_type="text/plain")


dist = ROOT / "frontend" / "dist"
if dist.exists():
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{path:path}")
    def frontend(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "Endpoint not found")
        asset = (dist / path).resolve()
        if asset.is_relative_to(dist.resolve()) and asset.is_file():
            return FileResponse(asset)
        return FileResponse(dist / "index.html")
