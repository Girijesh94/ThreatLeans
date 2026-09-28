import secrets
from datetime import UTC, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import HTTPException, Request
from sqlalchemy import select

from .config import get_settings
from .store import DB, Session, User, audit, digest, now

hasher = PasswordHasher()


def bootstrap():
    s = get_settings()
    with DB.begin() as db:
        if db.scalar(select(User).where(User.username == s.admin_username)):
            return
        if s.auth_required and len(s.admin_password) < 12:
            raise RuntimeError(
                "Set THREATLEANS_ADMIN_PASSWORD to at least 12 characters before shared deployment"
            )
        if s.admin_password:
            db.add(User(username=s.admin_username, password_hash=hasher.hash(s.admin_password), role="admin"))


def login(username, password):
    with DB.begin() as db:
        u = db.scalar(select(User).where(User.username == username))
        try:
            valid = u and u.active and hasher.verify(u.password_hash, password)
        except VerificationError:
            valid = False
        if not valid:
            audit(username[:80], "login_failed")
            raise HTTPException(401, "Incorrect username or password")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        db.add(Session(token_hash=digest(token), user_id=u.id, csrf=csrf, expires=now() + timedelta(hours=8)))
        profile = {"username": u.username, "role": u.role, "csrf": csrf}
    audit(username, "login")
    return token, profile


def current(request: Request):
    if not get_settings().auth_required:
        return {"username": "local-analyst", "role": "admin", "csrf": "", "local": True}
    token = request.cookies.get("threatleans_session", "")
    with DB() as db:
        sess = db.get(Session, digest(token))
        if not sess or sess.expires.replace(tzinfo=UTC) <= now():
            raise HTTPException(401, "Sign in to continue")
        user = db.get(User, sess.user_id)
        if not user or not user.active:
            raise HTTPException(401, "Account is disabled")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), sess.csrf):
                raise HTTPException(403, "Missing or invalid CSRF token")
        return {"username": user.username, "role": user.role, "csrf": sess.csrf}


def require_admin(profile):
    if profile["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
