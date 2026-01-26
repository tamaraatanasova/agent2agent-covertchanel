from __future__ import annotations

import hmac
import os
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Optional
from uuid import uuid4

import hashlib


@dataclass(frozen=True)
class AuthUser:
    user_id: str
    username: str
    display_name: str
    created_at: str


@dataclass
class AuthSession:
    token: str
    user: AuthUser
    created_at: datetime
    expires_at: Optional[datetime]


class AuthStore:
    def __init__(self) -> None:
        self._db_path = Path(os.getenv("AUTH_DB_PATH", os.path.join("data", "auth.sqlite")))

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), timeout=3.0)
        conn.row_factory = sqlite3.Row
        self._ensure_schema(conn)
        return conn

    @staticmethod
    def _ensure_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              username TEXT NOT NULL UNIQUE,
              display_name TEXT NOT NULL,
              password_hash TEXT NOT NULL,
              password_salt TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000).hex()

    @staticmethod
    def _verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
        salt = bytes.fromhex(salt_hex)
        candidate = AuthStore._hash_password(password, salt)
        return hmac.compare_digest(candidate, stored_hash)

    @staticmethod
    def _normalize_username(username: str) -> str:
        return (username or "").strip().lower()

    def create_user(self, *, username: str, password: str, display_name: str | None = None) -> AuthUser:
        uname = self._normalize_username(username)
        if not uname:
            raise ValueError("username is required")
        if not password:
            raise ValueError("password is required")
        display = (display_name or "").strip() or uname

        user_id = str(uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        salt = secrets.token_bytes(16).hex()
        pw_hash = self._hash_password(password, bytes.fromhex(salt))

        with self._connect() as conn:
            with conn:
                conn.execute(
                    "INSERT INTO users (id, username, display_name, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, uname, display, pw_hash, salt, created_at),
                )
        return AuthUser(user_id=user_id, username=uname, display_name=display, created_at=created_at)

    def authenticate(self, *, username: str, password: str) -> AuthUser | None:
        uname = self._normalize_username(username)
        if not uname or not password:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, username, display_name, password_hash, password_salt, created_at FROM users WHERE username = ?",
                (uname,),
            ).fetchone()
        if row is None:
            return None
        if not self._verify_password(password, str(row["password_salt"]), str(row["password_hash"])):
            return None
        return AuthUser(
            user_id=str(row["id"]),
            username=str(row["username"]),
            display_name=str(row["display_name"]),
            created_at=str(row["created_at"]),
        )

    def get_user(self, user_id: str) -> AuthUser | None:
        if not user_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, username, display_name, created_at FROM users WHERE id = ?",
                (str(user_id),),
            ).fetchone()
        if row is None:
            return None
        return AuthUser(
            user_id=str(row["id"]),
            username=str(row["username"]),
            display_name=str(row["display_name"]),
            created_at=str(row["created_at"]),
        )


class AuthSessions:
    def __init__(self, *, ttl_hours: int = 24) -> None:
        self._lock = Lock()
        self._sessions: dict[str, AuthSession] = {}
        self._ttl = timedelta(hours=ttl_hours) if ttl_hours > 0 else None

    def create(self, user: AuthUser) -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = (now + self._ttl) if self._ttl is not None else None
        with self._lock:
            self._sessions[token] = AuthSession(token=token, user=user, created_at=now, expires_at=expires_at)
        return token

    def get(self, token: str | None) -> AuthUser | None:
        if not token:
            return None
        with self._lock:
            sess = self._sessions.get(token)
            if sess is None:
                return None
            if sess.expires_at and sess.expires_at <= datetime.now(timezone.utc):
                self._sessions.pop(token, None)
                return None
            return sess.user

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)
