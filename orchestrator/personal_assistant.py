from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4


def parse_day(value: str | None, *, today: date | None = None) -> date:
    """
    Parses a day value. Supported inputs:
      - None/""/"today"
      - "tomorrow"
      - "YYYY-MM-DD"
    """

    if today is None:
        today = datetime.now().astimezone().date()
    v = (value or "").strip().lower()
    if not v or v == "today":
        return today
    if v == "tomorrow":
        return today + timedelta(days=1)
    try:
        return date.fromisoformat(v)
    except Exception:
        return today


@dataclass(frozen=True)
class CalendarItem:
    item_id: str
    day: str  # YYYY-MM-DD
    title: str
    time: str | None = None  # HH:MM (24h) or None

    def display(self) -> str:
        if self.time:
            return f"{self.time} — {self.title}"
        return self.title

    def model_dump(self) -> dict[str, Any]:
        return {"id": self.item_id, "day": self.day, "time": self.time, "title": self.title}


class CalendarStore:
    def __init__(self) -> None:
        self._db_path = Path(os.getenv("CALENDAR_DB_PATH", os.path.join("data", "calendar.sqlite")))

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
            CREATE TABLE IF NOT EXISTS calendar_items (
              id TEXT PRIMARY KEY,
              user TEXT NOT NULL,
              day TEXT NOT NULL,
              time TEXT,
              title TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_calendar_user_day ON calendar_items(user, day)")

    @staticmethod
    def _order_by_sql() -> str:
        # Sort by time (nulls last), then stable insertion time.
        return "CASE WHEN time IS NULL OR time = '' THEN 1 ELSE 0 END, time, created_at"

    def list_day(self, *, user: str, day: date) -> list[CalendarItem]:
        key = day.isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT id, day, title, time FROM calendar_items WHERE user = ? AND day = ? ORDER BY {self._order_by_sql()}",
                (str(user), key),
            ).fetchall()
        return [CalendarItem(item_id=str(r["id"]), day=str(r["day"]), title=str(r["title"]), time=(str(r["time"]) if r["time"] else None)) for r in rows]

    def add_item(self, *, user: str, day: date, title: str, time: str | None) -> CalendarItem:
        key = day.isoformat()
        title = str(title or "").strip()
        if not title:
            raise ValueError("title is required")
        item = CalendarItem(
            item_id=str(uuid4()),
            day=key,
            title=title,
            time=(time.strip() if isinstance(time, str) and time.strip() else None),
        )
        created_at = datetime.now().astimezone().isoformat()
        with self._connect() as conn:
            with conn:
                conn.execute(
                    "INSERT INTO calendar_items (id, user, day, time, title, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (item.item_id, str(user), key, item.time, item.title, created_at),
                )
        return item

    def delete_index(self, *, user: str, day: date, index_1based: int) -> CalendarItem | None:
        if index_1based < 1:
            return None
        key = day.isoformat()
        offset = index_1based - 1
        with self._connect() as conn:
            with conn:
                row = conn.execute(
                    f"SELECT id, day, title, time FROM calendar_items WHERE user = ? AND day = ? ORDER BY {self._order_by_sql()} LIMIT 1 OFFSET ?",
                    (str(user), key, offset),
                ).fetchone()
                if row is None:
                    return None
                conn.execute("DELETE FROM calendar_items WHERE id = ?", (str(row["id"]),))
        return CalendarItem(item_id=str(row["id"]), day=str(row["day"]), title=str(row["title"]), time=(str(row["time"]) if row["time"] else None))

    def clear_day(self, *, user: str, day: date) -> int:
        key = day.isoformat()
        with self._connect() as conn:
            with conn:
                cur = conn.execute("DELETE FROM calendar_items WHERE user = ? AND day = ?", (str(user), key))
                return int(cur.rowcount or 0)

    def update_index(
        self,
        *,
        user: str,
        day: date,
        index_1based: int,
        title: str | None = None,
        time: str | None = None,
    ) -> CalendarItem | None:
        if index_1based < 1:
            return None
        key = day.isoformat()
        offset = index_1based - 1
        with self._connect() as conn:
            with conn:
                row = conn.execute(
                    f"SELECT id, day, title, time FROM calendar_items WHERE user = ? AND day = ? ORDER BY {self._order_by_sql()} LIMIT 1 OFFSET ?",
                    (str(user), key, offset),
                ).fetchone()
                if row is None:
                    return None

                new_title = str(row["title"]) if title is None else str(title).strip()
                if not new_title:
                    return None
                new_time = (str(row["time"]) if row["time"] else None) if time is None else (time.strip() if isinstance(time, str) and time.strip() else None)

                conn.execute(
                    "UPDATE calendar_items SET title = ?, time = ? WHERE id = ?",
                    (new_title, new_time, str(row["id"])),
                )
        return CalendarItem(item_id=str(row["id"]), day=str(row["day"]), title=new_title, time=new_time)

    def search(self, *, user: str, query: str) -> list[dict[str, Any]]:
        q = str(query or "").strip().lower()
        if not q:
            return []

        like = f"%{q}%"
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                  day,
                  id,
                  time,
                  title,
                  ROW_NUMBER() OVER (PARTITION BY day ORDER BY {self._order_by_sql()}) AS idx
                FROM calendar_items
                WHERE user = ? AND LOWER(title) LIKE ?
                ORDER BY day DESC, idx ASC
                LIMIT 50
                """,
                (str(user), like),
            ).fetchall()
        return [
            {
                "day": str(r["day"]),
                "index": int(r["idx"]),
                "item": {"id": str(r["id"]), "day": str(r["day"]), "time": (str(r["time"]) if r["time"] else None), "title": str(r["title"])},
            }
            for r in rows
        ]


calendar_store = CalendarStore()
