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
    duration_minutes: int | None = None

    def display(self) -> str:
        if self.time:
            if self.duration_minutes:
                end = self._calc_end_time()
                if end:
                    return f"{self.time}–{end} ({self.duration_minutes}m) — {self.title}"
                return f"{self.time} ({self.duration_minutes}m) — {self.title}"
            return f"{self.time} — {self.title}"
        return self.title

    def _calc_end_time(self) -> str | None:
        if not self.time or not self.duration_minutes:
            return None
        try:
            h, m = self.time.split(":", 1)
            start = int(h) * 60 + int(m)
            end = (start + int(self.duration_minutes)) % (24 * 60)
            eh = end // 60
            em = end % 60
            return f"{eh:02d}:{em:02d}"
        except Exception:
            return None

    def model_dump(self) -> dict[str, Any]:
        return {
            "id": self.item_id,
            "day": self.day,
            "time": self.time,
            "title": self.title,
            "duration_minutes": self.duration_minutes,
        }


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
              duration_minutes INTEGER,
              title TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_calendar_user_day ON calendar_items(user, day)")
        try:
            conn.execute("ALTER TABLE calendar_items ADD COLUMN duration_minutes INTEGER")
        except sqlite3.OperationalError:
            pass

    @staticmethod
    def _order_by_sql() -> str:
        # Sort by time (nulls last), then stable insertion time.
        return "CASE WHEN time IS NULL OR time = '' THEN 1 ELSE 0 END, time, created_at"

    def list_day(self, *, user: str, day: date) -> list[CalendarItem]:
        key = day.isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT id, day, title, time, duration_minutes FROM calendar_items WHERE user = ? AND day = ? ORDER BY {self._order_by_sql()}",
                (str(user), key),
            ).fetchall()
        return [
            CalendarItem(
                item_id=str(r["id"]),
                day=str(r["day"]),
                title=str(r["title"]),
                time=(str(r["time"]) if r["time"] else None),
                duration_minutes=(int(r["duration_minutes"]) if r["duration_minutes"] is not None else None),
            )
            for r in rows
        ]

    def list_range(self, *, user: str, start: date, end: date) -> list[CalendarItem]:
        start_key = start.isoformat()
        end_key = end.isoformat()
        if end_key < start_key:
            start_key, end_key = end_key, start_key
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, day, title, time, duration_minutes
                FROM calendar_items
                WHERE user = ? AND day BETWEEN ? AND ?
                ORDER BY day, {self._order_by_sql()}
                """,
                (str(user), start_key, end_key),
            ).fetchall()
        return [
            CalendarItem(
                item_id=str(r["id"]),
                day=str(r["day"]),
                title=str(r["title"]),
                time=(str(r["time"]) if r["time"] else None),
                duration_minutes=(int(r["duration_minutes"]) if r["duration_minutes"] is not None else None),
            )
            for r in rows
        ]

    def add_item(self, *, user: str, day: date, title: str, time: str | None, duration_minutes: int | None = None) -> CalendarItem:
        key = day.isoformat()
        title = str(title or "").strip()
        if not title:
            raise ValueError("title is required")
        if duration_minutes is not None:
            duration_minutes = max(1, min(24 * 60, int(duration_minutes)))
        item = CalendarItem(
            item_id=str(uuid4()),
            day=key,
            title=title,
            time=(time.strip() if isinstance(time, str) and time.strip() else None),
            duration_minutes=duration_minutes,
        )
        created_at = datetime.now().astimezone().isoformat()
        with self._connect() as conn:
            with conn:
                conn.execute(
                    "INSERT INTO calendar_items (id, user, day, time, duration_minutes, title, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (item.item_id, str(user), key, item.time, item.duration_minutes, item.title, created_at),
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
                    f"SELECT id, day, title, time, duration_minutes FROM calendar_items WHERE user = ? AND day = ? ORDER BY {self._order_by_sql()} LIMIT 1 OFFSET ?",
                    (str(user), key, offset),
                ).fetchone()
                if row is None:
                    return None
                conn.execute("DELETE FROM calendar_items WHERE id = ?", (str(row["id"]),))
        return CalendarItem(
            item_id=str(row["id"]),
            day=str(row["day"]),
            title=str(row["title"]),
            time=(str(row["time"]) if row["time"] else None),
            duration_minutes=(int(row["duration_minutes"]) if row["duration_minutes"] is not None else None),
        )

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
        duration_minutes: int | None = None,
    ) -> CalendarItem | None:
        if index_1based < 1:
            return None
        key = day.isoformat()
        offset = index_1based - 1
        with self._connect() as conn:
            with conn:
                row = conn.execute(
                    f"SELECT id, day, title, time, duration_minutes FROM calendar_items WHERE user = ? AND day = ? ORDER BY {self._order_by_sql()} LIMIT 1 OFFSET ?",
                    (str(user), key, offset),
                ).fetchone()
                if row is None:
                    return None

                new_title = str(row["title"]) if title is None else str(title).strip()
                if not new_title:
                    return None
                new_time = (str(row["time"]) if row["time"] else None) if time is None else (time.strip() if isinstance(time, str) and time.strip() else None)
                if duration_minutes is None:
                    new_duration = (int(row["duration_minutes"]) if row["duration_minutes"] is not None else None)
                else:
                    new_duration = max(1, min(24 * 60, int(duration_minutes)))

                conn.execute(
                    "UPDATE calendar_items SET title = ?, time = ?, duration_minutes = ? WHERE id = ?",
                    (new_title, new_time, new_duration, str(row["id"])),
                )
        return CalendarItem(item_id=str(row["id"]), day=str(row["day"]), title=new_title, time=new_time, duration_minutes=new_duration)

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
                  duration_minutes,
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
                "item": {
                    "id": str(r["id"]),
                    "day": str(r["day"]),
                    "time": (str(r["time"]) if r["time"] else None),
                    "duration_minutes": (int(r["duration_minutes"]) if r["duration_minutes"] is not None else None),
                    "title": str(r["title"]),
                },
            }
            for r in rows
        ]


calendar_store = CalendarStore()
