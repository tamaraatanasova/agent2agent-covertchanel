from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from threading import Lock
from typing import Any
from uuid import uuid4

from orchestrator.orchestrator import Orchestrator
from orchestrator.personal_assistant import CalendarItem, CalendarStore, calendar_store
from orchestrator.store import InMemoryStore
from shared.a2a_types import A2ATask


@dataclass
class HostSession:
    session_id: str
    messages: list[dict[str, str]] = field(default_factory=list)
    last_case_id: str | None = None  # last "report" id
    assistant_name: str | None = None
    assistant_pending: dict[str, Any] | None = None


class HostAgentService:
    """
    Simple in-process “Host Agent” that:
    - accepts user messages (text or JSON incident bundles)
    - calls the orchestrator (which calls internal agents)
    - returns a user-facing summary + links to stored case traces
    """

    def __init__(self, *, store: InMemoryStore, orch: Orchestrator) -> None:
        self._store = store
        self._orch = orch
        self._calendar: CalendarStore = calendar_store
        self._lock = Lock()
        self._sessions: dict[str, HostSession] = {}

    def create_session(self, *, session_id: str | None = None) -> HostSession:
        sid = session_id or str(uuid4())
        with self._lock:
            existing = self._sessions.get(sid)
            if existing is not None:
                return existing
            sess = HostSession(session_id=sid)
            self._sessions[sid] = sess
            return sess

    def get_session(self, session_id: str) -> HostSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def handle_message(self, *, session_id: str, text: str) -> dict[str, Any]:
        sess = self.get_session(session_id)
        if sess is None:
            # Preserve the provided session_id when integrating with external A2A
            # clients (maps cleanly to contextId).
            sess = self.create_session(session_id=session_id)

        text = (text or "").strip()
        if not text:
            return {"session_id": session_id, "reply": "Tell me what you want to do with your calendar."}

        sess.messages.append({"role": "user", "text": text})

        if text.lower().startswith("/"):
            resp = self._handle_command(sess, session_id, text)
            if resp is not None:
                return resp

        assistant = self._maybe_handle_assistant(sess, session_id, text) or {"session_id": session_id, "reply": "Try: “Show my calendar for today” or “Add 10am Gym”."}
        sess.messages.append({"role": "assistant", "text": str(assistant.get("reply") or "")})
        return assistant

    def _handle_command(self, sess: HostSession, session_id: str, text: str) -> dict[str, Any] | None:
        cmd, *rest = text.strip().split(maxsplit=1)
        cmd = cmd.lower()
        arg = rest[0].strip() if rest else ""

        if cmd in {"/help", "/commands"}:
            user = sess.assistant_name or "Tamara"
            reply = self._assistant_help(user=user)
            sess.messages.append({"role": "assistant", "text": reply})
            return {"session_id": session_id, "reply": reply, "case_id": sess.last_case_id}

        if cmd == "/reset":
            sess.assistant_pending = None
            sess.assistant_name = None
            sess.last_case_id = None
            reply = "Reset OK. Try: “I’m Tamara — show my calendar for today.”"
            sess.messages.append({"role": "assistant", "text": reply})
            return {"session_id": session_id, "reply": reply, "case_id": sess.last_case_id}

        if cmd == "/last":
            if not sess.last_case_id:
                reply = "No reports yet. Send a calendar request to create one."
                sess.messages.append({"role": "assistant", "text": reply})
                return {"session_id": session_id, "reply": reply}
            reply = f"Last report: {sess.last_case_id}\nOpen: /case/{sess.last_case_id}"
            sess.messages.append({"role": "assistant", "text": reply})
            rec = self._store.get_case(sess.last_case_id)
            return {"session_id": session_id, "reply": reply, "case_id": sess.last_case_id, "alerts": (rec.alerts if rec else [])}

        return None

    def _maybe_handle_assistant(self, sess: HostSession, session_id: str, text: str) -> dict[str, Any] | None:
        if not sess.assistant_name or re.search(r"\b(my\s+name\s+is|call\s+me)\b", (text or ""), flags=re.IGNORECASE):
            extracted_name = self._assistant_extract_name(text)
            if extracted_name:
                sess.assistant_name = extracted_name
        if not sess.assistant_name:
            # Friendly demo default.
            sess.assistant_name = "Tamara"

        case_id = str(uuid4())
        sess.last_case_id = case_id
        self._store.create_case(
            case_id,
            {
                "kind": "calendar_report",
                "session_id": session_id,
                "user": sess.assistant_name,
                "text": text,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        reply, state = self._assistant_handle_message(sess, case_id=case_id, text=text)
        try:
            day = str(state.get("day") or "")
            items = state.get("items") if isinstance(state.get("items"), list) else []
            self._store.patch_incident_bundle(case_id, {"day": day, "item_count": len(items)})
            self._store.set_final_report(
                case_id,
                {
                    "severity": "info",
                    "executive_summary": f"Calendar report for {sess.assistant_name} ({day or 'n/a'}).",
                },
            )
        except Exception:
            # Best-effort: report metadata should not break chat.
            pass

        try:
            # Attach a covert-channel demo to every calendar report.
            self._run_covert_calendar(case_id=case_id, message="HI")
        except Exception as e:
            self._store.patch_incident_bundle(case_id, {"covert_error": str(e) or "error"})
        rec = self._store.get_case(case_id)
        alerts = rec.alerts if rec else []
        return {"session_id": session_id, "reply": reply, "mode": "assistant", "assistant": state, "case_id": case_id, "alerts": alerts}

    def _assistant_intent(self, text: str) -> bool:
        t = (text or "").strip().lower()
        if not t:
            return False

        keywords = (
            "calendar",
            "agenda",
            "schedule",
            "appointment",
            "reminder",
            "remind me",
            "plan my day",
            "my day",
            "free today",
        )
        if any(k in t for k in keywords):
            return True

        if re.match(r"^(add|schedule|plan|delete|remove|clear)\b", t):
            # Only treat as assistant if it looks time/task-ish (avoid hijacking SOC "add IOC" style messages).
            if re.search(r"\b(\d{1,2})(?::\d{2})?\s*(am|pm)\b", t) or re.search(r"\b([01]?\d|2[0-3]):[0-5]\d\b", t):
                return True
            if any(k in t for k in ("meeting", "call", "doctor", "dentist", "gym", "lunch", "dinner", "class")):
                return True
            if "today" in t or "tomorrow" in t:
                return True

        if re.search(r"\b(i'?m|i am|my name is)\b", t) and any(
            k in t for k in ("calendar", "agenda", "schedule", "today", "tomorrow", "my day")
        ):
            return True

        return False

    def _assistant_extract_name(self, text: str) -> str | None:
        s = (text or "").strip()
        m = re.search(r"\b(?:i'?m|i\s+am|my\s+name\s+is|call\s+me)\s+([A-Za-z][A-Za-z'-]{1,30})\b", s, flags=re.IGNORECASE)
        if not m:
            return None
        raw = m.group(1).strip()
        if not raw:
            return None
        stop = {
            "working",
            "busy",
            "free",
            "tired",
            "doing",
            "okay",
            "ok",
            "fine",
            "good",
            "great",
            "here",
            "there",
        }
        weekdays = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
        if raw.lower() in stop or raw.lower() in weekdays:
            return None
        return raw.title()

    @staticmethod
    def _calendar_items_from_payload(items: Any) -> list[CalendarItem]:
        out: list[CalendarItem] = []
        if not isinstance(items, list):
            return out
        for it in items:
            if not isinstance(it, dict):
                continue
            item_id = str(it.get("id") or it.get("item_id") or "")
            day = str(it.get("day") or "")
            title = str(it.get("title") or "")
            time_s = it.get("time")
            out.append(CalendarItem(item_id=item_id, day=day, title=title, time=(str(time_s) if time_s else None)))
        return out

    def _call_calendar(self, *, case_id: str, to_agent: str, task_name: str, params: dict[str, Any]) -> dict[str, Any]:
        r = self._orch._call_agent(
            case_id=case_id,
            from_agent="orchestrator",
            to_agent=to_agent,
            task=A2ATask(name=task_name, parameters=params),
            mitigation_mode="on_alert",
        )
        if "error" in r:
            err = r.get("error") if isinstance(r.get("error"), dict) else {"message": "agent error"}
            raise RuntimeError(str(err.get("message") or "agent error"))
        out = r.get("output")
        if not isinstance(out, dict):
            out = {"output": out}
        self._store.set_agent_output(case_id, to_agent, out)
        return out

    def _calendar_list_day(self, *, case_id: str, user: str, day: date) -> list[CalendarItem]:
        out = self._call_calendar(
            case_id=case_id,
            to_agent="calendar_view",
            task_name="list_day",
            params={"user": user, "day": day.isoformat()},
        )
        return self._calendar_items_from_payload(out.get("items"))

    def _calendar_search(self, *, case_id: str, user: str, query: str) -> list[dict[str, Any]]:
        out = self._call_calendar(
            case_id=case_id,
            to_agent="calendar_view",
            task_name="search",
            params={"user": user, "query": query},
        )
        hits = out.get("hits")
        return hits if isinstance(hits, list) else []

    def _calendar_add(self, *, case_id: str, user: str, day: date, title: str, time: str | None) -> list[CalendarItem]:
        out = self._call_calendar(
            case_id=case_id,
            to_agent="calendar_edit",
            task_name="add_item",
            params={"user": user, "day": day.isoformat(), "title": title, "time": time},
        )
        return self._calendar_items_from_payload(out.get("items"))

    def _calendar_update(
        self,
        *,
        case_id: str,
        user: str,
        day: date,
        index: int,
        title: str | None,
        time: str | None,
    ) -> tuple[CalendarItem | None, list[CalendarItem]]:
        out = self._call_calendar(
            case_id=case_id,
            to_agent="calendar_edit",
            task_name="update_item",
            params={"user": user, "day": day.isoformat(), "index": int(index), "title": title, "time": time},
        )
        updated = out.get("updated") if isinstance(out.get("updated"), dict) else None
        updated_item = self._calendar_items_from_payload([updated])[0] if isinstance(updated, dict) else None
        items = self._calendar_items_from_payload(out.get("items"))
        return updated_item, items

    def _calendar_delete(self, *, case_id: str, user: str, day: date, index: int) -> tuple[CalendarItem | None, list[CalendarItem]]:
        out = self._call_calendar(
            case_id=case_id,
            to_agent="calendar_edit",
            task_name="delete_item",
            params={"user": user, "day": day.isoformat(), "index": int(index)},
        )
        deleted = out.get("deleted") if isinstance(out.get("deleted"), dict) else None
        deleted_item = self._calendar_items_from_payload([deleted])[0] if isinstance(deleted, dict) else None
        items = self._calendar_items_from_payload(out.get("items"))
        return deleted_item, items

    def _calendar_clear(self, *, case_id: str, user: str, day: date) -> int:
        out = self._call_calendar(
            case_id=case_id,
            to_agent="calendar_edit",
            task_name="clear_day",
            params={"user": user, "day": day.isoformat(), "confirm": True},
        )
        try:
            return int(out.get("cleared") or 0)
        except Exception:
            return 0

    def _run_covert_calendar(self, *, case_id: str, message: str) -> None:
        """
        Safe demo: leak a short message using a timing channel over calendar agents.
        The secret is stored in the report bundle and decoded from observed latencies.
        """

        msg = (message or "").strip()
        if not msg:
            msg = "HI"
        msg_bytes = msg.encode("utf-8")[:2]  # keep it fast (16 bits)
        bits = "".join("1" if (b & (1 << (7 - i))) else "0" for b in msg_bytes for i in range(8))
        bits_hash = hashlib.sha256(bits.encode("utf-8")).hexdigest()[:16]

        # Store demo parameters on the report (bits will be redacted by the API view).
        self._store.patch_incident_bundle(
            case_id,
            {
                "channel": "timing",
                "topology": "single",
                "bits": bits,
                "bits_len": len(bits),
                "bits_hash": bits_hash,
                "message": msg_bytes.decode("utf-8", errors="replace"),
            },
        )

        agents = ["calendar_view", "calendar_edit"]
        for idx, bit in enumerate(bits):
            to_agent = agents[idx % len(agents)]
            self._orch._call_agent(
                case_id=case_id,
                from_agent="orchestrator",
                to_agent=to_agent,
                task=A2ATask(name="covert_send_bit", parameters={"i": idx, "bit": bit}),
                mitigation_mode="off",
                rate_limit=False,
            )

    def _assistant_handle_message(self, sess: HostSession, *, case_id: str, text: str) -> tuple[str, dict[str, Any]]:
        user = sess.assistant_name or "Tamara"
        now = datetime.now().astimezone()
        today = now.date()

        lowered = (text or "").strip().lower()

        pending = sess.assistant_pending or {}
        if isinstance(pending, dict) and pending.get("type") == "confirm_clear":
            day = date.fromisoformat(str(pending.get("day")))
            if self._assistant_is_yes(text):
                n = self._calendar_clear(case_id=case_id, user=user, day=day)
                sess.assistant_pending = None
                items = self._calendar_list_day(case_id=case_id, user=user, day=day)
                reply = f"Done — cleared {n} activity(ies) for {day.strftime('%A, %B %d, %Y')}.\n\n" + self._assistant_format_day(
                    user=user, day=day, today=today, items=items
                )
                return reply, self._assistant_state(user=user, day=day, items=items)
            if self._assistant_is_no(text):
                sess.assistant_pending = None
                items = self._calendar_list_day(case_id=case_id, user=user, day=day)
                reply = "OK — I won’t delete anything.\n\n" + self._assistant_format_day(user=user, day=day, today=today, items=items)
                return reply, self._assistant_state(user=user, day=day, items=items)
            reply = "Please reply “yes” to clear the day, or “no” to cancel."
            items = self._calendar_list_day(case_id=case_id, user=user, day=day)
            return reply, self._assistant_state(user=user, day=day, items=items)

        if isinstance(pending, dict) and pending.get("type") == "await_add":
            day = date.fromisoformat(str(pending.get("day")))
            if self._assistant_is_no(text):
                sess.assistant_pending = None
                items = self._calendar_list_day(case_id=case_id, user=user, day=day)
                reply = "No problem.\n\n" + self._assistant_format_day(user=user, day=day, today=today, items=items)
                return reply, self._assistant_state(user=user, day=day, items=items)

            schedule = self._assistant_maybe_apply_recurring_schedule(case_id=case_id, user=user, text=text, today=today, default_day=day)
            if schedule is not None:
                sess.assistant_pending = None
                items = self._calendar_list_day(case_id=case_id, user=user, day=day)
                reply = schedule + "\n\n" + self._assistant_format_day(user=user, day=day, today=today, items=items)
                return reply, self._assistant_state(user=user, day=day, items=items)

            # Treat the next user message as the activity details.
            time_str, title = self._assistant_extract_time_and_title(text)
            if not title:
                reply = "What should I add? Example: “Gym at 6pm” or “Add 14:00 Dentist”."
                items = self._calendar_list_day(case_id=case_id, user=user, day=day)
                return reply, self._assistant_state(user=user, day=day, items=items)

            items = self._calendar_add(case_id=case_id, user=user, day=day, title=title, time=time_str)
            sess.assistant_pending = None
            reply = f"Added.\n\n{self._assistant_format_day(user=user, day=day, today=today, items=items)}"
            return reply, self._assistant_state(user=user, day=day, items=items)

        day = self._assistant_parse_day(text, today=today)

        schedule = self._assistant_maybe_apply_recurring_schedule(case_id=case_id, user=user, text=text, today=today, default_day=day)
        if schedule is not None:
            sess.assistant_pending = None
            items = self._calendar_list_day(case_id=case_id, user=user, day=day)
            reply = schedule + "\n\n" + self._assistant_format_day(user=user, day=day, today=today, items=items)
            return reply, self._assistant_state(user=user, day=day, items=items)

        items = self._calendar_list_day(case_id=case_id, user=user, day=day)

        if any(k in lowered for k in ("help", "what can you do", "commands")):
            reply = self._assistant_help(user=user)
            return reply, self._assistant_state(user=user, day=day, items=items)

        if re.search(r"\b(search|find)\b", lowered):
            m = re.search(r"\b(?:search|find)\b\s+(.+)$", (text or "").strip(), flags=re.IGNORECASE)
            q = (m.group(1).strip() if m else "").strip()
            if not q:
                reply = "What should I search for? Example: “Search gym”."
                return reply, self._assistant_state(user=user, day=day, items=items)
            hits = self._calendar_search(case_id=case_id, user=user, query=q)
            if not hits:
                reply = f"No matches for “{q}”."
                return reply, self._assistant_state(user=user, day=day, items=items)

            lines = [f"Found {len(hits)} match(es) for “{q}”:"]
            for h in hits[:12]:
                day_str = h.get("day")
                idx = h.get("index")
                item = h.get("item") if isinstance(h.get("item"), dict) else {}
                title = item.get("title")
                time_s = item.get("time")
                try:
                    d = date.fromisoformat(str(day_str))
                    day_label = d.strftime("%Y-%m-%d")
                except Exception:
                    day_label = str(day_str)
                when = f"{time_s} — " if time_s else ""
                lines.append(f"- {day_label} #{idx}: {when}{title}")
            reply = "\n".join(lines)
            return reply, self._assistant_state(user=user, day=day, items=items)

        if re.search(r"\b(edit|update|change)\b", lowered):
            m = re.search(r"\b(\d{1,3})\b", text or "")
            if not m:
                reply = "Which one should I edit? Example: “Edit 2 to 3pm Meeting”."
                return reply, self._assistant_state(user=user, day=day, items=items)
            idx = int(m.group(1))
            rest = (text or "")[m.end() :].strip()
            rest = re.sub(r"^(?:to|with)\b[:\s-]*", "", rest, flags=re.IGNORECASE).strip()
            time_str, title = self._assistant_extract_time_and_title(rest)
            title = title.strip()
            if not title and time_str is None:
                reply = "What should I change it to? Example: “Edit 2 to Lunch at 12:30”."
                return reply, self._assistant_state(user=user, day=day, items=items)

            updated, items = self._calendar_update(
                case_id=case_id,
                user=user,
                day=day,
                index=idx,
                title=(title if title else None),
                time=time_str,
            )
            if updated is None:
                reply = f"I couldn’t find item #{idx}.\n\n{self._assistant_format_day(user=user, day=day, today=today, items=items)}"
                return reply, self._assistant_state(user=user, day=day, items=items)
            reply = f"Updated: {updated.display()}\n\n{self._assistant_format_day(user=user, day=day, today=today, items=items)}"
            return reply, self._assistant_state(user=user, day=day, items=items)

        if any(k in lowered for k in ("clear", "delete all", "remove all")):
            if "today" in lowered or "tomorrow" in lowered or re.search(r"\b20\d{2}-\d{2}-\d{2}\b", lowered):
                n = self._calendar_clear(case_id=case_id, user=user, day=day)
                items = self._calendar_list_day(case_id=case_id, user=user, day=day)
                reply = f"Done — cleared {n} activity(ies).\n\n{self._assistant_format_day(user=user, day=day, today=today, items=items)}"
                return reply, self._assistant_state(user=user, day=day, items=items)
            sess.assistant_pending = {"type": "confirm_clear", "day": day.isoformat()}
            reply = f"Do you want me to delete *all* activities for {day.strftime('%A, %B %d, %Y')}? Reply “yes” to confirm or “no” to cancel."
            return reply, self._assistant_state(user=user, day=day, items=items)

        if re.search(r"\b(delete|remove|cancel)\b", lowered):
            m = re.search(r"\b(\d{1,3})\b", lowered)
            if not m:
                reply = "Which one should I delete? Example: “Delete 2”."
                return reply, self._assistant_state(user=user, day=day, items=items)
            idx = int(m.group(1))
            removed, items = self._calendar_delete(case_id=case_id, user=user, day=day, index=idx)
            if removed is None:
                reply = f"I couldn’t find item #{idx}.\n\n{self._assistant_format_day(user=user, day=day, today=today, items=items)}"
                return reply, self._assistant_state(user=user, day=day, items=items)
            reply = f"Deleted: {removed.display()}\n\n{self._assistant_format_day(user=user, day=day, today=today, items=items)}"
            return reply, self._assistant_state(user=user, day=day, items=items)

        if re.match(r"^(add|schedule|plan)\b", lowered):
            time_str, title = self._assistant_extract_time_and_title(text)
            if not title:
                sess.assistant_pending = {"type": "await_add", "day": day.isoformat()}
                reply = f"Sure — what should I add for {day.strftime('%A, %B %d, %Y')}?"
                return reply, self._assistant_state(user=user, day=day, items=items)
            items = self._calendar_add(case_id=case_id, user=user, day=day, title=title, time=time_str)
            reply = f"Added.\n\n{self._assistant_format_day(user=user, day=day, today=today, items=items)}"
            return reply, self._assistant_state(user=user, day=day, items=items)

        # Default: show the day.
        reply = self._assistant_format_day(user=user, day=day, today=today, items=items)
        if not items:
            sess.assistant_pending = {"type": "await_add", "day": day.isoformat()}
        return reply, self._assistant_state(user=user, day=day, items=items)

    def _assistant_parse_day(self, text: str, *, today: date) -> date:
        t = (text or "").lower()
        if "tomorrow" in t:
            return today + timedelta(days=1)
        m = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", t)
        if m:
            try:
                return date.fromisoformat(m.group(1))
            except ValueError:
                pass
        return today

    def _assistant_is_yes(self, text: str) -> bool:
        t = (text or "").strip().lower()
        return t in {"y", "yes", "yeah", "yep", "ok", "okay", "sure", "confirm"}

    def _assistant_is_no(self, text: str) -> bool:
        t = (text or "").strip().lower()
        return t in {"n", "no", "nope", "nah", "cancel", "stop"}

    def _assistant_extract_time_and_title(self, text: str) -> tuple[str | None, str]:
        s = (text or "").strip()
        s = re.sub(r"^(?:please\s+)?(?:add|schedule|plan|edit|update|change)\b[:\s-]*", "", s, flags=re.IGNORECASE).strip()
        s = re.sub(r"\b(to\s+my\s+calendar|to\s+calendar)\b", "", s, flags=re.IGNORECASE).strip()
        s = re.sub(r"\b(today|tomorrow)\b", "", s, flags=re.IGNORECASE).strip()

        # Time range: 9-5, 9 to 5, 9am-5pm, 09:00–17:00
        m = re.search(
            r"\b(?:from\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s*(?:-|–|—|\bto\b)\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b",
            s,
            flags=re.IGNORECASE,
        )
        if m:
            sh, sm, sap = int(m.group(1)), int(m.group(2) or "0"), (m.group(3) or "")
            eh, em, eap = int(m.group(4)), int(m.group(5) or "0"), (m.group(6) or "")

            start_ampm = sap.lower() if sap else ""
            end_ampm = eap.lower() if eap else ""

            # If only one side specifies am/pm, make a best-effort guess for the other.
            if start_ampm and not end_ampm:
                end_ampm = start_ampm
            if end_ampm and not start_ampm:
                start_ampm = "am" if end_ampm == "pm" else end_ampm

            def to_24h(h: int, ap: str) -> tuple[int, bool]:
                if ap not in ("am", "pm"):
                    return h, False
                hh = 0 if h == 12 else h
                if ap == "pm":
                    hh += 12
                return hh, True

            sh24, s_exp = to_24h(sh, start_ampm)
            eh24, e_exp = to_24h(eh, end_ampm)

            # Common shorthand: "9 to 5" means 09:00–17:00.
            if eh24 < sh24 and not (s_exp and e_exp and start_ampm == "pm" and end_ampm == "am"):
                if eh24 + 12 <= 23:
                    eh24 += 12

            time_str = f"{sh24:02d}:{sm:02d}"
            end_str = f"{eh24:02d}:{em:02d}"
            title = (s[: m.start()] + s[m.end() :]).strip(" -–—")
            title = re.sub(r"\bat\b", "", title, flags=re.IGNORECASE).strip(" -–—")
            if title:
                title = f"{title} (until {end_str})"
            return time_str, title

        # 3pm, 3:30pm
        m = re.search(r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b", s, flags=re.IGNORECASE)
        if m:
            hour = int(m.group(1))
            minute = int(m.group(2) or "0")
            ampm = m.group(3).lower()
            if hour == 12:
                hour = 0
            if ampm == "pm":
                hour += 12
            time_str = f"{hour:02d}:{minute:02d}"
            title = (s[: m.start()] + s[m.end() :]).strip(" -–—")
            title = re.sub(r"\bat\b", "", title, flags=re.IGNORECASE).strip(" -–—")
            return time_str, title

        # 24h time: 14:00
        m = re.search(r"\b([01]?\d|2[0-3]):([0-5]\d)\b", s)
        if m:
            time_str = f"{int(m.group(1)):02d}:{int(m.group(2)):02d}"
            title = (s[: m.start()] + s[m.end() :]).strip(" -–—")
            title = re.sub(r"\bat\b", "", title, flags=re.IGNORECASE).strip(" -–—")
            return time_str, title

        return None, s

    def _assistant_maybe_apply_recurring_schedule(self, *, case_id: str, user: str, text: str, today: date, default_day: date) -> str | None:
        t = (text or "").strip()
        lowered = t.lower()

        # Detect a recurring schedule intent (keep it simple, demo-friendly).
        recurrence_cues = ("every", "each", "daily", "weekdays", "weekends", "mon-fri", "monday to friday", "monday through friday", "monday thru friday")
        if not any(cue in lowered for cue in recurrence_cues) and not re.search(r"\b(mon|tue|wed|thu|fri|sat|sun)\b", lowered):
            return None

        # Require a time RANGE (e.g., "9 to 5") to treat it as a repeating block.
        start_time, end_time = self._assistant_extract_time_range(t)
        if not start_time or not end_time:
            return None

        days = self._assistant_extract_days_of_week(t)
        if days is None:
            if "every day" in lowered or "daily" in lowered:
                days = {0, 1, 2, 3, 4, 5, 6}
            else:
                return None

        weeks = self._assistant_extract_duration_weeks(t)
        loc = self._assistant_extract_location(t)

        base = "Work" if re.search(r"\bwork(?:ing)?\b", lowered) else "Block"
        title = f"{base} in {loc}" if loc else base
        if end_time:
            title = f"{title} (until {end_time})"

        # Default start day is whatever the assistant is currently looking at (today/tomorrow/etc).
        start_day = default_day
        if "tomorrow" in lowered:
            start_day = today + timedelta(days=1)
        m = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", lowered)
        if m:
            try:
                start_day = date.fromisoformat(m.group(1))
            except ValueError:
                pass

        # If the requested start day doesn't match the pattern (e.g., it's weekend for Mon–Fri), roll forward.
        for _ in range(0, 7):
            if start_day.weekday() in days:
                break
            start_day = start_day + timedelta(days=1)

        horizon_days = max(7, min(90, int(weeks) * 7))
        added = 0
        skipped = 0
        for i in range(horizon_days):
            d = start_day + timedelta(days=i)
            if d.weekday() not in days:
                continue
            existing = self._calendar_list_day(case_id=case_id, user=user, day=d)
            if any(it.time == start_time and it.title == title for it in existing):
                skipped += 1
                continue
            self._calendar_add(case_id=case_id, user=user, day=d, title=title, time=start_time)
            added += 1

        day_label = f"{start_time}–{end_time}"
        days_label = self._assistant_days_label(days)
        weeks_label = "1 week" if weeks == 1 else f"{weeks} weeks"
        extra = f" in {loc}" if loc else ""

        if added == 0 and skipped > 0:
            return f"That schedule already exists ({days_label} {day_label}{extra})."
        if skipped > 0:
            return f"Updated your schedule: {days_label} {day_label}{extra} for the next {weeks_label}. (Added {added}, already had {skipped}.)"
        return f"Updated your schedule: {days_label} {day_label}{extra} for the next {weeks_label}. (Added {added}.)"

    def _assistant_extract_time_range(self, text: str) -> tuple[str | None, str | None]:
        s = (text or "").strip()
        m = re.search(
            r"\b(?:from\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s*(?:-|–|—|\bto\b)\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b",
            s,
            flags=re.IGNORECASE,
        )
        if not m:
            return None, None

        sh, sm, sap = int(m.group(1)), int(m.group(2) or "0"), (m.group(3) or "")
        eh, em, eap = int(m.group(4)), int(m.group(5) or "0"), (m.group(6) or "")

        start_ampm = sap.lower() if sap else ""
        end_ampm = eap.lower() if eap else ""

        if start_ampm and not end_ampm:
            end_ampm = start_ampm
        if end_ampm and not start_ampm:
            start_ampm = "am" if end_ampm == "pm" else end_ampm

        def to_24h(h: int, ap: str) -> tuple[int, bool]:
            if ap not in ("am", "pm"):
                return h, False
            hh = 0 if h == 12 else h
            if ap == "pm":
                hh += 12
            return hh, True

        sh24, s_exp = to_24h(sh, start_ampm)
        eh24, e_exp = to_24h(eh, end_ampm)
        if eh24 < sh24 and not (s_exp and e_exp and start_ampm == "pm" and end_ampm == "am"):
            if eh24 + 12 <= 23:
                eh24 += 12

        return f"{sh24:02d}:{sm:02d}", f"{eh24:02d}:{em:02d}"

    def _assistant_extract_days_of_week(self, text: str) -> set[int] | None:
        t = (text or "").strip().lower()
        if "weekdays" in t:
            return {0, 1, 2, 3, 4}
        if "weekends" in t or "weekend" in t:
            return {5, 6}
        if "mon-fri" in t:
            return {0, 1, 2, 3, 4}

        aliases = {
            "mon": 0,
            "monday": 0,
            "tue": 1,
            "tues": 1,
            "tuesday": 1,
            "wed": 2,
            "weds": 2,
            "wednesday": 2,
            "thu": 3,
            "thur": 3,
            "thurs": 3,
            "thursday": 3,
            "fri": 4,
            "friday": 4,
            "sat": 5,
            "saturday": 5,
            "sun": 6,
            "sunday": 6,
        }

        # Range: monday to friday / mon through fri
        m = re.search(
            r"\b(mon(?:day)?|tue(?:s|sday)?|wed(?:s|nesday)?|thu(?:r|rs|rsday)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)\s*"
            r"(?:-|to|through|thru)\s*"
            r"(mon(?:day)?|tue(?:s|sday)?|wed(?:s|nesday)?|thu(?:r|rs|rsday)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)\b",
            t,
        )
        if m:
            start = aliases.get(m.group(1)[:3], aliases.get(m.group(1), 0))
            end = aliases.get(m.group(2)[:3], aliases.get(m.group(2), 0))
            if start <= end:
                return set(range(start, end + 1))
            return set(range(start, 7)) | set(range(0, end + 1))

        days: set[int] = set()
        for w in re.findall(r"\b(mon|tue(?:s)?|wed(?:s)?|thu(?:r|rs)?|fri|sat|sun)\b", t):
            key = w[:3]
            if key in aliases:
                days.add(aliases[key])
        return days or None

    def _assistant_extract_duration_weeks(self, text: str) -> int:
        t = (text or "").strip().lower()
        if "next week" in t:
            return 1
        m = re.search(r"\b(\d{1,2})\s*week(?:s)?\b", t)
        if m:
            try:
                n = int(m.group(1))
                return max(1, min(12, n))
            except Exception:
                pass
        if "month" in t:
            return 4
        return 2

    def _assistant_extract_location(self, text: str) -> str | None:
        # Very small heuristic: grab up to 4 words after "in"/"at" until we hit a stop word.
        t = (text or "").strip()
        m = re.search(r"\b(?:in|at)\s+(.+)$", t, flags=re.IGNORECASE)
        if not m:
            return None
        rest = m.group(1).strip()
        if not rest:
            return None
        stop = {
            "from",
            "to",
            "every",
            "each",
            "daily",
            "weekdays",
            "weekday",
            "weekends",
            "weekend",
            "starting",
            "for",
            "on",
            "mon",
            "monday",
            "tue",
            "tues",
            "tuesday",
            "wed",
            "weds",
            "wednesday",
            "thu",
            "thur",
            "thurs",
            "thursday",
            "fri",
            "friday",
            "sat",
            "saturday",
            "sun",
            "sunday",
        }
        out: list[str] = []
        for w in rest.split():
            clean = re.sub(r"[^A-Za-z0-9'/-]", "", w).strip()
            if not clean:
                continue
            if clean.lower() in stop:
                break
            out.append(clean)
            if len(out) >= 4:
                break
        if not out:
            return None
        return " ".join(out)

    @staticmethod
    def _assistant_days_label(days: set[int]) -> str:
        if days == {0, 1, 2, 3, 4}:
            return "Mon–Fri"
        if days == {5, 6}:
            return "Sat–Sun"
        if days == {0, 1, 2, 3, 4, 5, 6}:
            return "Every day"
        names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        return ", ".join(names[i] for i in range(7) if i in days) or "Selected days"

    def _assistant_format_day(self, *, user: str, day: date, today: date, items: list[CalendarItem]) -> str:
        day_label = day.strftime("%A, %B %d, %Y")
        is_today = day == today

        if not items:
            free = "You’re free today" if is_today else "No activities yet"
            return (
                f"{user}, here’s your calendar for {day_label}.\n"
                f"{free}.\n\n"
                "Want to add something?\n"
                "- Example: “Add 10am Gym”\n"
                "- Example: “Add 14:00 Dentist”\n"
                "- Or just type the activity (e.g., “Lunch at 12:30”)"
            )

        lines = [f"{user}, here’s your calendar for {day_label}:"]
        for idx, it in enumerate(items, start=1):
            lines.append(f"{idx}) {it.display()}")
        lines.append("")
        lines.append("You can say:")
        lines.append("- “Add 3pm Meeting”")
        lines.append("- “Delete 2”")
        lines.append("- “Clear today”")
        return "\n".join(lines)

    def _assistant_help(self, *, user: str) -> str:
        return (
            f"Hi {user}! I can help you manage a simple calendar.\n\n"
            "Try:\n"
            "- “Show my calendar for today”\n"
            "- “Add 10am Gym”\n"
            "- “Add 14:00 Dentist tomorrow”\n"
            "- “Delete 2”\n"
            "- “Clear today”\n"
            "- “Switch to SOC mode”"
        )

    def _assistant_state(self, *, user: str, day: date, items: list[CalendarItem]) -> dict[str, Any]:
        return {"user": user, "day": day.isoformat(), "items": [it.model_dump() for it in items]}

    def _parse_incident_bundle(self, text: str) -> dict[str, Any]:
        text = (text or "").strip()

        # If the user pasted a JSON bundle, use it directly.
        if text.startswith("{") and text.endswith("}"):
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass

        # If the user pasted an LLM-style prompt, extract the incident portion.
        # Supported format:
        #   Title: ...
        #   Incident: ...
        # Anything before "Incident:" is treated as instructions and ignored for telemetry.
        lowered = text.lower()
        incident_text = text
        title: str | None = None

        if "incident:" in lowered:
            i = lowered.index("incident:")
            incident_text = text[i + len("incident:") :].strip()

        if "title:" in lowered:
            i = lowered.index("title:")
            rest = text[i + len("title:") :]
            title = rest.splitlines()[0].strip() or None

        # If the extracted incident is JSON, use it.
        if incident_text.startswith("{") and incident_text.endswith("}"):
            try:
                obj = json.loads(incident_text)
                if isinstance(obj, dict):
                    if title and "title" not in obj:
                        obj = {**obj, "title": title}
                    return obj
            except json.JSONDecodeError:
                pass

        return {"title": title or "User-described incident", "events": [{"msg": incident_text}], "artifacts": {}}

    def _looks_like_structured_bundle(self, bundle: dict[str, Any]) -> bool:
        if not isinstance(bundle, dict):
            return False
        if "demo" in bundle:
            return True
        events = bundle.get("events")
        artifacts = bundle.get("artifacts")
        if isinstance(events, list) and len(events) >= 2:
            return True
        if isinstance(artifacts, dict) and any(artifacts.get(k) for k in ("hosts", "users", "iocs", "processes", "ips", "urls")):
            return True
        return False

    def _triage_questions(self, text: str) -> list[str]:
        extracted = self._extract_entities(text)
        questions: list[str] = []

        if not extracted.get("hosts"):
            questions.append("Which host(s) / asset(s) are affected? (e.g., pc-hr-01, dc-01)")
        if not extracted.get("timeframe"):
            questions.append("What timeframe did this happen? (e.g., 'last 10 minutes', '2026-01-22 20:10–20:30')")
        if not (extracted.get("ips") or extracted.get("domains") or extracted.get("urls") or extracted.get("hashes") or extracted.get("processes")):
            questions.append("Any indicators? (IP/domain/URL/hash/process/command line)")

        # Keep it short and “SOC-like”.
        return questions[:3]

    def _format_questions(self, questions: list[str]) -> str:
        lines = [
            "I can triage this faster with 2–3 details. Reply with any you know:",
        ]
        for q in questions:
            lines.append(f"- {q}")
        lines.append("Or paste a JSON incident bundle to skip questions.")
        return "\n".join(lines)

    def _merge_followup(self, base_bundle: dict[str, Any], followup_text: str) -> dict[str, Any]:
        bundle = dict(base_bundle or {})
        events = bundle.get("events") if isinstance(bundle.get("events"), list) else []
        events = list(events)
        events.append({"msg": followup_text})
        bundle["events"] = events

        artifacts = bundle.get("artifacts") if isinstance(bundle.get("artifacts"), dict) else {}
        artifacts = dict(artifacts)
        extracted = self._extract_entities(followup_text)

        for k, v in extracted.items():
            if not v:
                continue
            if isinstance(v, list):
                prev = artifacts.get(k)
                prev_list = list(prev) if isinstance(prev, list) else []
                for it in v:
                    if it not in prev_list:
                        prev_list.append(it)
                artifacts[k] = prev_list
            else:
                if not artifacts.get(k):
                    artifacts[k] = v

        bundle["artifacts"] = artifacts
        return bundle

    def _extract_entities(self, text: str) -> dict[str, Any]:
        s = (text or "").strip()

        ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", s)
        urls = re.findall(r"\bhttps?://[^\s)]+", s, flags=re.IGNORECASE)
        domains = re.findall(r"\b[a-z0-9.-]+\.[a-z]{2,}\b", s, flags=re.IGNORECASE)
        processes = re.findall(r"\b[a-z0-9_.-]+\.exe\b", s, flags=re.IGNORECASE)

        sha256 = re.findall(r"\b[a-f0-9]{64}\b", s, flags=re.IGNORECASE)
        sha1 = re.findall(r"\b[a-f0-9]{40}\b", s, flags=re.IGNORECASE)
        md5 = re.findall(r"\b[a-f0-9]{32}\b", s, flags=re.IGNORECASE)
        hashes = list(dict.fromkeys(sha256 + sha1 + md5))

        # Hostname-ish tokens (kept conservative).
        hosts = re.findall(r"\b(?:[a-z]{2,10}-[a-z0-9]{1,10}-?\d{0,3}|[a-z]{2,10}\d{0,3})\b", s, flags=re.IGNORECASE)
        hosts = [h for h in hosts if len(h) <= 20]

        users = re.findall(r"\b[a-z][a-z0-9._-]{1,30}\b", s, flags=re.IGNORECASE)
        users = [u for u in users if "." in u or "_" in u]

        timeframe = None
        m = re.search(r"\b(last\s+\d+\s+(?:min|mins|minute|minutes|hour|hours|day|days))\b", s, flags=re.IGNORECASE)
        if m:
            timeframe = m.group(1)
        else:
            m2 = re.search(r"\b(20\d{2}-\d{2}-\d{2}(?:[ t]\d{2}:\d{2}(?::\d{2})?)?)\b", s)
            if m2:
                timeframe = m2.group(1)

        return {
            "ips": list(dict.fromkeys(ips)),
            "urls": list(dict.fromkeys(urls)),
            "domains": list(dict.fromkeys(domains)),
            "processes": list(dict.fromkeys(processes)),
            "hashes": hashes,
            "hosts": list(dict.fromkeys(hosts)),
            "users": list(dict.fromkeys(users)),
            "timeframe": timeframe,
        }

    def _format_reply(self, result: dict[str, Any]) -> str:
        if "error" in result and result["error"]:
            err = result["error"]
            return f"Error: {err.get('code', 'UNKNOWN')}: {err.get('message', 'request failed')}"

        report = result.get("report") or {}
        outputs = report.get("outputs") or {}
        ti = outputs.get("threat_intel", {}) or {}
        anomaly = outputs.get("anomaly", {}) or {}
        compliance = outputs.get("compliance", {}) or {}
        plan = outputs.get("ir_planner", {}) or {}

        lines: list[str] = []
        if result.get("case_id"):
            lines.append(f"Case created: {result['case_id']}")

        lines.append(f"Severity: {report.get('severity', 'low')}")
        if report.get("executive_summary"):
            lines.append(str(report["executive_summary"]))

        lines.append(f"Threat intel matches: {ti.get('match_count', 0)}")
        lines.append(f"Anomaly score: {float(anomaly.get('anomaly_score', 0.0)):.2f}")

        actions = plan.get("proposed_actions", [])
        allowed = compliance.get("allowed", [])
        blocked = compliance.get("blocked", [])
        if actions:
            lines.append(f"Proposed actions: {len(actions)} (allowed={len(allowed)}, blocked={len(blocked)})")
            if blocked:
                lines.append("Note: containment is blocked by policy until approved.")

        recs = report.get("recommendations") or []
        if recs:
            lines.append("Recommendations:")
            for r in recs[:5]:
                lines.append(f"- {r}")

        lines.append("Tip: open the case link to see full A2A message trace + timing alerts.")
        return "\n".join(lines)

    def _summarize_case(self, rec) -> str:
        lines = [f"Case: {rec.case_id}", f"Messages: {len(rec.messages)}", f"Alerts: {len(rec.alerts)}"]
        if rec.final_report:
            lines.append("Final report: available")
        else:
            lines.append("Final report: not set")
        return "\n".join(lines)
