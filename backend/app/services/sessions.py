"""Supabase 우선, 인메모리 폴백 방식의 Agent State 저장소."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import settings
from app.services.supabase import supabase_gateway


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}

    async def get(self, session_id: str) -> dict[str, Any] | None:
        self._purge_expired()
        response = await supabase_gateway.select_one(
            "scam_sessions", "state", {"session_id": session_id}
        )
        if response:
            state = response.get("state")
            if isinstance(state, dict):
                self._sessions[session_id] = deepcopy(state)
                return deepcopy(state)
        session = self._sessions.get(session_id)
        return deepcopy(session) if session else None

    async def save(self, session_id: str, state: dict[str, Any]) -> None:
        stored = deepcopy(state)
        stored["updated_at"] = datetime.now(UTC).isoformat()
        self._sessions[session_id] = stored
        await supabase_gateway.upsert(
            "scam_sessions",
            {
                "session_id": session_id,
                "user_id": stored.get("user_id"),
                "state": stored,
                "situation_stage": stored.get("situation_stage", "received_message"),
                "risk_level": stored.get("detection", {}).get("risk_level"),
                "updated_at": stored["updated_at"],
            },
            "session_id",
        )

    async def clear(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        await supabase_gateway.delete("scam_sessions", "session_id", session_id)

    def _purge_expired(self) -> None:
        cutoff = datetime.now(UTC) - timedelta(minutes=settings.session_ttl_minutes)
        expired = []
        for session_id, state in self._sessions.items():
            updated_at = state.get("updated_at")
            if updated_at and datetime.fromisoformat(updated_at) < cutoff:
                expired.append(session_id)
        for session_id in expired:
            self._sessions.pop(session_id, None)


session_store = SessionStore()
