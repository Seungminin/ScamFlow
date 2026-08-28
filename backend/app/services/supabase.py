"""Supabase PostgREST/RPC 접근을 한곳에서 관리하는 비동기 게이트웨이."""

import base64
import json
from typing import Any

import httpx
from loguru import logger

from app.core.config import settings


class SupabaseGateway:
    @property
    def server_key(self) -> str:
        """새 secret key 또는 legacy service_role JWT만 서버 키로 선택합니다."""
        candidates = (
            settings.supabase_secret_key,
            settings.supabase_service_role_key,
            settings.supabase_key,
        )
        for key in candidates:
            if key.startswith("sb_secret_"):
                return key
        for key in candidates:
            if self._legacy_role(key) == "service_role":
                return key
        return ""

    @property
    def enabled(self) -> bool:
        return bool(
            settings.enable_supabase
            and settings.supabase_url
            and self.server_key
        )

    @property
    def headers(self) -> dict[str, str]:
        key = self.server_key
        headers = {
            "apikey": key,
            "Content-Type": "application/json",
        }
        # 새 sb_secret 키는 apikey 헤더만, legacy JWT는 Bearer도 함께 사용합니다.
        if self._legacy_role(key) == "service_role":
            headers["Authorization"] = f"Bearer {key}"
        return headers

    @staticmethod
    def _legacy_role(key: str) -> str | None:
        if key.count(".") != 2:
            return None
        try:
            payload = key.split(".")[1]
            decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            return json.loads(decoded).get("role")
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: Any = None,
        prefer: str | None = None,
    ) -> Any | None:
        if not self.enabled:
            return None
        headers = dict(self.headers)
        if prefer:
            headers["Prefer"] = prefer
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.request(
                    method,
                    f"{settings.supabase_url.rstrip('/')}/rest/v1/{path.lstrip('/')}",
                    headers=headers,
                    params=params,
                    json=json,
                )
            response.raise_for_status()
            return response.json() if response.content else True
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning(f"Supabase 요청 실패, 로컬 폴백 사용: {exc}")
            return None

    async def select_one(
        self, table: str, columns: str, filters: dict[str, str]
    ) -> dict[str, Any] | None:
        params = {"select": columns, "limit": "1"}
        params.update({key: f"eq.{value}" for key, value in filters.items()})
        result = await self.request("GET", table, params=params)
        return result[0] if isinstance(result, list) and result else None

    async def upsert(
        self, table: str, row: dict[str, Any], conflict_column: str
    ) -> bool:
        result = await self.request(
            "POST",
            table,
            params={"on_conflict": conflict_column},
            json=row,
            prefer="resolution=merge-duplicates,return=minimal",
        )
        return result is not None

    async def insert(self, table: str, rows: list[dict[str, Any]]) -> bool:
        result = await self.request(
            "POST", table, json=rows, prefer="return=minimal"
        )
        return result is not None

    async def delete(self, table: str, column: str, value: str) -> bool:
        result = await self.request(
            "DELETE", table, params={column: f"eq.{value}"}, prefer="return=minimal"
        )
        return result is not None

    async def rpc(self, function: str, params: dict[str, Any]) -> list[dict] | None:
        result = await self.request("POST", f"rpc/{function}", json=params)
        return result if isinstance(result, list) else None


supabase_gateway = SupabaseGateway()
