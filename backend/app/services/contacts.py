"""공식 기관 연락처를 Supabase 원장과 로컬 폴백에서 조회합니다."""

import re

from app.services.supabase import supabase_gateway
from app.tools.scam_tools import OFFICIAL_NUMBERS


class OfficialContactRepository:
    async def lookup(self, phone: str) -> dict:
        normalized = re.sub(r"\D", "", phone)
        response = await supabase_gateway.select_one(
            "official_contacts",
            "agency,phone,source_url,verified_at",
            {"normalized_phone": normalized},
        )
        if response:
            return {
                "phone": phone,
                "normalized": normalized,
                "is_known_official": True,
                "agency": response["agency"],
                "source_url": response.get("source_url"),
                "verified_at": response.get("verified_at"),
                "directory": "supabase",
                "notice": "발신번호는 조작될 수 있으므로 표시 번호만으로 발신자의 신원을 보증할 수 없습니다.",
            }
        agency = OFFICIAL_NUMBERS.get(normalized)
        return {
            "phone": phone,
            "normalized": normalized,
            "is_known_official": agency is not None,
            "agency": agency,
            "directory": "local-fallback",
            "notice": "발신번호는 조작될 수 있으므로 표시 번호만으로 발신자의 신원을 보증할 수 없습니다.",
        }
