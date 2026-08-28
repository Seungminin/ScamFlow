"""Agent Tool 선택과 실행을 한곳에서 관리."""

from datetime import UTC, datetime
from uuid import uuid4

from loguru import logger

from app.core.config import settings
from app.services.contacts import OfficialContactRepository
from app.services.rag import OfficialKnowledgeRepository
from app.services.reputation import UrlReputationService, is_kisa_whois_target
from app.services.supabase import supabase_gateway
from app.tools.scam_tools import (
    OFFICIAL_CONTACT_SOURCES,
    OFFICIAL_INSTITUTION_NUMBERS,
    extract_phone_numbers,
    extract_urls,
    inspect_url,
)


class ToolExecutor:
    def __init__(self, knowledge: OfficialKnowledgeRepository | None = None):
        self.knowledge = knowledge or OfficialKnowledgeRepository()
        self.reputation = UrlReputationService()
        self.contacts = OfficialContactRepository()

    def select_tools(
        self,
        text: str,
        input_mode: str = "text",
        structured: dict | None = None,
        hypothesis: dict | None = None,
    ) -> list[str]:
        structured = structured or {}
        hypothesis = hypothesis or {}
        tools: list[str] = []
        if input_mode == "image_ocr":
            tools.append("multimodal_context_analysis")
        urls = extract_urls(text)
        if urls or any(marker in text.lower() for marker in ("url", "링크", "주소")):
            tools.extend(["inspect_url", "url_rule_engine"])
            if settings.enable_url_reputation and settings.google_safe_browsing_api_key:
                tools.append("google_safe_browsing")
            if (
                settings.enable_url_reputation
                and settings.kisa_whois_api_key
                and any(is_kisa_whois_target(url) for url in urls)
            ):
                tools.append("kisa_whois")
            if settings.enable_url_reputation and settings.virustotal_api_key:
                tools.append("virustotal")
        phones = structured.get("phone_numbers") or extract_phone_numbers(text)
        phone_verification_needed = bool(
            structured.get("contact_request")
            or structured.get("institution_impersonation")
        )
        if phones and phone_verification_needed:
            tools.append("inspect_phone")
        if structured.get("institution") and structured.get("institution_impersonation"):
            tools.append("verify_official_procedure")
            if phones:
                tools.append("verify_institution_contact")
        if (
            hypothesis.get("primary_type") not in {None, "safe_message", "unknown"}
            and float(hypothesis.get("confidence", 0)) >= 0.55
        ):
            tools.append("scam_case_rag")
        return list(dict.fromkeys(tools))

    async def execute_selected(
        self,
        tool_names: list[str],
        text: str,
        session_id: str | None = None,
        structured: dict | None = None,
        hypothesis: dict | None = None,
        situation_stage: str = "received_message",
    ) -> tuple[dict, list[dict]]:
        structured = structured or {}
        hypothesis = hypothesis or {}
        results: dict = {}
        traces: list[dict] = []
        if "inspect_url" in tool_names:
            urls = extract_urls(text)
            inspected = []
            for url in urls:
                item = inspect_url(url)
                item["reputation"] = await self.reputation.lookup(
                    url,
                    selected_providers=set(tool_names),
                )
                item["risk_components"] = self._url_components(item)
                item["risk_score"] = max(
                    component["score"] for component in item["risk_components"].values()
                )
                if settings.environment == "development":
                    logger.debug(f"URL rule result: {item['risk_components']['url_structure']}")
                    logger.debug(f"WHOIS result: {self._provider_result(item, 'kisa_whois')}")
                    logger.debug(f"Safe Browsing result: {self._provider_result(item, 'google_safe_browsing')}")
                inspected.append(item)
            results["urls"] = inspected
            remote_count = sum(bool(item["reputation"]) for item in inspected)
            summary = f"URL {len(urls)}개 구조 검사 · 외부 평판 {remote_count}개 조회"
            traces.append({"name": "inspect_url", "status": "completed", "summary": summary})
            traces.append({"name": "url_rule_engine", "status": "completed", "summary": f"eTLD+1·allowlist·URL 구조 {len(urls)}개 검사"})
        if "inspect_phone" in tool_names:
            phones = structured.get("phone_numbers") or extract_phone_numbers(text)
            results["phones"] = [await self.contacts.lookup(phone) for phone in phones]
            summary = f"전화번호 {len(phones)}개 공식번호 대조"
            traces.append({"name": "inspect_phone", "status": "completed", "summary": summary})
        if "verify_institution_contact" in tool_names:
            verification = self._verify_institution_contact(
                structured.get("institution"),
                structured.get("phone_numbers") or extract_phone_numbers(text),
            )
            results["institution_verification"] = verification
            traces.append(
                {
                    "name": "verify_institution_contact",
                    "status": "completed",
                    "summary": verification["summary"],
                }
            )
        if "verify_official_procedure" in tool_names:
            procedure = self._verify_official_procedure(structured)
            results["official_procedure"] = procedure
            traces.append(
                {
                    "name": "verify_official_procedure",
                    "status": "completed",
                    "summary": procedure["summary"],
                }
            )
        if "scam_case_rag" in tool_names:
            sources = await self.knowledge.search(
                text,
                hypothesis.get("primary_type", "unknown"),
                situation_stage,
            )
            results["scenario_sources"] = sources
            traces.append(
                {
                    "name": "scam_case_rag",
                    "status": "completed",
                    "summary": f"가설 유사 공식 사례 {len(sources)}건 검색",
                }
            )
        if "multimodal_context_analysis" in tool_names:
            results["multimodal"] = {"status": "structured", "source": "ocr_text"}
            traces.append({"name": "multimodal_context_analysis", "status": "completed", "summary": "OCR 결과에서 대화·URL·전화번호·요구 정황 구조화"})
        await self._write_audit(session_id, traces)
        return results, traces

    @staticmethod
    def _verify_institution_contact(institution: str | None, phones: list[str]) -> dict:
        official = OFFICIAL_INSTITUTION_NUMBERS.get(institution or "", set())
        normalized = ["".join(character for character in phone if character.isdigit()) for phone in phones]
        matched = [phone for phone in normalized if phone in official]
        if not phones:
            status = "no_phone"
        elif matched:
            status = "match"
        else:
            status = "mismatch"
        summary = (
            f"{institution} 공식번호와 일치"
            if status == "match"
            else f"{institution} 공식번호와 불일치"
            if status == "mismatch"
            else f"{institution} 비교 번호 없음"
        )
        return {
            "institution": institution,
            "status": status,
            "presented_numbers": normalized,
            "official_numbers": sorted(official),
            "matched_numbers": matched,
            "source_url": OFFICIAL_CONTACT_SOURCES.get(institution or ""),
            "score": 90 if status == "mismatch" else 0,
            "summary": summary,
            "notice": "표시 번호 일치는 발신번호 조작 가능성 때문에 신원을 보증하지 않습니다.",
        }

    @staticmethod
    def _verify_official_procedure(structured: dict) -> dict:
        institution = structured.get("institution")
        reasons: list[str] = []
        if structured.get("authentication_request"):
            reasons.append("금융기관 직원을 자처하며 인증번호 전달을 요구하는 절차는 공식 확인이 필요합니다.")
        if structured.get("personal_info_request"):
            reasons.append("메시지·통화 상대에게 비밀번호·신분증·카드정보를 전달하도록 요구합니다.")
        if structured.get("app_install_request"):
            reasons.append("기관 업무를 명분으로 앱·원격지원 설치를 요구합니다.")
        if structured.get("financial_request") and institution in {"경찰청", "검찰청", "금융감독원", "법원"}:
            reasons.append("공공·수사기관을 자처하며 송금 또는 자금 이동을 요구합니다.")
        if (
            structured.get("international_sender")
            and institution
            and structured.get("callback_request")
        ):
            reasons.append(
                "국제발신 메시지가 국내 기관을 자처하며 메시지에 표시된 번호로 연락을 유도합니다."
            )
        status = "inconsistent" if reasons else "needs_confirmation"
        return {
            "institution": institution,
            "status": status,
            "score": 90 if reasons else 0,
            "reasons": reasons or ["추출된 정보만으로 공식 절차 일치 여부를 확정할 수 없습니다."],
            "summary": f"{institution} 공식 절차와 {'불일치 정황' if reasons else '추가 확인 필요'}",
        }

    @staticmethod
    def _provider_result(item: dict, provider: str) -> dict:
        return next(
            (result for result in item.get("reputation", []) if result.get("provider") == provider),
            {"provider": provider, "status": "disabled", "score": 0},
        )

    def _url_components(self, item: dict) -> dict[str, dict]:
        reputation = item.get("reputation", [])
        threat_results = [
            result for result in reputation
            if result.get("provider") in {"google_safe_browsing", "virustotal"}
        ]
        whois = self._provider_result(item, "kisa_whois")
        threat_score = max((int(result.get("score", 0)) for result in threat_results), default=0)
        threat_reasons = [
            f"{result['provider']}: {result.get('status', 'unknown')}"
            for result in threat_results
        ] or ["활성화된 위협정보 provider가 없습니다."]
        domain_reasons = list(whois.get("reasons", []))
        if not domain_reasons:
            domain_reasons = [f"KISA WHOIS: {whois.get('status', 'disabled')}"]
        structure_score = int(item.get("score", 0))
        structure_reasons = list(item.get("reasons", []))
        for result in reputation:
            redirect_target = result.get("redirect_target")
            if redirect_target and redirect_target != item.get("url"):
                redirect_analysis = inspect_url(redirect_target)
                structure_score = max(structure_score, int(redirect_analysis.get("risk_score", 0)))
                structure_reasons.append(
                    f"{result['provider']} 확인 redirect 대상: {redirect_analysis.get('registrable_domain') or redirect_target}"
                )
        return {
            "threat_intelligence": {"score": threat_score, "reasons": threat_reasons},
            "domain_reputation": {"score": int(whois.get("score", 0)), "reasons": domain_reasons},
            "url_structure": {"score": structure_score, "reasons": structure_reasons},
        }

    async def _write_audit(self, session_id: str | None, traces: list[dict]) -> None:
        if not session_id or not traces:
            return
        created_at = datetime.now(UTC).isoformat()
        await supabase_gateway.insert(
            "tool_audit_logs",
            [
                {
                    "id": str(uuid4()),
                    "session_id": session_id,
                    "tool_name": trace["name"],
                    "status": trace["status"],
                    "summary": trace["summary"],
                    "created_at": created_at,
                }
                for trace in traces
            ],
        )
