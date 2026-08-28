"""전체 대화 Event 관계에서 사기 가설과 축별 근거를 생성합니다."""

from dataclasses import dataclass

SCENARIO_LABELS = {
    "family_impersonation": "가족·지인 사칭",
    "financial_institution_impersonation": "금융기관 사칭",
    "government_impersonation": "정부·수사기관 사칭",
    "delivery_customs_smishing": "택배·통관 스미싱",
    "card_payment_impersonation": "카드·결제 사칭",
    "investment_fraud": "투자 사기",
    "loan_fraud": "대출 사기",
    "gift_card_request": "상품권 구매 요구",
    "credential_theft": "개인정보·인증번호 탈취",
    "malicious_app": "악성 앱 설치 유도",
    "safe_message": "정상 상황",
    "unknown": "판단 불가",
}


@dataclass(frozen=True)
class Candidate:
    scenario_type: str
    confidence: float
    evidence: tuple[str, ...]
    relationships: tuple[str, ...]


class ScenarioUnderstandingService:
    """단일 키워드가 아닌 Entity/Event 조합을 시나리오 후보로 변환합니다."""

    def analyze(self, structured: dict) -> dict:
        candidates = self._candidates(structured)
        candidates.sort(key=lambda item: item.confidence, reverse=True)
        if not candidates:
            candidates = [
                Candidate(
                    "safe_message" if structured.get("everyday_conversation") else "unknown",
                    0.82 if structured.get("everyday_conversation") else 0.55,
                    ("일상 대화 흐름" if structured.get("everyday_conversation") else "판단 가능한 복합 Event 부족",),
                    (),
                )
            ]
        top = candidates[0]
        confidence_map = self._confidence_map(candidates)
        scenario_score = (
            5
            if top.scenario_type == "safe_message"
            else 10
            if top.scenario_type == "unknown"
            else round(top.confidence * 100)
        )
        return {
            "primary_type": top.scenario_type,
            "label": SCENARIO_LABELS[top.scenario_type],
            "confidence": top.confidence,
            "confidences": confidence_map,
            "evidence": list(top.evidence),
            "relationships": list(top.relationships),
            "requires_external_verification": self._verification_needs(structured, top),
            "risk_axes": {
                "scenario_pattern": {
                    "score": scenario_score,
                    "reasons": list(top.relationships or top.evidence),
                },
                "identity_risk": self._identity_axis(structured),
                "financial_credential_request": self._request_axis(structured),
                "external_verification": {
                    "score": 0,
                    "reasons": ["외부 근거 검증 전입니다."],
                },
            },
            "source": "scenario-pattern-engine",
        }

    def merge_llm(self, local: dict, llm: dict) -> dict:
        """검증된 LLM 가설은 로컬 후보를 보강하되 고위험 로컬 관계를 지우지 않습니다."""
        if not llm:
            return local
        scenario_type = llm.get("primary_type")
        try:
            confidence = float(llm.get("confidence", 0))
        except (TypeError, ValueError):
            return local
        if scenario_type not in SCENARIO_LABELS or not 0 <= confidence <= 1:
            return local
        merged = {**local}
        merged["llm_candidate"] = {
            "primary_type": scenario_type,
            "confidence": confidence,
            "reasoning": list(llm.get("reasoning", []))[:6],
        }
        if confidence >= 0.72 and (
            local["primary_type"] in {"unknown", "safe_message"}
            or confidence > float(local["confidence"]) + 0.08
        ):
            merged["primary_type"] = scenario_type
            merged["label"] = SCENARIO_LABELS[scenario_type]
            merged["confidence"] = confidence
            merged["evidence"] = list(dict.fromkeys([*local["evidence"], *llm.get("evidence", [])]))[:6]
            merged["relationships"] = list(dict.fromkeys([*local["relationships"], *llm.get("reasoning", [])]))[:6]
            merged["risk_axes"] = {
                **local["risk_axes"],
                "scenario_pattern": {
                    "score": round(confidence * 100),
                    "reasons": merged["relationships"] or merged["evidence"],
                },
            }
        merged["source"] = "hybrid-scenario-reasoning"
        return merged

    def apply_external_evidence(self, hypothesis: dict, tool_results: dict) -> dict:
        axis_score = 0
        reasons: list[str] = []
        verification = tool_results.get("institution_verification")
        if verification:
            status = verification.get("status")
            if status == "mismatch":
                axis_score = max(axis_score, 90)
                reasons.append("표시된 번호가 사칭 기관의 공식번호와 일치하지 않습니다.")
            elif status == "match":
                reasons.append("표시 번호는 공식번호와 일치하지만 발신번호 조작 가능성은 남습니다.")
            elif status == "no_phone":
                reasons.append("비교할 발신번호가 없어 기관 사칭 여부를 확정할 수 없습니다.")
        procedure = tool_results.get("official_procedure")
        if procedure and procedure.get("status") == "inconsistent":
            axis_score = max(axis_score, int(procedure.get("score", 85)))
            reasons.extend(procedure.get("reasons", []))
        phone_results = tool_results.get("phones", [])
        if phone_results and not any(item.get("is_known_official") for item in phone_results):
            axis_score = max(axis_score, 65)
            reasons.append("입력된 전화번호가 공식 연락처 원장에서 확인되지 않았습니다.")
        merged = {**hypothesis, "risk_axes": {**hypothesis["risk_axes"]}}
        merged["risk_axes"]["external_verification"] = {
            "score": axis_score,
            "reasons": list(dict.fromkeys(reasons))[:6] or ["외부 검증에서 추가 위험 근거가 확인되지 않았습니다."],
        }
        return merged

    def _candidates(self, s: dict) -> list[Candidate]:
        candidates: list[Candidate] = []
        if (
            s.get("relationship_mention")
            and (s.get("new_contact") or s.get("device_failure_pretext"))
            and any(
                s.get(key)
                for key in (
                    "financial_request",
                    "personal_info_request",
                    "gift_card_request",
                    "account_use_request",
                    "proxy_action_request",
                    "app_install_request",
                )
            )
        ):
            strength = sum(
                bool(s.get(key))
                for key in (
                    "urgency",
                    "contact_avoidance",
                    "channel_restriction",
                    "financial_request",
                    "gift_card_request",
                    "account_use_request",
                    "proxy_action_request",
                )
            )
            confidence = min(0.97, 0.58 + strength * 0.075)
            relationships = ["가족 주장 → 휴대전화 고장·새 연락처"]
            if s.get("urgency"):
                relationships.append("새 연락수단 → 긴급성으로 확인 시간 축소")
            if s.get("gift_card_request"):
                relationships.append("본인 확인 회피 → 현금성 상품권 구매 요구")
            if s.get("account_use_request") or s.get("proxy_action_request"):
                relationships.append("본인이 직접 할 수 없다고 주장 → 상대방 명의·대리 행동 요구")
            candidates.append(
                Candidate(
                    "family_impersonation",
                    confidence,
                    tuple(self._event_labels(s, "relationship_mention", "device_failure_pretext", "gift_card_request", "account_use_request", "urgency")),
                    tuple(relationships),
                )
            )
        institution = s.get("institution")
        suspicious_institution_event = any(
            s.get(key)
            for key in (
                "authentication_request",
                "personal_info_request",
                "financial_request",
                "urgency",
                "link_access_request",
                "app_install_request",
                "international_sender",
                "callback_request",
                "unauthorized_claim",
            )
        )
        if institution and suspicious_institution_event:
            if institution in {"경찰청", "검찰청", "금융감독원", "법원"}:
                candidates.append(
                    Candidate(
                        "government_impersonation",
                        min(0.96, 0.62 + 0.11 * sum(bool(s.get(k)) for k in ("urgency", "financial_request", "personal_info_request", "app_install_request"))),
                        (f"{institution} 명칭 사용",),
                        ("공공기관 신뢰 주장 → 금전·정보·앱 요구 검증 필요",),
                    )
                )
            elif "카드" in institution:
                card_signal_score = (
                    0.18 * bool(s.get("international_sender"))
                    + 0.08 * bool(s.get("phone_number_present"))
                    + 0.11 * bool(s.get("financial_request"))
                    + 0.11 * bool(s.get("authentication_request"))
                    + 0.12 * bool(s.get("callback_request"))
                    + 0.10 * bool(s.get("unauthorized_claim"))
                )
                relationships = ["카드사 명칭 사용 → 발신 경로와 공식 연락처 검증 필요"]
                if s.get("international_sender"):
                    relationships.append("국제발신 → 국내 카드사 명칭 사용")
                if s.get("unauthorized_claim") and s.get("callback_request"):
                    relationships.append("미신청·미승인 거래 불안 조성 → 표시 번호로 문의 유도")
                candidates.append(
                    Candidate(
                        "card_payment_impersonation",
                        min(0.97, 0.55 + card_signal_score),
                        tuple(
                            [f"{institution} 명칭 사용"]
                            + (["국제발신 시스템 안내"] if s.get("international_sender") else [])
                            + (["미신청·미승인 거래 문의 유도"] if s.get("unauthorized_claim") else [])
                        ),
                        tuple(relationships),
                    )
                )
            elif institution == "관세청":
                customs_signal_score = (
                    0.14 * bool(s.get("financial_request"))
                    + 0.12 * bool(s.get("link_access_request"))
                    + 0.10 * bool(s.get("urgency"))
                    + 0.12 * bool(s.get("international_sender"))
                    + 0.10 * bool(s.get("callback_request"))
                    + 0.08 * bool(s.get("unauthorized_claim"))
                    + 0.08 * bool(s.get("account_problem_claim"))
                )
                relationships = ["통관 문제 주장 → 미납 세금·표시 연락처의 공식 절차 검증 필요"]
                if s.get("international_sender"):
                    relationships.append("국제발신 → 국내 관세청 명칭 사용")
                if s.get("unauthorized_claim") and s.get("callback_request"):
                    relationships.append("본인 거래가 아니라는 불안 조성 → 표시 번호로 문의 유도")
                candidates.append(
                    Candidate(
                        "delivery_customs_smishing",
                        min(0.96, 0.52 + customs_signal_score),
                        tuple(
                            ["통관·세관 명칭 사용"]
                            + (["국제발신 시스템 안내"] if s.get("international_sender") else [])
                            + (["미납 세금 처리 예고"] if s.get("account_problem_claim") else [])
                        ),
                        tuple(relationships),
                    )
                )
            else:
                candidates.append(
                    Candidate(
                        "financial_institution_impersonation",
                        min(0.96, 0.58 + 0.12 * sum(bool(s.get(k)) for k in ("authentication_request", "personal_info_request", "phone_number_present", "urgency"))),
                        (f"{institution} 명칭 사용",),
                        ("금융기관 주장 → 인증정보·표시 번호의 공식 절차 일치 여부 검증 필요",),
                    )
                )
        if s.get("gift_card_request"):
            candidates.append(Candidate("gift_card_request", 0.86, ("상품권·핀번호 요구",), ("현금성 자산 구매 → 코드 전달 요구 가능성",)))
        if s.get("authentication_request") or s.get("personal_info_request"):
            candidates.append(Candidate("credential_theft", 0.84 if s.get("authentication_request") else 0.74, tuple(self._event_labels(s, "authentication_request", "personal_info_request")), ("신뢰 주체 주장 → 인증·개인정보 제공 요구",)))
        if s.get("app_install_request"):
            candidates.append(Candidate("malicious_app", 0.93, ("앱·원격지원 설치 요구",), ("문제 해결 명분 → 기기 제어권 획득 시도",)))
        text = str(s.get("message_content", "")).lower()
        if any(word in text for word in ("택배", "배송", "배달", "주문 주소", "통관", "관세", "세금 미납")) and (
            s.get("url_present")
            or s.get("link_access_request")
            or s.get("financial_request")
            or s.get("personal_info_request")
        ):
            candidates.append(Candidate("delivery_customs_smishing", 0.88, ("택배·통관 문제", "링크 또는 비용 요구"), ("배송 문제 제시 → 즉시 조회·납부 유도",)))
        if any(word in text for word in ("수익 보장", "리딩방", "상장 예정", "고수익", "원금 보장")):
            candidates.append(Candidate("investment_fraud", 0.86, ("비정상적 투자 이익 약속",), ("고수익 약속 → 입금·추가 비용 요구",)))
        if any(word in text for word in ("저금리", "대환", "선입금", "보증료", "대출 승인")):
            candidates.append(Candidate("loan_fraud", 0.84, ("대출 조건·선입금 요구",), ("대출 승인 명분 → 선입금·보증료 요구",)))
        informational_purposes = {
            "fee_change_notice",
            "transaction_notice",
            "authentication_notice",
            "delivery_notice",
            "informational_notice",
        }
        validated_risk_events = (
            "money_transfer_request",
            "payment_request",
            "gift_card_request",
            "credential_request",
            "personal_info_request",
            "url_click_request",
            "contact_request",
            "app_install_request",
            "proxy_action_request",
        )
        if (
            s.get("message_purpose") in informational_purposes
            and not any(s.get(key) for key in validated_risk_events)
        ):
            candidates.append(
                Candidate(
                    "safe_message",
                    0.95,
                    tuple(s.get("benign_signals", [])[:5]) or ("정보성 안내",),
                    (),
                )
            )
        if s.get("protective_notice") and not suspicious_institution_event:
            candidates.append(
                Candidate(
                    "safe_message",
                    0.82,
                    ("인증정보를 타인에게 제공하지 말라는 보호 안내",),
                    (),
                )
            )
        return candidates

    @staticmethod
    def _confidence_map(candidates: list[Candidate]) -> dict[str, float]:
        values = {candidate.scenario_type: candidate.confidence for candidate in candidates[:3]}
        values.setdefault("safe_message", 0.04 if candidates[0].scenario_type != "safe_message" else candidates[0].confidence)
        values.setdefault("unknown", max(0.01, 1 - max(values.values())))
        total = sum(values.values()) or 1
        return {key: round(value / total, 3) for key, value in values.items()}

    @staticmethod
    def _event_labels(s: dict, *keys: str) -> list[str]:
        labels = {
            "relationship_mention": "가족 관계 주장",
            "device_failure_pretext": "휴대전화 고장 주장",
            "gift_card_request": "상품권 요구",
            "account_use_request": "타인 명의 사용 요구",
            "urgency": "긴급성 표현",
            "authentication_request": "인증번호 요구",
            "personal_info_request": "개인정보 요구",
        }
        return [labels[key] for key in keys if s.get(key)]

    @staticmethod
    def _verification_needs(s: dict, candidate: Candidate) -> list[str]:
        needs: list[str] = []
        if s.get("urls"):
            needs.append("url_reputation")
        if s.get("phone_numbers") and (
            s.get("contact_request") or s.get("institution_impersonation")
        ):
            needs.append("official_phone_match")
        if s.get("institution") and s.get("institution_impersonation"):
            needs.extend(["official_contact", "official_procedure"])
        if candidate.scenario_type not in {"safe_message", "unknown"}:
            needs.append("scam_case_rag")
        return list(dict.fromkeys(needs))

    @staticmethod
    def _identity_axis(s: dict) -> dict:
        score = 0
        reasons: list[str] = []
        if s.get("claimed_identity") or s.get("relationship_mention"):
            score = 35
            reasons.append("가족·지인 관계를 신원 근거로 주장합니다.")
        if s.get("institution"):
            score = max(score, 40)
            reasons.append(f"{s['institution']} 명칭을 신뢰 근거로 사용합니다.")
        if s.get("new_contact") or s.get("device_failure_pretext"):
            score = max(score, 70)
            reasons.append("기존 연락수단을 사용할 수 없다는 명분이 있습니다.")
        if s.get("international_sender") and s.get("institution"):
            score = max(score, 80)
            reasons.append("국제발신 안내와 국내 기관 주장이 함께 확인됩니다.")
        return {"score": score, "reasons": reasons or ["명시적인 신원 사칭 근거가 없습니다."]}

    @staticmethod
    def _request_axis(s: dict) -> dict:
        scores = {
            "financial_request": 65,
            "gift_card_request": 90,
            "bank_transfer_request": 85,
            "authentication_request": 90,
            "personal_info_request": 80,
            "account_use_request": 80,
            "app_install_request": 95,
            "callback_request": 65,
            "unauthorized_claim": 55,
            "link_access_request": 75,
            "external_url_present": 55,
        }
        present = [key for key in scores if s.get(key)]
        if (
            s.get("url_present")
            and (
                s.get("institution") == "관세청"
                or s.get("message_purpose") in {"delivery_notice", "customs_notice"}
            )
        ):
            present.append("external_url_present")
        labels = {
            "financial_request": "금전 요구",
            "gift_card_request": "상품권·핀번호 요구",
            "bank_transfer_request": "계좌이체 요구",
            "authentication_request": "인증번호 요구",
            "personal_info_request": "개인정보 요구",
            "account_use_request": "타인 명의 사용 요구",
            "app_install_request": "앱 설치 요구",
            "callback_request": "표시된 상담번호로 연락 유도",
            "unauthorized_claim": "미신청·미승인 거래 불안 조성",
            "link_access_request": "외부 URL 접속 유도",
            "external_url_present": "배송·통관 안내에 외부 URL 포함",
        }
        score = max((scores[key] for key in present), default=0)
        reasons = [labels[key] for key in present]
        if s.get("url_present") and any(
            s.get(key)
            for key in (
                "financial_request",
                "personal_info_request",
                "authentication_request",
                "app_install_request",
            )
        ):
            score = max(score, 85)
            reasons.append("외부 URL과 금전·정보·인증 행동 요구가 결합됨")
        return {
            "score": score,
            "reasons": reasons or ["금전·인증정보·앱 설치 요구가 확인되지 않았습니다."],
        }
