"""ScamFlow Rule Engine, State, Tool, Graph 테스트."""

import pytest

from app.graph.edges import route_to_action_or_recovery
from app.graph.graph import get_scamflow_graph
from app.graph.state import create_initial_state
from app.schemas.chat import SituationStage
from app.services.context_extractor import extract_structured_context
from app.services.ocr import OcrService
from app.services.rules import SafetyPolicy, ScamRuleEngine
from app.tools.executor import ToolExecutor
from app.tools.scam_tools import inspect_phone, inspect_url


def test_initial_state_keeps_session_context():
    state = create_initial_state("session-1", "user-1")
    assert state["session_id"] == "session-1"
    assert state["user_id"] == "user-1"
    assert state["messages"] == []
    assert state["situation_stage"] == "received_message"


def test_multimodal_text_context_is_structured_for_agent():
    context = extract_structured_context(
        "엄마 임시폰이야. 전화는 안돼. 지금 상품권 핀번호 보내줘 https://fake.example"
    )
    assert context["new_contact"] is True
    assert context["urgency"] is True
    assert context["money_request"] is True
    assert context["family_impersonation"] is True
    assert context["urls"] == ["https://fake.example"]


def test_one_line_ocr_keeps_international_notice_separate_from_card_message():
    context = extract_structured_context(
        "00611787916328 [국제발신] [롯데카드] ****-2249카드 정상발급 "
        "(고객님 발급 아닌 경우 문의필수) 상담:02)605-1234 오전 11:03"
    )

    assert context["international_sender"] is True
    assert context["institution"] == "롯데카드"
    assert context["callback_request"] is True
    assert context["unauthorized_claim"] is True
    assert "롯데카드" in context["message_content"]
    assert "국제발신" not in context["message_content"]
    assert "00611787916328" in context["phone_numbers"]
    assert "02)605-1234" in context["phone_numbers"]


def test_document_parse_html_preserves_message_line_boundaries():
    text = OcrService()._collect_text(
        "<p>[국제발신]</p><p>[롯데카드]</p><p>발급 아닌 경우 상담:02-605-1234</p>"
    )

    assert text.splitlines() == [
        "[국제발신]",
        "[롯데카드]",
        "발급 아닌 경우 상담:02-605-1234",
    ]


def test_family_relationship_words_alone_are_not_impersonation_evidence():
    normal = extract_structured_context(
        "엄마가 너도 빨리 집에 오라고 했어. 학교 끝나면 픽업하고 갈 때 전화할게."
    )
    compound = extract_structured_context(
        "엄마 새 번호야. 전화는 안돼. 급하니 상품권 핀번호 보내줘."
    )

    assert normal["relationship_mention"] is True
    assert normal["family_impersonation"] is False
    assert normal["direct_contact_willingness"] is True
    assert normal["everyday_conversation"] is True
    assert compound["family_impersonation"] is True


def test_ambiguous_family_opening_becomes_identity_verification_scenario():
    text = "엄마 나 폰고장나서 AS 맡겼어. 꼭 좀 부탁할거있어. 문자확인하는대로 답장줄래?"
    structured = extract_structured_context(text)
    result = ScamRuleEngine().detect(
        text, SituationStage.RECEIVED_MESSAGE, structured
    )

    assert structured["identity_grooming"] is True
    assert structured["family_impersonation"] is False
    assert structured["money_request"] is False
    assert structured["channel_restriction"] is True
    assert result.scam_type == "unknown"
    assert result.risk_score < 45
    assert result.scenario_assessment["status"] == "verification_required"
    assert result.scenario_assessment["stage"] == "identity_grooming"
    assert result.highlights


def test_negative_evidence_blocks_solar_family_false_positive():
    text = "엄마가 집에 빨리 오라고 했어. 학교 픽업하고 갈 때 전화할게."
    structured = extract_structured_context(text)
    engine = ScamRuleEngine()
    initial = engine.detect(text, SituationStage.RECEIVED_MESSAGE, structured)
    merged = engine.merge_verified_evidence(
        initial,
        SituationStage.RECEIVED_MESSAGE,
        solar_candidate={
            "scam_type": "family_impersonation",
            "confidence": 0.95,
            "risk_score": 90,
            "highlights": [
                {
                    "phrase": "엄마",
                    "reason": "가족 관계 표현",
                    "category": "relationship",
                    "strength": 3,
                }
            ],
            "negative_evidence": [
                {
                    "phrase": "전화할게",
                    "reason": "직접 통화 의사",
                    "category": "direct_contact",
                    "strength": 3,
                }
            ],
        },
        tool_results={},
        structured_input=structured,
    )

    assert merged.scam_type != "family_impersonation"
    assert merged.risk_level == "low"
    assert merged.negative_evidence
    assert merged.risk_breakdown["negative_evidence_score"] > 0


@pytest.mark.parametrize(
    ("text", "expected_type", "minimum_score"),
    [
        ("엄마 폰 액정 깨져서 전화 안돼. 지금 상품권 핀번호 보내줘", "family_impersonation", 54),
        ("검찰입니다. 대포통장 연루됐으니 안전계좌로 이체하세요", "institution_impersonation", 54),
        ("저금리 대환 승인, 예치금을 가상계좌로 선입금", "loan_fraud", 54),
        ("택배 배송 확인 http://delivery-check.xyz/app.apk", "smishing", 35),
        ("원금 보장 고수익 리딩방, 상장 예정 코인", "investment_fraud", 54),
        ("TeamViewer 원격지원 앱을 설치하세요", "remote_control_app", 54),
    ],
)
def test_rule_engine_classifies_major_scam_types(text, expected_type, minimum_score):
    result = ScamRuleEngine().detect(text, SituationStage.RECEIVED_MESSAGE)
    assert result.scam_type == expected_type
    assert result.risk_score >= minimum_score


def test_unconfirmed_transfer_is_separate_from_scam_likelihood():
    result = ScamRuleEngine().detect(
        "돈을 보냈습니다", SituationStage.TRANSFERRED_MONEY,
        stage_confirmation="needs_confirmation",
    )
    assert result.risk_score < 45
    assert result.risk_breakdown["stage_confirmation"] == "needs_confirmation"
    assert result.risk_breakdown["response_urgency"] == "caution"
    assert route_to_action_or_recovery({
        "situation_stage": "transferred_money",
        "stage_confirmation": "needs_confirmation",
    }) == "action"
    assert route_to_action_or_recovery({
        "situation_stage": "transferred_money",
        "stage_confirmation": "confirmed",
    }) == "recovery"


def test_external_malicious_url_evidence_can_only_raise_risk():
    engine = ScamRuleEngine()
    initial = engine.detect("처음 보는 주소입니다", SituationStage.RECEIVED_MESSAGE)
    merged = engine.merge_verified_evidence(
        initial,
        SituationStage.RECEIVED_MESSAGE,
        solar_candidate={},
        tool_results={
            "urls": [
                {
                    "host": "fake.example",
                    "reputation": [
                        {"provider": "virustotal", "status": "malicious"}
                    ],
                }
            ]
        },
    )
    assert merged.scam_type == "smishing"
    assert merged.risk_score >= 92
    assert merged.risk_score >= initial.risk_score


def test_solar_candidate_cannot_turn_reported_stage_into_scam_score():
    engine = ScamRuleEngine()
    initial = engine.detect("이미 송금했습니다", SituationStage.TRANSFERRED_MONEY)
    merged = engine.merge_verified_evidence(
        initial,
        SituationStage.TRANSFERRED_MONEY,
        solar_candidate={
            "scam_type": "safe_message",
            "confidence": 0.99,
            "risk_score": 1,
            "highlights": [],
        },
        tool_results={},
    )
    assert merged.risk_score < 45
    assert merged.risk_breakdown["stage_confirmation"] == "needs_confirmation"


def test_safety_policy_requires_approval_for_external_calls():
    actions = SafetyPolicy().actions_for(
        "unknown", SituationStage.TRANSFERRED_MONEY, "confirmed"
    )
    assert actions[0]["target"] == "112"
    assert actions[0]["requires_approval"] is True
    assert all(action["action_type"] != "transfer" for action in actions)


def test_safety_policy_rejects_unsafe_solar_next_action():
    policy = SafetyPolicy()
    fallback = "기존 가족 번호로 직접 확인"
    assert policy.validate_next_action(
        "안전한 거래이므로 송금해도 됩니다.", fallback, "trusted-family-contact"
    ) == fallback
    assert policy.validate_next_action(
        "즉시 112에 신고하고 지급정지를 요청하세요.",
        fallback,
        "trusted-family-contact",
    ) == fallback
    assert policy.validate_next_action(
        "기존 연락처로 가족에게 직접 확인하세요.",
        fallback,
        "trusted-family-contact",
    ) != fallback
    assert policy.validate_explanation(
        "확인 결과 안전한 거래이므로 송금해도 됩니다.", "안전 보증 불가"
    ) == "안전 보증 불가"


def test_url_and_phone_tools_do_not_overpromise_identity():
    url = inspect_url("http://delivery-check.xyz/app.apk")
    phone = inspect_phone("112")
    assert url["risk"] == "suspicious"
    assert phone["is_known_official"] is True
    assert "보증할 수 없습니다" in phone["notice"]


@pytest.mark.asyncio
async def test_tool_selection_and_graph_flow():
    executor = ToolExecutor()
    tool_message = "검찰입니다. 즉시 010-1234-5678로 전화하세요. http://fake.xyz"
    tools = executor.select_tools(
        tool_message,
        structured=extract_structured_context(tool_message),
    )
    assert {"inspect_url", "inspect_phone"}.issubset(tools)
    assert "official_rag_search" not in tools
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("graph-session"),
            "user_input": "엄마 액정 깨져서 전화 안돼. 지금 상품권 보내줘",
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )
    assert result["detection"]["scam_type"] == "family_impersonation"
    assert result["flow_stage"] == "action"
    assert result["sources"]
    assert result["actions"][0]["id"] == "trusted-family-contact"
    assert any(tool["name"] == "official_rag_search" for tool in result["tools_used"])


@pytest.mark.asyncio
async def test_normal_url_click_keeps_url_and_situation_risk_separate():
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("normal-url-session"),
            "user_input": "https://www.naver.com/",
            "input_mode": "url_phone",
            "situation_stage": "clicked_link",
        }
    )
    breakdown = result["detection"]["risk_breakdown"]
    assert breakdown["url_risk"] <= 10
    assert breakdown["situation_risk"] == 15
    assert result["detection"]["risk_score"] < 45
    assert result["detection"]["scam_type"] == "safe_message"
    assert result["needs_rag"] is False
    assert result["solar_selected"] is False
    assert not result["sources"]
    assert result["detection"]["headline"] == "현재 확인된 위험 신호가 없습니다."
    assert breakdown["url_structure"]["score"] <= 8
    assert breakdown["exposure_risk"]["score"] == 15
    assert breakdown["exposure_risk"]["score"] == breakdown["situation_risk"]


def test_registrable_domain_allowlist_rejects_deceptive_subdomain():
    official = inspect_url("https://news.naver.com/article/1")
    deceptive = inspect_url("https://naver.com.login.evil-example.xyz/account")

    assert official["registrable_domain"] == "naver.com"
    assert official["is_allowlisted"] is True
    assert official["risk_score"] <= 8
    assert deceptive["registrable_domain"] == "evil-example.xyz"
    assert deceptive["is_allowlisted"] is False
    assert deceptive["risk_score"] >= 45


def test_url_rule_engine_detects_ip_punycode_at_shortener_and_redirect():
    assert inspect_url("http://192.0.2.1/login")["risk_score"] >= 45
    assert inspect_url("https://xn--navr-8za.example/")["risk_score"] >= 24
    assert inspect_url("https://naver.com@evil.example/login")["risk_score"] >= 45
    assert inspect_url("https://bit.ly/example")["risk_score"] >= 30
    assert inspect_url("https://example.com/?redirect=https://evil.example")["risk_score"] >= 14


def test_recent_domain_and_phishing_context_create_high_composite_risk():
    text = "검찰입니다. 대포통장 사건이니 안전계좌 확인을 위해 개인정보를 지금 입력하세요."
    structured = extract_structured_context(text)
    engine = ScamRuleEngine()
    initial = engine.detect(text, SituationStage.RECEIVED_MESSAGE, structured)
    merged = engine.merge_verified_evidence(
        initial,
        SituationStage.RECEIVED_MESSAGE,
        solar_candidate={},
        tool_results={
            "urls": [{
                "risk_score": 85,
                "risk_components": {
                    "threat_intelligence": {"score": 0, "reasons": ["미탐지"]},
                    "domain_reputation": {"score": 85, "reasons": ["등록 후 3일인 신규 도메인"]},
                    "url_structure": {"score": 38, "reasons": ["기관 사칭 유사 도메인"]},
                },
                "reputation": [{"provider": "kisa_whois", "status": "found", "score": 85}],
            }]
        },
        structured_input=structured,
    )

    assert merged.risk_score >= 85
    assert merged.risk_breakdown["domain_reputation"]["score"] == 85
    assert merged.risk_breakdown["threat_intelligence"]["score"] == 0


@pytest.mark.asyncio
async def test_suspicious_url_and_phishing_context_raise_fused_risk():
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("phishing-url-session"),
            "user_input": "택배 배송이 중단됐습니다. 지금 http://delivery-check.xyz/app.apk 설치하세요",
            "input_mode": "url_phone",
            "situation_stage": "clicked_link",
        }
    )
    breakdown = result["detection"]["risk_breakdown"]
    assert breakdown["url_risk"] >= 45
    assert breakdown["financial_credential_request"]["score"] >= 90
    assert result["detection"]["risk_score"] >= 85
    assert result["needs_rag"] is True
    assert result["sources"]


@pytest.mark.asyncio
async def test_orchestrator_can_skip_tool_node_and_select_multimodal_conditionally():
    executor = ToolExecutor()
    assert executor.select_tools("일반적인 상황 설명", "text") == []
    assert "multimodal_context_analysis" in executor.select_tools(
        "OCR로 추출한 대화", "image_ocr"
    )
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("no-tool-session"),
            "user_input": "잘 모르겠지만 이상한 연락을 받았습니다",
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )
    assert result["selected_tools"] == []
    assert [trace["name"] for trace in result["tools_used"]] == [
        "entity_event_extraction",
        "scenario_hypothesis",
        "agent_orchestrator",
    ]
    assert result["needs_rag"] is False
