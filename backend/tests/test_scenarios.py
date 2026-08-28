"""대표 금융사기 상황을 Agent Orchestrator 전체 경로로 검증합니다."""

import pytest

from app.graph.graph import get_scamflow_graph
from app.graph.state import create_initial_state

SCENARIOS = [
    {
        "id": "normal-clicked-url",
        "message": "https://www.naver.com/",
        "mode": "url_phone",
        "stage": "clicked_link",
        "level": "low",
        "flow": "action",
        "tool": "inspect_url",
        "rag": False,
        "urgency": "caution",
    },
    {
        "id": "family-gift-card",
        "message": "엄마 나 임시폰이야. 전화는 안돼. 급하니까 상품권 핀번호를 지금 보내줘.",
        "mode": "text",
        "stage": "received_message",
        "level": "critical",
        "flow": "action",
        "tool": "scam_case_rag",
        "rag": True,
        "urgency": "routine",
    },
    {
        "id": "institution-safe-account",
        "message": "검찰입니다. 대포통장에 연루됐으니 금감원 안전계좌로 즉시 송금하세요.",
        "mode": "text",
        "stage": "received_message",
        "level": "critical",
        "flow": "action",
        "tool": "verify_official_procedure",
        "rag": True,
        "urgency": "routine",
    },
    {
        "id": "delivery-apk",
        "message": "택배 배송 오류입니다. http://delivery-check.xyz/app.apk 앱을 설치하세요.",
        "mode": "url_phone",
        "stage": "clicked_link",
        "level": "critical",
        "flow": "action",
        "tool": "inspect_url",
        "rag": True,
        "urgency": "caution",
    },
    {
        "id": "personal-info-entered",
        "message": "링크에서 주민등록번호와 계좌 정보를 입력했습니다.",
        "mode": "text",
        "stage": "entered_info",
        # Scam Likelihood와 피해 단계는 분리합니다. 입력 피해는 urgency로 표현합니다.
        "level": "low",
        "flow": "recovery",
        "tool": "inspect_url",
        "rag": True,
        "urgency": "urgent",
    },
    {
        "id": "remote-app-installed",
        "message": "상대가 보안앱이라고 한 애니데스크 원격지원 앱을 설치했습니다.",
        "mode": "text",
        "stage": "installed_app",
        # 앱 설치 피해는 Scam Likelihood를 왜곡하지 않고 exposure/urgency로 강제 대응합니다.
        "level": "low",
        "flow": "recovery",
        "tool": None,
        "rag": True,
        "urgency": "critical",
    },
    {
        "id": "money-transferred",
        "message": "사기 의심 계좌로 이미 돈을 송금했습니다.",
        "mode": "text",
        "stage": "transferred_money",
        "level": "low",
        "flow": "recovery",
        "tool": None,
        "rag": True,
        "urgency": "critical",
    },
]


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda item: item["id"])
async def test_representative_scamflow_scenario(scenario):
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state(f"scenario-{scenario['id']}"),
            "user_input": scenario["message"],
            "input_mode": scenario["mode"],
            "situation_stage": scenario["stage"],
            "stage_confirmation": "confirmed" if scenario["stage"] == "transferred_money" else "not_required",
        }
    )

    assert result["detection"]["risk_level"] == scenario["level"]
    assert result["flow_stage"] == scenario["flow"]
    assert result["needs_rag"] is scenario["rag"]
    assert bool(result["sources"]) is scenario["rag"]
    assert "안전을 보증하지 않습니다" in result["safety_notice"]

    selected = result["selected_tools"]
    if scenario["tool"]:
        assert scenario["tool"] in selected
    else:
        assert selected == []

    breakdown = result["detection"]["risk_breakdown"]
    assert breakdown["response_urgency"] == scenario["urgency"]
    if scenario["stage"] == "clicked_link":
        assert breakdown["situation_risk"] == 15
    if scenario["stage"] == "entered_info":
        assert breakdown["situation_risk"] == 55
    if scenario["stage"] == "installed_app":
        assert breakdown["situation_risk"] == 85
    if scenario["stage"] == "transferred_money":
        assert breakdown["situation_risk"] == 100


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("message", "expected_type", "required_tools"),
    [
        (
            "우리은행입니다. 본인 확인을 위해 문자 인증번호를 알려주세요. 문의 010-7777-8888",
            "credential_theft",
            {"inspect_phone", "verify_institution_contact", "verify_official_procedure"},
        ),
        (
            "엄마 나 폰 고장나서 새 번호야. 급해. 엄마 명의로 문화상품권을 대신 사서 핀번호 보내줘.",
            "family_impersonation",
            {"scam_case_rag"},
        ),
        (
            "방금 수신한 문자메시지는 해외에서 발송되었습니다.\n롯데카드 결제 승인 안내입니다. 010-1111-2222로 확인하세요.",
            "card_payment_impersonation",
            {"inspect_phone", "verify_institution_contact"},
        ),
        (
            "관세청 통관 세금이 미납되었습니다. 오늘까지 https://customs-pay.example 납부하세요.",
            "delivery_customs_smishing",
            {"inspect_url", "verify_official_procedure"},
        ),
    ],
)
async def test_scenario_hypothesis_precedes_verification_and_exposure(
    message, expected_type, required_tools
):
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state(f"hypothesis-{expected_type}"),
            "user_input": message,
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )

    assert result["scenario_hypothesis"]["primary_type"] == expected_type
    assert required_tools.issubset(set(result["selected_tools"]))
    assert result["detection"]["risk_score"] >= 80
    assert result["detection"]["risk_breakdown"]["exposure_risk"]["score"] == 0
    assert result["detection"]["risk_breakdown"]["scenario_pattern"]["score"] >= 80


@pytest.mark.asyncio
async def test_received_message_does_not_reduce_family_gift_card_likelihood():
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("family-message-received"),
            "user_input": "엄마 나 임시폰이야. 통화 못해. 급하니까 문화상품권을 대신 사서 핀번호 보내줘.",
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )

    assert result["detection"]["risk_score"] >= 85
    assert result["detection"]["risk_breakdown"]["situation_risk"] == 0
    assert result["detection"]["headline"] == "사기 가능성이 높은 연락이지만 아직 피해 전 단계입니다."
    assert result["actions"][0]["id"] == "trusted-family-contact"


@pytest.mark.asyncio
async def test_international_lotte_card_callback_is_high_risk_before_exposure():
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("international-lotte-card"),
            "user_input": (
                "[국제발신] [롯데카드] ****-2249카드 정상발급 "
                "(고객님 발급 아닌 경우 문의필수) 상담:02)605-1234"
            ),
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )

    assert result["structured_input"]["international_sender"] is True
    assert result["structured_input"]["callback_request"] is True
    assert result["scenario_hypothesis"]["primary_type"] == "card_payment_impersonation"
    assert result["detection"]["risk_score"] >= 85
    assert result["detection"]["risk_breakdown"]["exposure_risk"]["score"] == 0
    assert "verify_institution_contact" in result["selected_tools"]


@pytest.mark.asyncio
async def test_international_customs_callback_is_critical_before_exposure():
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("international-customs-callback"),
            "user_input": (
                "[통관세금미납안내]세금합계:448,000원(8개월분)금일 정상처리 예정 "
                "본인 아닌 경우 통관국 관세청 ☎02.470.6517\n"
                "방금 수신한 문자메시지는 해외에서 발송되었습니다."
            ),
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )

    assert result["structured_input"]["international_sender"] is True
    assert result["structured_input"]["callback_request"] is True
    assert result["structured_input"]["unauthorized_claim"] is True
    assert result["scenario_hypothesis"]["primary_type"] == "delivery_customs_smishing"
    assert result["detection"]["risk_score"] >= 85
    assert result["detection"]["risk_level"] == "critical"
    assert result["detection"]["risk_breakdown"]["exposure_risk"]["score"] == 0
    assert "verify_institution_contact" in result["selected_tools"]
    assert "verify_official_procedure" in result["selected_tools"]


@pytest.mark.asyncio
async def test_institution_name_and_official_number_alone_do_not_create_high_risk():
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("customs-official-information"),
            "user_input": "관세청 통관 제도 안내입니다. 문의는 고객지원센터 125를 이용하세요.",
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )

    assert result["detection"]["risk_score"] < 45
    assert result["detection"]["risk_level"] == "low"
    assert result["detection"]["scam_type"] == "safe_message"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("message", "expected_type"),
    [
        (
            "[CJ대한통운] 고객님 안녕하세요. 배송주소 오류로 배송이 지연되고 있습니다. "
            "정확한 주소 수정해주세요. bit.ly/2LYrJ4B",
            "delivery_customs_smishing",
        ),
        (
            "[Web발신] 고객님 안녕하세요. 주문 주소 정보가 잘못되어 배달이 되지 않습니다. "
            "완전한 정보를 기입해주세요. bit.ly/2kTWRpQ",
            "delivery_customs_smishing",
        ),
        (
            "주문한 상품이 OO택배에 배송되었으나 주소가 확인되지 않아 반송하오니 "
            "주소 확인부탁드립니다. http://ab.cde/123\n"
            "미수령 택배가 있습니다. 앱 설치 후 확인해주세요.",
            "malicious_app",
        ),
    ],
)
async def test_delivery_external_url_and_address_reentry_use_action_evidence(
    message, expected_type
):
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("delivery-address-reentry"),
            "user_input": message,
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )

    assert result["structured_input"]["personal_info_request"] is True
    assert result["scenario_hypothesis"]["primary_type"] == expected_type
    assert result["detection"]["risk_score"] >= 85
    assert result["detection"]["risk_breakdown"]["financial_credential_request"]["score"] >= 80
    assert result["detection"]["risk_breakdown"]["url_risk"] >= 15


@pytest.mark.asyncio
async def test_normal_bank_otp_protection_notice_is_not_credential_request():
    result = await get_scamflow_graph().ainvoke(
        {
            **create_initial_state("normal-bank-otp"),
            "user_input": "[우리은행] 인증번호 123456입니다. 타인에게 알려주지 마세요. 대표 1588-5000",
            "input_mode": "text",
            "situation_stage": "received_message",
        }
    )

    assert result["structured_input"]["authentication_present"] is True
    assert result["structured_input"]["authentication_request"] is False
    assert result["scenario_hypothesis"]["primary_type"] == "safe_message"
    assert result["detection"]["risk_score"] < 20
