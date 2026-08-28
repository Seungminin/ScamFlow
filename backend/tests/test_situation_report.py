from app.services.situation_report import SituationReportService, mask_text


def state(scenario="family_impersonation"):
    return {
        "session_id": "report-test",
        "structured_input": {
            "gift_card_request": True,
            "phone_numbers": ["010-1234-5678"],
            "supporting_evidence": ["휴대전화 고장을 명분으로 사용"],
        },
        "detection": {
            "risk_level": "warning",
            "highlights": [{"reason": "상품권 구매 요구"}],
        },
        "tools_used": [],
        "recommended_actions": [],
        "next_action": "확인하세요.",
        "interactive_agent": {
            "scenario": scenario,
            "scam_likelihood": 88,
            "exposure_state": {
                "gift_card_purchased": True,
                "gift_card_code_shared": False,
                "money_sent": None,
            },
            "conversation": [
                {
                    "role": "user",
                    "content": "샀지만 번호는 안 보냈어요",
                    "facts": {
                        "gift_card_purchased": True,
                        "gift_card_code_shared": False,
                    },
                }
            ],
            "confirmed_details": {},
            "next_best_action": {
                "title": "상품권 번호를 전달하지 마세요.",
                "follow_up_actions": ["구매처에 취소 가능 여부를 문의하세요."],
            },
        },
    }


def test_report_separates_user_confirmation_and_ai_evidence():
    report = SituationReportService().build(state())
    assert "사용자에게 직접 확인한 내용" in report["detailed_text"]
    assert "상품권 구매: 예" in report["detailed_text"]
    assert "상품권 PIN·번호 전달: 아니오" in report["detailed_text"]
    assert "확인된 위험 정황" in report["detailed_text"]
    assert "상품권 구매 요구" in report["detailed_text"]
    assert "상품권 구매 완료 / 코드 전달 전" in report["detailed_text"]


def test_sensitive_values_are_masked_by_default():
    report = SituationReportService().build(state())
    assert "010-****-5678" in report["detailed_text"]
    assert "010-1234-5678" not in report["detailed_text"]
    assert "900101-*******" in mask_text("주민등록번호 900101-1234567")


def test_money_sent_report_prioritizes_payment_stop():
    value = state("institution_impersonation")
    value["interactive_agent"]["exposure_state"]["money_sent"] = True
    value["interactive_agent"]["confirmed_details"] = {"money_sent_amount": 100000}
    value["interactive_agent"]["next_best_action"]["title"] = (
        "송금 금융회사에 즉시 지급정지를 요청하세요."
    )
    report = SituationReportService().build(value)
    assert "100,000원 송금" in report["detailed_text"]
    assert "송금 완료" in report["detailed_text"]
    assert "지급정지" in report["detailed_text"]


def test_institution_report_records_user_confirmed_credentials_separately():
    value = state("institution_impersonation")
    value["structured_input"] = {
        "institution_impersonation": True,
        "authentication_request": True,
        "institution": "금융감독원",
    }
    value["interactive_agent"]["exposure_state"] = {
        "credential_shared": True,
        "money_sent": False,
    }
    value["interactive_agent"]["conversation"] = [
        {
            "role": "user",
            "content": "인증번호는 줬지만 송금은 안 했어요",
            "facts": {"credential_shared": True, "money_sent": False},
        }
    ]
    value["interactive_agent"]["next_best_action"]["title"] = (
        "노출된 인증수단을 즉시 변경하세요."
    )
    report = SituationReportService().build(value)
    assert "금융기관·공공기관 사칭" in report["detailed_text"]
    assert "인증번호·비밀번호 전달: 예" in report["detailed_text"]
    assert "송금: 아니오" in report["detailed_text"]
    assert "노출된 인증수단" in report["detailed_text"]


def test_pdf_is_real_pdf():
    service = SituationReportService()
    data = service.pdf(service.build(state())["detailed_text"])
    assert data.startswith(b"%PDF")
    assert len(data) > 3000
