"""Scenario/RAG 전단의 Event Evidence Extraction을 독립적으로 검증합니다."""

from app.services.context_extractor import extract_structured_context
from app.tools.executor import ToolExecutor
from app.tools.scam_tools import extract_phone_numbers, extract_urls


def test_normal_korea_investment_fee_change_notice_has_no_action_request():
    result = extract_structured_context(
        """
한국투자증권
주식수수료 변경 안내
계좌 43289***-01
최근 6개월 매매거래 미발생에 따른 수수료 변경
문의 1544-5000
"""
    )

    assert result["claimed_institution"] == "한국투자증권"
    assert result["message_purpose"] == "fee_change_notice"
    assert result["financial_context_present"] is True
    assert result["money_transfer_request"] is False
    assert result["payment_request"] is False
    assert result["gift_card_request"] is False
    assert result["credential_request"] is False
    assert result["url_click_request"] is False
    assert result["app_install_request"] is False
    assert result["urgency"] is False
    assert result["phone_number_present"] is True
    assert result["contact_request"] is False
    assert result["validated_events"]["phone_number_present"]["evidence"] == "문의 1544-5000"


def test_family_gift_card_request_keeps_original_evidence():
    result = extract_structured_context(
        "엄마 나 폰 고장났어.\n지금 인증이 안되는데\n문화상품권 하나 사줄래?"
    )

    assert result["device_problem_claim"] is True
    assert result["authentication_problem_claim"] is True
    assert result["gift_card_request"] is True
    assert result["validated_events"]["gift_card_request"]["evidence"] == "문화상품권 하나 사줄래?"


def test_bank_credential_theft_request_has_evidence():
    result = extract_structured_context(
        "우리은행입니다.\n본인 확인을 위해 문자로 받은 인증번호를 알려주세요."
    )

    assert result["claimed_institution"] == "우리은행"
    assert result["credential_request"] is True
    assert "인증번호를 알려주세요" in result["validated_events"]["credential_request"]["evidence"]


def test_normal_authentication_notice_is_not_credential_request():
    result = extract_structured_context(
        "[삼성닷컴]\n본인확인 인증번호 [803133]을 화면에 입력해주세요."
    )

    assert result["message_purpose"] == "authentication_notice"
    assert result["credential_request"] is False
    assert result["validated_events"]["credential_request"]["evidence"] is None


def test_customs_fee_transfer_request_is_explicit_and_urgent():
    result = extract_structured_context(
        "통관 비용 448,000원이 미납되었습니다.\n아래 계좌로 오늘까지 입금해주세요."
    )

    assert result["payment_request"] is True
    assert result["money_transfer_request"] is True
    assert result["urgency"] is True
    assert result["validated_events"]["money_transfer_request"]["evidence"] == "아래 계좌로 오늘까지 입금해주세요."


def test_scheme_less_short_url_from_ocr_is_normalized_and_sent_to_url_tools():
    text = "[CJ대한통운] 배송주소 오류로 배송이 지연됩니다.\n정확한 주소 수정해주세요.\nbit.ly/2LYrJ4B"
    result = extract_structured_context(text)

    assert extract_urls(text) == ["https://bit.ly/2LYrJ4B"]
    assert result["urls"] == ["https://bit.ly/2LYrJ4B"]
    assert result["url_present"] is True
    assert result["personal_info_request"] is True
    assert result["validated_events"]["url_present"]["evidence"] == "https://bit.ly/2LYrJ4B"
    tools = ToolExecutor().select_tools(text, structured=result)
    assert {"inspect_url", "url_rule_engine"}.issubset(set(tools))


def test_ocr_spacing_around_short_url_separators_is_repaired():
    assert extract_urls("bit . ly / 2LYrJ4B") == ["https://bit.ly/2LYrJ4B"]


def test_international_customs_callback_notice_extracts_compound_risk_events():
    text = (
        "[통관세금미납안내]세금합계:448,000원(8개월분)금일 정상처리 예정 "
        "본인 아닌 경우 통관국 관세청 ☎02.470.6517\n"
        "방금 수신한 문자메시지는 해외에서 발송되었습니다."
    )
    result = extract_structured_context(text)

    assert extract_phone_numbers(text) == ["02.470.6517"]
    assert result["institution"] == "관세청"
    assert result["international_sender"] is True
    assert result["urgency"] is True
    assert result["unauthorized_claim"] is True
    assert result["callback_request"] is True
    assert result["account_problem_claim"] is True
    assert result["phone_numbers"] == ["02.470.6517"]


def test_delivery_address_reentry_is_an_action_request():
    result = extract_structured_context(
        "택배 배송지 오류입니다. 아래 사이트에서 배송 주소를 재입력해주세요.\n"
        "https://cjlogistics.delivery-check.xyz/address"
    )

    assert result["personal_info_request"] is True
    assert result["url_present"] is True
    assert result["validated_events"]["personal_info_request"]["evidence"].startswith(
        "택배 배송지 오류"
    )


def test_generic_delivery_information_entry_is_an_action_request():
    result = extract_structured_context(
        "[Web발신] 고객님 안녕하세요. 주문 주소 정보가 잘못되어 배달이 되지 않습니다. "
        "완전한 정보를 기입해주세요. bit.ly/2kTWRpQ"
    )

    assert result["institution"] is None
    assert result["personal_info_request"] is True
    assert result["url_present"] is True
    assert result["urls"] == ["https://bit.ly/2kTWRpQ"]


def test_delivery_address_confirmation_and_app_install_are_action_requests():
    result = extract_structured_context(
        "주문한 상품이 OO택배에 배송되었으나 주소가 확인되지 않아 반송하오니 "
        "주소 확인부탁드립니다. http://ab.cde/123\n"
        "미수령 택배가 있습니다. 앱 설치 후 확인해주세요."
    )

    assert result["personal_info_request"] is True
    assert result["app_install_request"] is True
    assert result["url_present"] is True
    assert result["urls"] == ["http://ab.cde/123"]
