"""대화형 Safety Agent의 상태 전이와 우선 행동 테스트."""

from app.services.interactive_agent import InteractiveAgentService


def analysis(scam_type: str, **context):
    defaults = {
        "family_impersonation": False,
        "institution_impersonation": False,
        "gift_card_request": False,
        "money_request": False,
        "financial_request": False,
        "authentication_request": False,
        "credential_request": False,
        "personal_info_request": False,
        "app_install_request": False,
        "callback_request": False,
        "phone_numbers": [],
        "urls": [],
    }
    defaults.update(context)
    return {
        "detection": {"scam_type": scam_type, "risk_level": "warning"},
        "structured_input": defaults,
    }


def test_family_gift_card_flow_branches_to_issuer_stop_action():
    service = InteractiveAgentService()
    state = service.initialize(
        analysis("gift_card_request", family_impersonation=True, gift_card_request=True),
        "received_message",
    )
    assert state["next_question"]["id"] == "gift_card_purchased"

    state = service.respond(state, "gift_card_purchased", True, None)
    assert state["next_question"]["id"] == "gift_card_code_shared"

    state = service.respond(state, "gift_card_code_shared", True, None)
    assert state["status"] == "action_ready"
    assert "발행사" in state["next_best_action"]["title"]


def test_family_natural_language_updates_multiple_facts_without_duplicate_question():
    service = InteractiveAgentService()
    state = service.initialize(
        analysis("family_impersonation", family_impersonation=True, gift_card_request=True),
        "received_message",
    )
    state = service.respond(state, None, None, "상품권은 샀는데 핀번호는 아직 안 보냈어요")
    assert state["exposure_state"]["gift_card_purchased"] is True
    assert state["exposure_state"]["gift_card_code_shared"] is False
    assert state["status"] == "action_ready"
    assert state["questions_asked"] == ["gift_card_purchased"]
    assert [item["question_id"] for item in state["conversation"] if item.get("question_id")].count("gift_card_purchased") == 1


def test_smishing_no_click_stops_downstream_questions():
    service = InteractiveAgentService()
    state = service.initialize(
        analysis("delivery_customs_smishing", urls=["http://bad.example"], personal_info_request=True, app_install_request=True),
        "received_message",
    )
    assert state["next_question"]["id"] == "link_clicked"
    state = service.respond(state, "link_clicked", False, None)
    assert state["status"] == "action_ready"
    assert state["exposure_state"]["app_installed"] is False
    assert "링크" in state["next_best_action"]["title"]


def test_smishing_installed_app_prioritizes_network_isolation():
    service = InteractiveAgentService()
    state = service.initialize(
        analysis("malicious_app", urls=["http://bad.example"], app_install_request=True),
        "installed_app",
    )
    assert state["next_question"]["id"] == "app_installed"
    state = service.respond(state, None, None, "네, 앱을 설치했어요")
    assert state["status"] == "action_ready"
    assert "Wi-Fi" in state["next_best_action"]["title"] or "네트워크" in state["next_best_action"]["title"]


def test_normal_message_rechecks_contradictory_transfer_hint():
    service = InteractiveAgentService()
    state = service.initialize(analysis("safe_message"), "transferred_money")
    assert state["scenario"] == "normal"
    assert state["exposure_state"]["money_sent"] is None
    assert state["next_question"]["id"] == "money_sent"
    state = service.respond(state, "money_sent", False, None)
    assert state["status"] == "action_ready"
    assert state["exposure_state"]["money_sent"] is False


def test_institution_natural_language_tracks_shared_code_and_no_transfer():
    service = InteractiveAgentService()
    state = service.initialize(
        analysis(
            "institution_impersonation",
            institution_impersonation=True,
            authentication_request=True,
            money_request=True,
            callback_request=True,
        ),
        "received_message",
    )
    assert state["next_question"]["id"] == "phone_called"
    state = service.respond(state, "phone_called", True, None)
    state = service.respond(state, None, None, "인증번호는 줬지만 송금은 안 했어요")
    assert state["exposure_state"]["credential_shared"] is True
    assert state["exposure_state"]["money_sent"] is False
    assert state["next_question"]["id"] == "account_info_shared"
    state = service.respond(state, "account_info_shared", False, None)
    assert state["next_question"]["id"] == "institution_verified"
    state = service.respond(state, "institution_verified", False, None)
    assert state["status"] == "action_ready"
    assert "금융" in state["next_best_action"]["title"] or "정보" in state["next_best_action"]["title"]


def test_smishing_full_question_loop_reaches_app_isolation_action():
    service = InteractiveAgentService()
    state = service.initialize(
        analysis(
            "delivery_customs_smishing",
            urls=["http://bad.example"],
            personal_info_request=True,
            app_install_request=True,
        ),
        "received_message",
    )
    state = service.respond(state, "link_clicked", True, None)
    assert state["next_question"]["id"] == "personal_info_entered"
    state = service.respond(state, "personal_info_entered", False, None)
    assert state["next_question"]["id"] == "file_downloaded"
    state = service.respond(state, "file_downloaded", True, None)
    assert state["next_question"]["id"] == "app_installed"
    state = service.respond(state, "app_installed", True, None)
    assert state["status"] == "action_ready"
    assert state["next_best_action"]["priority"] == "critical"


def test_natural_language_money_amount_is_preserved():
    service = InteractiveAgentService()
    state = service.initialize(analysis("institution_impersonation", institution_impersonation=True, money_request=True), "received_message")
    state = service.respond(state, "money_sent", None, "10만원 보냈어요")
    assert state["exposure_state"]["money_sent"] is True
    assert state["confirmed_details"]["money_sent_amount"] == 100000
