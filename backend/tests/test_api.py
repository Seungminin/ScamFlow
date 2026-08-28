"""ScamFlow FastAPI 통합 테스트."""

from fastapi.testclient import TestClient

from app.main import app


def test_index_and_health():
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["service"] == "scamflow-agent"
        assert set(health.json()["integrations"]) == {
            "solar",
            "ocr",
            "supabase",
            "virustotal",
            "google_safe_browsing",
            "kisa_whois",
            "scenario_rag",
            "response_policy_rag",
        }


def test_family_analysis_keeps_session_context():
    with TestClient(app) as client:
        payload = {
            "message": "엄마 액정 깨져서 전화 안돼. 지금 상품권 핀번호 보내줘",
            "session_id": "api-family",
            "situation_stage": "received_message",
        }
        first = client.post("/api/v1/analyze", json=payload)
        assert first.status_code == 200
        assert first.json()["scam_type"] == "family_impersonation"
        assert first.json()["model_mode"] == "rag-assisted"
        assert first.json()["extracted_context"]["money_request"] is True
        assert first.json()["extracted_context"]["new_contact"] is True
        second = client.post(
            "/api/v1/analyze",
            json={"message": "링크도 받았습니다", "session_id": "api-family", "situation_stage": "clicked_link"},
        )
        assert second.status_code == 200
        assert second.json()["scam_type"] == "family_impersonation"
        session = client.get("/api/v1/sessions/api-family")
        assert session.status_code == 200
        assert len(session.json()["state"]["messages"]) == 4
        assert session.json()["state"]["situation_stage"] == "clicked_link"


def test_recovery_and_action_approval_gate():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={"message": "상대 계좌로 이미 송금했습니다", "session_id": "api-recovery", "situation_stage": "transferred_money", "stage_confirmation": "confirmed"},
        )
        data = response.json()
        assert response.status_code == 200
        assert data["flow_stage"] == "recovery"
        assert data["response_urgency"] == "critical"
        assert data["stage_confirmation"] == "confirmed"
        request = client.post("/api/v1/actions/request", json={"session_id": "api-recovery", "action_id": "call-112"})
        assert request.status_code == 200
        assert request.json()["status"] == "approval_required"
        approval = client.post("/api/v1/actions/approve", json={"session_id": "api-recovery", "action_id": "call-112", "approved": True})
        assert approval.status_code == 200
        assert approval.json()["action_url"] == "tel:112"


def test_api_exposes_separate_risk_axes_for_normal_clicked_url():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={
                "message": "https://www.naver.com/",
                "session_id": "api-normal-url",
                "input_mode": "url_phone",
                "situation_stage": "clicked_link",
            },
        )
        data = response.json()
        assert response.status_code == 200
        assert data["risk_breakdown"]["url_risk"] <= 10
        assert data["risk_breakdown"]["situation_risk"] == 15
        assert data["risk_score"] < 45


def test_api_exposes_ambiguous_identity_grooming_state():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            json={
                "message": "엄마 나 폰고장나서 AS 맡겼어. 부탁할거있어. 문자확인하는대로 답장줄래?",
                "session_id": "api-identity-grooming",
                "situation_stage": "received_message",
            },
        )
        data = response.json()
        assert response.status_code == 200
        assert data["scam_type"] == "unknown"
        assert data["risk_score"] < 45
        assert data["scenario_assessment"]["status"] == "verification_required"
        assert data["scenario_assessment"]["stage"] == "identity_grooming"
        assert data["actions"][0]["id"] == "trusted-family-contact"
        assert data["follow_up_questions"] == []
        assert "기존 연락처" in data["next_action"]


def test_normal_chat_with_reported_transfer_requires_confirmation_before_recovery():
    normal_chat = (
        "엄마: 너도 빨리 집에 와. 나: 학교 끝나면 픽업해줘. "
        "엄마: 알았어, 갈 때 전화할게."
    )
    with TestClient(app) as client:
        reported = client.post(
            "/api/v1/analyze",
            json={
                "message": normal_chat,
                "session_id": "api-transfer-confirmation",
                "situation_stage": "transferred_money",
            },
        )
        data = reported.json()
        assert reported.status_code == 200
        assert data["risk_score"] < 20
        assert data["stage_confirmation"] == "needs_confirmation"
        assert data["response_urgency"] == "caution"
        assert data["flow_stage"] == "action"
        assert data["actions"][0]["id"] == "confirm-transfer"

        confirmed = client.post(
            "/api/v1/analyze",
            json={
                "message": "이 대화 상대의 요청으로 실제 돈을 보냈습니다.",
                "session_id": "api-transfer-confirmation",
                "situation_stage": "transferred_money",
                "stage_confirmation": "confirmed",
            },
        )
        confirmed_data = confirmed.json()
        assert confirmed.status_code == 200
        assert confirmed_data["stage_confirmation"] == "confirmed"
        assert confirmed_data["response_urgency"] == "critical"
        assert confirmed_data["flow_stage"] == "recovery"
        assert confirmed_data["actions"][0]["id"] == "call-112"


def test_new_consultation_does_not_reuse_previous_agent_context():
    normal_family_chat = (
        "엄마: 너도 빨리 집에 와. "
        "나: 학교 끝나면 픽업해주라. 밖에 너무 더워. "
        "엄마: 알았어, 갈 때 전화할게."
    )
    with TestClient(app) as client:
        first = client.post(
            "/api/v1/analyze",
            json={
                "message": "엄마 새 번호야. 전화는 안돼. 급하니 상품권 핀번호 보내줘.",
                "session_id": "context-to-clear",
                "situation_stage": "transferred_money",
            },
        )
        assert first.json()["risk_score"] >= 45
        assert first.json()["stage_confirmation"] == "needs_confirmation"

        cleared = client.delete("/api/v1/sessions/context-to-clear")
        assert cleared.status_code == 200
        fresh = client.post(
            "/api/v1/analyze",
            json={
                "message": normal_family_chat,
                "session_id": "context-to-clear",
            },
        )
        data = fresh.json()

        assert data["situation_stage"] == "received_message"
        assert data["scam_type"] != "family_impersonation"
        assert data["risk_level"] == "low"
        assert data["risk_score"] < 20
        assert data["negative_evidence"]
        assert "상품권" not in data["extracted_context"]["conversation_text"]
        assert "transferred_money" not in data["context_summary"]


def test_ocr_is_safe_when_disabled():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze/image",
            json={"session_id": "api-ocr", "image_base64": "aGVsbG8gd29ybGQ=", "filename": "capture.png"},
        )
        assert response.status_code == 422
        assert "비활성화" in response.json()["detail"]


def test_multi_image_extract_is_safe_when_disabled():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/extract/images",
            json={
                "images": [
                    {"image_base64": "aGVsbG8gd29ybGQ=", "filename": "one.png"},
                    {"image_base64": "aGVsbG8gd29ybGQ=", "filename": "two.jpg"},
                ]
            },
        )
        assert response.status_code == 422
        assert "비활성화" in response.json()["detail"]


def test_multi_image_extract_splits_conversation_urls_and_phones(monkeypatch):
    async def fake_extract(_image_base64: str, filename: str) -> str:
        if filename == "one.png":
            return "엄마 새 번호야. https://delivery-check.xyz 확인해줘"
        return "전화는 안돼. 010-1234-5678로 답장해줘"

    monkeypatch.setattr("app.api.routes.scamflow.ocr_service.extract", fake_extract)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/extract/images",
            json={
                "images": [
                    {"image_base64": "aGVsbG8gd29ybGQ=", "filename": "one.png"},
                    {"image_base64": "aGVsbG8gd29ybGQ=", "filename": "two.png"},
                ]
            },
        )

    data = response.json()
    assert response.status_code == 200
    assert data["image_count"] == 2
    assert data["urls"] == ["https://delivery-check.xyz"]
    assert data["phone_numbers"] == ["010-1234-5678"]
    assert "[캡처 1]" in data["conversation_text"]
    assert "[캡처 2]" in data["conversation_text"]


def test_image_extract_preserves_international_notice_and_card_message(monkeypatch):
    async def fake_extract(_image_base64: str, _filename: str) -> str:
        return (
            "00611787916328 [국제발신] [롯데카드] ****-2249카드 정상발급 "
            "(고객님 발급 아닌 경우 문의필수) 상담:02)605-1234"
        )

    monkeypatch.setattr("app.api.routes.scamflow.ocr_service.extract", fake_extract)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/extract/images",
            json={
                "images": [
                    {"image_base64": "aGVsbG8gd29ybGQ=", "filename": "international.png"}
                ]
            },
        )

    data = response.json()
    assert response.status_code == 200
    assert "[시스템 안내] 국제발신" in data["conversation_text"]
    assert "롯데카드" in data["conversation_text"]
    assert data["system_notices"] == ["국제발신"]
    assert "00611787916328" in data["phone_numbers"]
    assert "delivery-check.xyz" not in data["conversation_text"]
    assert "010-1234-5678" not in data["conversation_text"]
