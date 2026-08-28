"""외부 연동의 키 선택과 안전한 비활성 동작 테스트."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.config import settings
from app.services.reputation import (
    GoogleSafeBrowsingProvider,
    KisaWhoisProvider,
    UrlReputationService,
)
from app.services.solar import SolarEnricher
from app.services.supabase import SupabaseGateway
from app.tools.executor import ToolExecutor


def test_new_supabase_secret_key_is_preferred_over_misplaced_publishable(monkeypatch):
    monkeypatch.setattr(settings, "enable_supabase", True)
    monkeypatch.setattr(settings, "supabase_url", "https://example.supabase.co")
    monkeypatch.setattr(settings, "supabase_secret_key", "")
    monkeypatch.setattr(
        settings, "supabase_service_role_key", "sb_publishable_public"
    )
    monkeypatch.setattr(settings, "supabase_key", "sb_secret_backend")

    gateway = SupabaseGateway()

    assert gateway.enabled is True
    assert gateway.server_key == "sb_secret_backend"
    assert set(gateway.headers) == {"apikey", "Content-Type"}


def test_publishable_key_alone_cannot_enable_server_store(monkeypatch):
    monkeypatch.setattr(settings, "enable_supabase", True)
    monkeypatch.setattr(settings, "supabase_url", "https://example.supabase.co")
    monkeypatch.setattr(settings, "supabase_secret_key", "")
    monkeypatch.setattr(
        settings, "supabase_service_role_key", "sb_publishable_public"
    )
    monkeypatch.setattr(settings, "supabase_key", "")

    assert SupabaseGateway().enabled is False


def test_agent_selects_kisa_only_for_supported_url_targets(monkeypatch):
    monkeypatch.setattr(settings, "enable_url_reputation", True)
    monkeypatch.setattr(settings, "google_safe_browsing_api_key", "google-key")
    monkeypatch.setattr(settings, "kisa_whois_api_key", "kisa-key")
    monkeypatch.setattr(settings, "virustotal_api_key", "")
    executor = ToolExecutor()

    assert "kisa_whois" not in executor.select_tools("https://www.naver.com", "url_phone")
    assert "kisa_whois" in executor.select_tools("https://www.kisa.or.kr", "url_phone")
    assert "kisa_whois" in executor.select_tools("https://202.30.50.51", "url_phone")


@pytest.mark.asyncio
async def test_reputation_service_runs_only_agent_selected_providers(monkeypatch):
    monkeypatch.setattr(settings, "enable_url_reputation", True)
    calls: list[str] = []

    class FakeProvider:
        def __init__(self, name):
            self.name = name

        async def lookup(self, _url):
            calls.append(self.name)
            return {"provider": self.name, "status": "no_detection", "score": 0}

    service = UrlReputationService(
        [FakeProvider("google_safe_browsing"), FakeProvider("kisa_whois")]
    )
    result = await service.lookup(
        "https://www.naver.com",
        selected_providers={"google_safe_browsing"},
    )

    assert calls == ["google_safe_browsing"]
    assert [item["provider"] for item in result] == ["google_safe_browsing"]


@pytest.mark.asyncio
async def test_solar_keeps_negative_evidence_when_type_field_is_missing(monkeypatch):
    monkeypatch.setattr(settings, "enable_solar_detection", True)
    monkeypatch.setattr(settings, "upstage_api_key", "up_test")
    enricher = SolarEnricher()

    async def incomplete_response(*_args, **_kwargs):
        return {
            "confidence": 0.9,
            "risk_score": 5,
            "positive_evidence": [],
            "negative_evidence": [
                {
                    "phrase": "전화할게",
                    "reason": "직접 통화 의사",
                    "category": "direct_contact",
                    "strength": 3,
                }
            ],
        }

    monkeypatch.setattr(enricher, "_complete", incomplete_response)
    result = await enricher.analyze(
        "갈 때 전화할게", "received_message", {}, {}
    )

    assert result["scam_type"] == "safe_message"
    assert result["negative_evidence"][0]["phrase"] == "전화할게"


@pytest.mark.asyncio
async def test_safe_browsing_failure_returns_neutral_fallback(monkeypatch):
    monkeypatch.setattr(settings, "google_safe_browsing_api_key", "test-key")

    class FailingClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, *_args, **_kwargs):
            raise httpx.ConnectError("offline")

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: FailingClient())
    result = await GoogleSafeBrowsingProvider().lookup("https://example.com")

    assert result["status"] == "unavailable"
    assert result["score"] == 0


@pytest.mark.asyncio
async def test_kisa_whois_domain_age_is_scored_without_exposing_raw_payload(monkeypatch):
    monkeypatch.setattr(settings, "kisa_whois_api_key", "test-key")
    monkeypatch.setattr(settings, "kisa_whois_api_url", "https://apis.data.go.kr/B551505/whois")
    request: dict = {}
    recent_date = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y. %m. %d.")

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "response": {
                    "whois": {
                        "krdomain": {
                            "createdDate": recent_date,
                            "registrar": "테스트 등록대행자",
                            "registrant": "응답에 포함돼도 외부로 전달하지 않음",
                        }
                    }
                }
            }

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, **kwargs):
            request["url"] = url
            request["params"] = kwargs["params"]
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    result = await KisaWhoisProvider().lookup("https://example.kr/login")

    assert result["status"] == "found"
    assert result["score"] == 85
    assert result["domain_age_days"] <= 2
    assert "registrant" not in result
    assert request["url"].endswith("/domain_name")
    assert request["params"]["serviceKey"] == "test-key"
    assert "key" not in request["params"]


@pytest.mark.asyncio
async def test_kisa_whois_decodes_general_key_once_and_selects_ip_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "kisa_whois_api_key", "encoded%2Bkey%3D")
    monkeypatch.setattr(settings, "kisa_whois_api_url", "https://apis.data.go.kr/B551505/whois")
    request: dict = {}

    class FakeResponse:
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {"response": {"result": {"result_code": "10000"}, "whois": {"countryCode": "KR"}}}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, **kwargs):
            request["url"] = url
            request["params"] = kwargs["params"]
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    result = await KisaWhoisProvider().lookup("https://202.30.50.51/login")

    assert result["status"] == "found"
    assert request["url"].endswith("/ip_address")
    assert request["params"]["serviceKey"] == "encoded+key="


@pytest.mark.asyncio
async def test_kisa_whois_xml_gateway_error_is_neutral(monkeypatch):
    monkeypatch.setattr(settings, "kisa_whois_api_key", "test-key")
    monkeypatch.setattr(settings, "kisa_whois_api_url", "https://apis.data.go.kr/B551505/whois")

    class FakeResponse:
        text = """<OpenAPI_ServiceResponse><cmmMsgHeader><returnReasonCode>30</returnReasonCode></cmmMsgHeader></OpenAPI_ServiceResponse>"""

        def raise_for_status(self):
            return None

        def json(self):
            raise ValueError("not json")

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: FakeClient())
    result = await KisaWhoisProvider().lookup("https://kisa.or.kr")

    assert result["status"] == "unavailable"
    assert result["score"] == 0
    assert result["error_code"] == "30"
