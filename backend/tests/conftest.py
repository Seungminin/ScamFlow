"""테스트가 실제 외부 API나 운영 Supabase를 호출하지 않도록 격리합니다."""

import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def disable_external_integrations(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "enable_solar", False)
    monkeypatch.setattr(settings, "enable_solar_detection", False)
    monkeypatch.setattr(settings, "enable_ocr", False)
    monkeypatch.setattr(settings, "enable_supabase", False)
    monkeypatch.setattr(settings, "enable_url_reputation", False)
