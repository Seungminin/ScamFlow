"""피해 단계별 공식 RAG 문서 검색 품질 회귀 테스트."""

import pytest

from app.services.rag import OfficialKnowledgeRepository


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("query", "scam_type", "stage", "expected_id"),
    [
        (
            "주민등록번호와 신분증 개인정보를 입력했습니다",
            "unknown",
            "entered_info",
            "fss-personal-info-exposure",
        ),
        (
            "애니데스크 악성앱을 설치했습니다",
            "remote_control_app",
            "installed_app",
            "kisa-malicious-app-recovery",
        ),
        (
            "명의도용 대출과 신용정보를 확인하고 싶습니다",
            "unknown",
            "entered_info",
            "credit4u-credit-check",
        ),
        (
            "이미 송금해서 지급정지가 필요합니다",
            "institution_impersonation",
            "transferred_money",
            "police-integrated-response",
        ),
    ],
)
async def test_official_rag_returns_stage_specific_guides(
    query, scam_type, stage, expected_id
):
    repository = OfficialKnowledgeRepository()
    results = await repository.search(query, scam_type, stage, limit=5)

    assert expected_id in {item["id"] for item in results}
    assert all(item["url"].startswith("https://") for item in results)
    assert all(item["retrieval"] == "local-fallback" for item in results)


def test_official_rag_corpus_has_distinct_recovery_coverage():
    repository = OfficialKnowledgeRepository()
    ids = {item["id"] for item in repository._documents}

    assert len(ids) == len(repository._documents) >= 11
    assert {
        "police-integrated-response",
        "fss-personal-info-exposure",
        "msafer-identity-protection",
        "credit4u-credit-check",
        "kisa-malicious-app-recovery",
    }.issubset(ids)
