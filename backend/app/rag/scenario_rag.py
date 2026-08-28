"""smishing.csv를 사용하는 Scam Scenario RAG."""

import csv
import hashlib
import re
from pathlib import Path
from threading import Lock

from app.core.config import settings
from app.rag.embeddings import EMBEDDING_VERSION, korean_rag_embedding
from app.rag.vector_store import PersistentVectorStore
from app.services.embeddings import DIMENSIONS

DATASET_SOURCE = "jmjmjm3/kor-smishing-message"

EVENT_QUERY_LABELS = {
    "relationship_mention": "가족 또는 지인 관계 주장",
    "device_failure_pretext": "휴대폰 고장 또는 사용 불가 주장",
    "new_contact": "새 연락처 또는 임시 전화번호 사용",
    "contact_avoidance": "기존 전화 통화와 본인 확인 회피",
    "channel_restriction": "문자나 메신저로만 답장 유도",
    "urgency": "긴급 상황을 강조하며 빠른 행동 요구",
    "money_transfer_request": "실제 송금·입금 요구",
    "payment_request": "결제·비용 지불 요구",
    "gift_card_request": "문화상품권 또는 상품권 구매 요청",
    "credential_request": "인증·비밀번호 제공 요구",
    "personal_info_request": "개인정보 또는 금융정보 요구",
    "url_click_request": "URL 클릭·접속 요구",
    "app_install_request": "앱 또는 원격제어 프로그램 설치 요구",
    "international_sender": "국제발신 메시지",
    "contact_request": "표시된 전화번호로 연락 행동 요구",
    "unauthorized_claim": "미신청 발급 또는 미승인 결제 불안 조성",
}


class ScenarioRag:
    def __init__(self, csv_path: Path | None = None, index_dir: Path | None = None) -> None:
        backend_root = Path(__file__).parents[2]
        workspace_csv = backend_root.parent / "smishing.csv"
        backend_csv = backend_root / "data" / "smishing.csv"
        self.csv_path = csv_path or (backend_csv if backend_csv.exists() else workspace_csv)
        self.index_dir = index_dir or backend_root / "data" / "rag" / "scenario"
        self.store = PersistentVectorStore(
            self.index_dir,
            korean_rag_embedding,
            EMBEDDING_VERSION,
            DIMENSIONS,
        )
        self._build_lock = Lock()

    def ensure_index(self) -> int:
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Scenario RAG CSV를 찾을 수 없습니다: {self.csv_path}")
        fingerprint = _file_sha256(self.csv_path)
        if self.store.is_current(fingerprint):
            return self.store.load()
        if not settings.rag_auto_build_index:
            raise FileNotFoundError(
                "Scenario RAG index가 없습니다. scripts/build_rag_index.py를 먼저 실행하세요."
            )
        with self._build_lock:
            if self.store.is_current(fingerprint):
                return self.store.load()
            return self.store.build(self._documents(), fingerprint)

    def build_index(self, force: bool = False) -> int:
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Scenario RAG CSV를 찾을 수 없습니다: {self.csv_path}")
        fingerprint = _file_sha256(self.csv_path)
        if not force and self.store.is_current(fingerprint):
            return self.store.load()
        return self.store.build(self._documents(), fingerprint)

    def search(self, original_text: str, structured: dict, hypothesis: dict, top_k: int | None = None) -> dict:
        self.ensure_index()
        query = self.build_query(original_text, structured, hypothesis)
        limit = top_k or settings.rag_scenario_top_k
        candidates = [
            item
            for item in self.store.search(query, max(20, limit * 6))
            if float(item.get("similarity", 0)) >= settings.rag_scenario_min_similarity
        ]
        results = self._balanced_results(candidates, limit)
        evidence = self._summarize_evidence(results, structured)
        return {"query": query, "results": results, "evidence": evidence}

    @staticmethod
    def build_query(original_text: str, structured: dict, hypothesis: dict) -> str:
        lines: list[str] = []
        label = hypothesis.get("label")
        if label:
            lines.append(f"추정 시나리오: {label}")
        validated_events = structured.get("validated_events", {})
        for key, description in EVENT_QUERY_LABELS.items():
            validated = validated_events.get(key)
            is_present = (
                bool(validated.get("value"))
                if isinstance(validated, dict)
                else bool(structured.get(key))
            )
            if is_present:
                lines.append(description)
        purpose = structured.get("message_purpose")
        if purpose:
            lines.append(f"메시지 목적: {purpose}")
        for signal in structured.get("benign_signals", [])[:5]:
            lines.append(f"정상·완화 근거: {signal}")
        institution = structured.get("institution")
        if institution:
            lines.append(f"주장 기관: {institution}")
        requested_asset = structured.get("requested_asset")
        if requested_asset:
            lines.append(f"요청 자산: {requested_asset}")
        message = structured.get("message_content") or original_text
        if message:
            lines.append(f"원문: {str(message)[:2000]}")
        return "\n".join(lines)

    def _documents(self):
        with self.csv_path.open(encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            for row_index, row in enumerate(reader):
                content = _clean_text(row.get("content"))
                label = _clean_text(row.get("label")) or "판단 불가"
                explanation = _clean_explanation(row.get("explanation"))
                scenario_type = _clean_text(row.get("type")) or "미분류"
                if not content:
                    continue
                document_text = (
                    f"[유형]\n{scenario_type}\n\n[판정]\n{label}\n\n"
                    f"[메시지]\n{content}\n\n[데이터셋 판단 근거]\n{explanation}"
                )
                yield {
                    "row_id": str(row_index),
                    "content": content,
                    "label": label,
                    "type": scenario_type,
                    "explanation": explanation,
                    "source": DATASET_SOURCE,
                    "document_text": document_text,
                }

    @staticmethod
    def _balanced_results(candidates: list[dict], limit: int) -> list[dict]:
        selected = candidates[:limit]
        labels = {item.get("label") for item in selected}
        for expected_label in ("스미싱", "정상"):
            if expected_label in labels:
                continue
            alternate = next((item for item in candidates if item.get("label") == expected_label), None)
            if alternate:
                selected = [*selected[: max(0, limit - 1)], alternate]
                labels.add(expected_label)
        unique: list[dict] = []
        seen: set[str] = set()
        for item in selected:
            row_id = str(item.get("row_id"))
            if row_id not in seen:
                seen.add(row_id)
                unique.append({key: value for key, value in item.items() if key != "document_text"})
        return unique[:limit]

    @staticmethod
    def _summarize_evidence(results: list[dict], structured: dict) -> dict:
        if not results:
            return {
                "available": False,
                "applicable": False,
                "reliable": False,
                "risk_score": 0,
                "raw_risk_score": 0,
                "top_similarity": 0.0,
                "reasons": [],
            }
        top_similarity = max(float(item["similarity"]) for item in results)
        # 균형을 위해 추가된 낮은 유사도의 반대 label이 점수를 왜곡하지 않도록
        # 최상위 유사도와 실질적으로 경쟁하는 문서만 Evidence 표를 계산합니다.
        competitive_floor = max(top_similarity - 0.05, top_similarity * 0.90)
        competitive = [
            item for item in results if float(item["similarity"]) >= competitive_floor
        ]
        smishing_weight = sum(max(0.0, float(item["similarity"])) for item in competitive if item.get("label") == "스미싱")
        normal_weight = sum(max(0.0, float(item["similarity"])) for item in competitive if item.get("label") == "정상")
        total = smishing_weight + normal_weight
        raw_risk_score = round(50 + 50 * (smishing_weight - normal_weight) / total) if total else 50
        label_margin = abs(smishing_weight - normal_weight) / total if total else 0.0
        reliable = top_similarity >= 0.24 and label_margin >= 0.15

        direct_risk_request = any(
            structured.get(key)
            for key in (
                "financial_request",
                "gift_card_request",
                "bank_transfer_request",
                "authentication_request",
                "personal_info_request",
                "link_access_request",
                "app_install_request",
                "account_use_request",
                "proxy_action_request",
            )
        )
        institution_abuse_flow = bool(
            structured.get("institution_impersonation")
            and any(
                structured.get(key)
                for key in ("international_sender", "callback_request", "unauthorized_claim")
            )
        )
        actionable_pattern = direct_risk_request or institution_abuse_flow
        normal_guardrail = bool(
            structured.get("everyday_conversation")
            and structured.get("direct_contact_willingness")
            and not actionable_pattern
        )
        applicable = bool(reliable and actionable_pattern and not normal_guardrail)
        retrieved_reasons = [
            f"유사 {item.get('label', '사례')} 사례: {item.get('type', '미분류')} ({float(item['similarity']):.2f})"
            for item in results[:3]
        ]
        if normal_guardrail:
            reasons = ["일상 대화와 직접 통화 의사가 있고 위험 행동 요구가 없어 유사 사례를 점수에 반영하지 않았습니다."]
        elif not actionable_pattern:
            reasons = ["금전·인증정보·링크·앱 설치 등 실질적인 위험 행동 요구가 없어 유사 사례를 점수에 반영하지 않았습니다."]
        elif not reliable:
            reasons = ["검색 유사도 또는 label 합의가 부족해 점수 근거로 사용하지 않았습니다."]
        else:
            reasons = retrieved_reasons
        return {
            "available": True,
            "applicable": applicable,
            "reliable": reliable,
            "risk_score": max(0, min(100, raw_risk_score)) if applicable else 0,
            "raw_risk_score": max(0, min(100, raw_risk_score)),
            "top_similarity": round(top_similarity, 4),
            "label_margin": round(label_margin, 4),
            "normal_guardrail": normal_guardrail,
            "reasons": reasons,
        }


def _clean_text(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _clean_explanation(value: object) -> str:
    text = str(value or "")
    text = re.sub(r"\$\$스미싱\s*여부\$\$\s*:\s*[^\n]*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\$\$설명\$\$\s*:\s*", "", text, flags=re.IGNORECASE)
    return _clean_text(text)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
