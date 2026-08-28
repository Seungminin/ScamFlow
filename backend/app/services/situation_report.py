"""현재 Agent State에서 편집 가능한 상황 요약과 PDF를 생성합니다."""

import io
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

SCENARIOS = {
    "family_impersonation": "가족·지인 사칭 메신저피싱",
    "smishing": "택배·배송 스미싱",
    "institution_impersonation": "금융기관·공공기관 사칭",
    "normal": "뚜렷한 사기 시나리오 미확인",
}
FACTS = {
    "identity_verified": "기존 연락처로 가족·지인 본인 확인",
    "institution_verified": "공식 대표번호로 기관 확인",
    "link_clicked": "메시지 링크 접속",
    "personal_info_entered": "개인정보 입력",
    "credential_entered": "인증정보 입력",
    "file_downloaded": "파일 다운로드",
    "app_installed": "앱 설치",
    "phone_called": "메시지 번호로 전화",
    "credential_shared": "인증번호·비밀번호 전달",
    "account_info_shared": "계좌·금융정보 전달",
    "money_sent": "송금",
    "gift_card_purchased": "상품권 구매",
    "gift_card_code_shared": "상품권 PIN·번호 전달",
    "remote_control_installed": "원격제어 앱 설치",
}


class SituationReportService:
    def build(self, state: dict[str, Any], masked: bool = True) -> dict[str, Any]:
        agent, context, detection = (
            state["interactive_agent"],
            state.get("structured_input", {}),
            state.get("detection", {}),
        )
        now = datetime.now(UTC).astimezone()
        facts, stage = agent["exposure_state"], self._stage(agent["exposure_state"])
        action = (agent.get("next_best_action") or {}).get("title") or state.get(
            "next_action", "추가 확인이 필요합니다."
        )
        follow = (agent.get("next_best_action") or {}).get(
            "follow_up_actions"
        ) or state.get("recommended_actions", [])[1:]
        user_facts: dict[str, bool] = {}
        answers = []
        for item in agent.get("conversation", []):
            if item.get("role") == "user":
                user_facts.update(item.get("facts", {}))
                answers.append(item.get("content", ""))
        confirmed = [
            f"{FACTS.get(key, key)}: {'예' if value else '아니오'}"
            for key, value in user_facts.items()
        ]
        relevant_unknown = [
            FACTS[key] for key in agent.get("unknown_facts", []) if key in FACTS
        ]
        if relevant_unknown:
            confirmed.append("아직 확인되지 않음: " + ", ".join(relevant_unknown))
        amount = agent.get("confirmed_details", {}).get("money_sent_amount")
        risks = list(
            dict.fromkeys(
                [
                    *[x for x in context.get("supporting_evidence", []) if x],
                    *[
                        x.get("reason") or x.get("phrase")
                        for x in detection.get("highlights", [])
                        if x.get("reason") or x.get("phrase")
                    ],
                ]
            )
        )[:8]
        sections = [
            (
                "1. 현재 상황",
                [
                    f"사용자 답변으로 {amount:,}원 송금이 확인되었습니다."
                    if amount
                    else (
                        "사기 가능성이 있는 연락이지만 직접 피해 행동은 확인되지 않았습니다."
                        if stage.startswith("메시지")
                        else f"사용자 답변으로 '{stage}' 단계가 확인되었습니다."
                    )
                ],
            ),
            (
                "2. 의심되는 사기 유형",
                [
                    SCENARIOS.get(agent["scenario"], agent["scenario"]),
                    f"Scam Likelihood: {agent['scam_likelihood']}/100",
                ],
            ),
            (
                "3. 상대방이 주장하거나 요구한 내용",
                self._demands(context) or ["구체적인 요구 내용 미확인"],
            ),
            ("4. 확인된 위험 정황", risks or ["표시할 수 있는 구체적 위험 근거 없음"]),
            (
                "5. 사용자에게 직접 확인한 내용",
                confirmed or ["Agent 질문으로 직접 확인된 내용 없음"],
            ),
            ("6. 현재 피해 진행 단계", [stage]),
            (
                "7. 현재 노출되었을 가능성이 있는 정보/자산",
                self._assets(facts) or ["확인된 직접 노출 없음"],
            ),
            ("8. 지금 가장 먼저 해야 할 행동", [action]),
            ("9. 그 다음 권장 행동", follow or ["공식 경로로 사실관계를 확인하세요."]),
            ("10. 신고·복구가 필요한 경우 권장 절차", self._recovery(facts)),
            (
                "11. 보존하면 좋은 증거",
                [
                    "문자·메신저 대화 전체 캡처",
                    "발신번호와 URL",
                    "송금·상품권 영수증과 거래 시각",
                    "상담·신고 접수 기록",
                ],
            ),
            (
                "12. 분석에 사용된 확인 가능한 근거",
                self._source(context, state) or ["사용자가 제공한 메시지"],
            ),
        ]
        detailed = self._text(now, sections)
        simple = "\n".join(
            [
                "ScamFlow 상황 간단 요약",
                f"작성 시각: {now:%Y-%m-%d %H:%M}",
                "",
                f"현재 상황: {SCENARIOS.get(agent['scenario'], agent['scenario'])}",
                f"현재 피해 단계: {stage}",
                f"지금 할 일: {action}",
                f"다음 행동: {follow[0] if follow else '공식 경로로 사실관계를 확인하세요.'}",
            ]
        )
        if masked:
            detailed, simple = mask_text(detailed), mask_text(simple)
        return {
            "session_id": state["session_id"],
            "generated_at": now.isoformat(),
            "title": "ScamFlow 금융사기 상황 요약",
            "simple_text": simple,
            "detailed_text": detailed,
            "mask_sensitive": masked,
            "next_best_action": action,
            "user_answers": answers,
        }

    def pdf(self, text: str) -> bytes:
        font = self._font()
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=17 * mm,
            bottomMargin=17 * mm,
            title="ScamFlow 금융사기 상황 요약",
        )
        base = getSampleStyleSheet()["BodyText"]
        body = ParagraphStyle(
            "body-ko",
            parent=base,
            fontName=font,
            fontSize=9.3,
            leading=14,
            textColor=HexColor("#24324A"),
        )
        title = ParagraphStyle(
            "title-ko",
            parent=body,
            fontSize=18,
            leading=25,
            alignment=TA_CENTER,
            textColor=HexColor("#123C93"),
            spaceAfter=12,
        )
        heading = ParagraphStyle(
            "heading-ko",
            parent=body,
            fontSize=11.5,
            leading=17,
            textColor=HexColor("#123C93"),
            spaceBefore=7,
        )
        story = [Paragraph("ScamFlow 금융사기 상황 요약", title)]
        lines = text.splitlines()
        if lines and lines[0].strip() == "ScamFlow 금융사기 상황 요약":
            lines = lines[1:]
        for line in lines:
            safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if re.match(r"^(?:[1-9]|1[0-2])\.", line):
                story.extend([Spacer(1, 2 * mm), Paragraph(safe, heading)])
            elif line.strip():
                story.append(Paragraph(safe, body))
            else:
                story.append(Spacer(1, 1.5 * mm))
        doc.build(story, onFirstPage=self._footer, onLaterPages=self._footer)
        return buf.getvalue()

    @staticmethod
    def _font() -> str:
        name = "ScamFlowKorean"
        if name not in pdfmetrics.getRegisteredFontNames():
            path = next(
                (
                    p
                    for p in [
                        Path("/System/Library/Fonts/Supplemental/AppleGothic.ttf"),
                        Path("/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc"),
                    ]
                    if p.exists()
                ),
                None,
            )
            if path:
                pdfmetrics.registerFont(TTFont(name, str(path)))
            else:
                # python:slim/CI에는 시스템 한글 글꼴이 없으므로 ReportLab의
                # 내장 한국어 CID 글꼴을 사용해 배포 환경에서도 PDF 생성을 보장합니다.
                name = "HYSMyeongJo-Medium"
                if name not in pdfmetrics.getRegisteredFontNames():
                    pdfmetrics.registerFont(UnicodeCIDFont(name))
        return name

    @staticmethod
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(HexColor("#78859B"))
        canvas.drawString(18 * mm, 9 * mm, "ScamFlow AI Safety Agent")
        canvas.drawRightString(192 * mm, 9 * mm, str(doc.page))
        canvas.restoreState()

    @staticmethod
    def _text(now, sections):
        lines = [
            "ScamFlow 금융사기 상황 요약",
            "",
            f"작성 시각: {now:%Y-%m-%d %H:%M}",
            "",
        ]
        for heading, items in sections:
            lines.extend([heading, *[f"- {item}" for item in items], ""])
        lines.extend(
            [
                "참고 안내",
                "이 문서는 ScamFlow AI가 사용자가 제공한 정보와 분석 결과를 바탕으로 상황을 정리한 참고용 문서입니다.",
                "공식 수사기관의 사건 확인서나 법적 판단을 대신하지 않습니다.",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _stage(f):
        if f.get("money_sent"):
            return "송금 완료"
        if f.get("gift_card_code_shared"):
            return "상품권 PIN·번호 전달 완료"
        if f.get("gift_card_purchased"):
            return "상품권 구매 완료 / 코드 전달 전"
        if f.get("remote_control_installed"):
            return "원격제어 앱 설치"
        if f.get("app_installed"):
            return "앱 설치"
        if any(
            f.get(k)
            for k in (
                "personal_info_entered",
                "credential_entered",
                "credential_shared",
                "account_info_shared",
            )
        ):
            return "개인·인증·금융정보 노출"
        if f.get("link_clicked"):
            return "링크 접속"
        return "메시지 수신 / 직접 피해 행동 미확인"

    @staticmethod
    def _demands(c):
        return [
            v
            for k, v in [
                ("gift_card_request", "상품권 구매 또는 PIN 전달 요구"),
                ("money_request", "송금·결제 요구"),
                ("authentication_request", "인증정보 요구"),
                ("personal_info_request", "개인정보 입력 요구"),
                ("app_install_request", "앱 설치 요구"),
                ("callback_request", "표시 번호로 연락 요구"),
            ]
            if c.get(k)
        ]

    @staticmethod
    def _assets(f):
        return [
            v
            for k, v in [
                ("money_sent", "송금한 금전"),
                ("gift_card_purchased", "구매한 상품권"),
                ("gift_card_code_shared", "상품권 PIN"),
                ("personal_info_entered", "입력한 개인정보"),
                ("credential_shared", "전달한 인증정보"),
                ("account_info_shared", "전달한 금융정보"),
                ("app_installed", "휴대전화와 금융 앱"),
            ]
            if f.get(k)
        ]

    @staticmethod
    def _recovery(f):
        if f.get("money_sent"):
            return [
                "송금 금융회사에 즉시 지급정지 요청",
                "112 신고",
                "거래 시각·계좌·대화 기록 보존",
            ]
        if f.get("app_installed") or f.get("remote_control_installed"):
            return [
                "기기 네트워크 차단",
                "다른 기기로 118·금융회사 연락",
                "감염 의심 기기에서 금융 앱 사용 중단",
            ]
        if any(
            f.get(k)
            for k in (
                "credential_shared",
                "account_info_shared",
                "personal_info_entered",
            )
        ):
            return [
                "노출된 인증수단 변경",
                "금융회사 공식 대표번호 상담",
                "명의도용·이상 거래 확인",
            ]
        return [
            "추가 연락·행동 요구 중단",
            "기존 연락처 또는 공식 대표번호로 확인",
            "필요시 112·118·1332 상담",
        ]

    @staticmethod
    def _source(c, state):
        mode_labels = {
            "image_ocr": "이미지 OCR",
            "text": "메시지 텍스트",
            "url_phone": "URL·전화번호",
        }
        values = [
            "원본 입력 유형: "
            + mode_labels.get(
                state.get("input_mode"), state.get("input_mode", "메시지")
            )
        ]
        if c.get("phone_numbers"):
            values.append("발신·표시 전화번호: " + ", ".join(c["phone_numbers"]))
        if c.get("urls"):
            values.append("확인된 URL: " + ", ".join(c["urls"]))
        if c.get("institution"):
            values.append("주장 기관: " + c["institution"])
        values.extend(
            x.get("summary") for x in state.get("tools_used", []) if x.get("summary")
        )
        values.extend(c.get("contradicting_evidence", []))
        return values[:8]


def mask_text(text: str) -> str:
    text = re.sub(
        r"(?<!\d)(01[016789])[- ]?\d{3,4}[- ]?(\d{4})(?!\d)", r"\1-****-\2", text
    )
    text = re.sub(r"(?<!\d)(\d{6})[- ]?[1-4]\d{6}(?!\d)", r"\1-*******", text)
    text = re.sub(
        r"(?<!\d)(\d{3,6})[- ]?\d{2,6}[- ]?(\d{3,6})(?!\d)", r"\1-****-\2", text
    )
    return re.sub(r"(?i)(OTP|인증번호)\s*[:：]?\s*\d{4,8}", r"\1: ******", text)


situation_report_service = SituationReportService()
