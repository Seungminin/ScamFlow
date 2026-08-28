"""ScamFlow 분석, 이미지 Context 추출, 세션, 승인 API."""

import asyncio
import io
import re
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from httpx import HTTPError

from app.graph.graph import get_scamflow_graph
from app.graph.state import create_initial_state
from app.schemas.chat import (
    ActionApprovalRequest,
    ActionApprovalResponse,
    ActionRequest,
    AgentAnswerRequest,
    AgentInteractionResponse,
    AnalysisResponse,
    AnalyzeRequest,
    ImageAnalyzeRequest,
    ImageExtractRequest,
    ImageExtractResponse,
    InputMode,
    SessionResponse,
    SituationReportRequest,
    SituationReportResponse,
)
from app.services.context_extractor import extract_structured_context
from app.services.interactive_agent import interactive_agent_service
from app.services.ocr import OcrService
from app.services.sessions import session_store
from app.services.situation_report import mask_text, situation_report_service
from app.services.solar import SolarEnricher

router = APIRouter(prefix="/api/v1", tags=["ScamFlow"])
ocr_service = OcrService()
solar_enricher = SolarEnricher()


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(request: AnalyzeRequest) -> AnalysisResponse:
    return await _run_analysis(request)


@router.post("/analyze/image", response_model=AnalysisResponse)
async def analyze_image(request: ImageAnalyzeRequest) -> AnalysisResponse:
    try:
        text = await ocr_service.extract(request.image_base64, request.filename)
    except (ValueError, HTTPError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await _run_analysis(
        AnalyzeRequest(
            message=text,
            session_id=request.session_id,
            input_mode=InputMode.IMAGE_OCR,
            situation_stage=request.situation_stage,
            stage_confirmation=request.stage_confirmation,
        )
    )


@router.post("/extract/images", response_model=ImageExtractResponse)
async def extract_images(request: ImageExtractRequest) -> ImageExtractResponse:
    """여러 캡처를 순서대로 OCR하고 입력 필드별 Context로 분리합니다."""
    try:
        texts = await asyncio.gather(
            *(
                ocr_service.extract(image.image_base64, image.filename)
                for image in request.images
            )
        )
    except (ValueError, HTTPError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    combined = "\n\n".join(
        f"[캡처 {index}]\n{text.strip()}" for index, text in enumerate(texts, start=1)
    )[:8000]
    structured = extract_structured_context(combined)
    urls = structured["urls"]
    phone_numbers = structured["phone_numbers"]
    conversation_lines: list[str] = []
    current_capture: int | None = None
    for record in structured["ocr_messages"]:
        capture_index = int(record.get("capture_index", 1))
        if capture_index != current_capture:
            conversation_lines.append(f"[캡처 {capture_index}]")
            current_capture = capture_index
        content = str(record.get("message_content", ""))
        for value in urls:
            content = content.replace(value, "")
            content = content.replace(
                re.sub(r"^https?://", "", value, flags=re.IGNORECASE), ""
            )
        for value in phone_numbers:
            content = content.replace(value, "")
        if content.strip():
            conversation_lines.append(content.strip())
    conversation = "\n".join(conversation_lines)
    conversation = re.sub(r"[ \t]+\n", "\n", conversation)
    conversation = re.sub(r"\n{3,}", "\n\n", conversation).strip()
    notice_context = "\n".join(
        f"[시스템 안내] {notice}" for notice in structured["system_notices"]
    )
    conversation = "\n".join(
        part for part in (notice_context, conversation) if part
    ).strip()
    return ImageExtractResponse(
        conversation_text=conversation,
        urls=urls,
        phone_numbers=phone_numbers,
        image_count=len(request.images),
        system_notices=structured["system_notices"],
        ocr_messages=structured["ocr_messages"],
    )


@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str) -> SessionResponse:
    state = await session_store.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    return SessionResponse(session_id=session_id, state=state)


@router.delete("/sessions/{session_id}")
async def clear_session(session_id: str) -> dict:
    await session_store.clear(session_id)
    return {"status": "cleared", "session_id": session_id}


@router.post("/agent/respond", response_model=AgentInteractionResponse)
async def respond_to_agent(request: AgentAnswerRequest) -> AgentInteractionResponse:
    """저장된 탐지 결과를 다시 계산하지 않고 노출 상태와 대응 정책만 갱신합니다."""
    state = await session_store.get(request.session_id)
    if not state or not state.get("interactive_agent"):
        raise HTTPException(status_code=404, detail="먼저 메시지를 분석해 주세요.")
    try:
        interaction = interactive_agent_service.respond(
            state["interactive_agent"],
            request.question_id,
            request.answer,
            request.message,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await _phrase_agent_question(interaction)
    state["interactive_agent"] = interaction
    question = interaction.get("next_question")
    action = interaction.get("next_best_action")
    state["follow_up_questions"] = [question["text"]] if question else []
    if action:
        state["next_action"] = action["title"]
        state["recommended_actions"] = [
            action["title"],
            *action.get("follow_up_actions", []),
        ]
    await session_store.save(request.session_id, state)
    return AgentInteractionResponse(
        session_id=request.session_id,
        interactive_agent=interaction,
        next_action=state.get("next_action", "추가 확인을 계속해 주세요."),
        follow_up_questions=state["follow_up_questions"],
    )


@router.post("/sessions/{session_id}/report", response_model=SituationReportResponse)
async def create_situation_report(
    session_id: str, request: SituationReportRequest
) -> SituationReportResponse:
    state = await session_store.get(session_id)
    if not state or not state.get("interactive_agent"):
        raise HTTPException(status_code=404, detail="먼저 메시지를 분석해 주세요.")
    return SituationReportResponse(
        **situation_report_service.build(state, request.mask_sensitive)
    )


@router.post("/sessions/{session_id}/report/pdf")
async def download_situation_pdf(
    session_id: str, request: SituationReportRequest
) -> StreamingResponse:
    state = await session_store.get(session_id)
    if not state or not state.get("interactive_agent"):
        raise HTTPException(status_code=404, detail="먼저 메시지를 분석해 주세요.")
    report = situation_report_service.build(state, request.mask_sensitive)
    text = request.edited_text or report["detailed_text"]
    if request.mask_sensitive:
        text = mask_text(text)
    data = situation_report_service.pdf(text)
    return _report_download(data, "pdf", "application/pdf")


@router.post("/sessions/{session_id}/report/txt")
async def download_situation_txt(
    session_id: str, request: SituationReportRequest
) -> StreamingResponse:
    state = await session_store.get(session_id)
    if not state or not state.get("interactive_agent"):
        raise HTTPException(status_code=404, detail="먼저 메시지를 분석해 주세요.")
    report = situation_report_service.build(state, request.mask_sensitive)
    text = request.edited_text or report["detailed_text"]
    if request.mask_sensitive:
        text = mask_text(text)
    return _report_download(
        text.encode("utf-8-sig"), "txt", "text/plain; charset=utf-8"
    )


def _report_download(data: bytes, extension: str, media_type: str) -> StreamingResponse:
    filename = f"ScamFlow_상황정리_{datetime.now():%Y%m%d_%H%M%S}.{extension}"
    disposition = f"attachment; filename*=UTF-8''{quote(filename)}"
    return StreamingResponse(
        io.BytesIO(data),
        media_type=media_type,
        headers={"Content-Disposition": disposition},
    )


@router.post("/actions/request")
async def request_action(request: ActionRequest) -> dict:
    state = await session_store.get(request.session_id)
    if not state:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    action = next(
        (item for item in state.get("actions", []) if item["id"] == request.action_id),
        None,
    )
    if not action:
        raise HTTPException(
            status_code=404, detail="현재 분석에 포함된 Action이 아닙니다."
        )
    if not action.get("requires_approval"):
        return {"status": "guide_only", "action": action}
    state["pending_action"] = action
    await session_store.save(request.session_id, state)
    return {
        "status": "approval_required",
        "action": action,
        "message": "외부 전화 또는 페이지 이동 전 사용자 승인이 필요합니다.",
    }


@router.post("/actions/approve", response_model=ActionApprovalResponse)
async def approve_action(request: ActionApprovalRequest) -> ActionApprovalResponse:
    state = await session_store.get(request.session_id)
    if not state or not state.get("pending_action"):
        raise HTTPException(status_code=409, detail="승인 대기 중인 Action이 없습니다.")
    pending = state["pending_action"]
    if pending["id"] != request.action_id:
        raise HTTPException(
            status_code=409, detail="승인 대상 Action이 일치하지 않습니다."
        )
    state["pending_action"] = None
    await session_store.save(request.session_id, state)
    if not request.approved:
        return ActionApprovalResponse(
            status="cancelled", message="사용자가 외부 Action을 취소했습니다."
        )
    target = pending.get("target")
    action_url = (
        f"tel:{target}" if pending["action_type"] == "call" and target else target
    )
    return ActionApprovalResponse(
        status="approved",
        message="승인되었습니다. 기기의 전화 앱 또는 공식 페이지로 연결합니다. 연결 후 실제 처리 여부는 직접 확인하세요.",
        action_url=action_url,
    )


async def _run_analysis(request: AnalyzeRequest) -> AnalysisResponse:
    previous = await session_store.get(request.session_id)
    if previous and previous.get("session_id") != request.session_id:
        previous = None
    previous = previous or create_initial_state(request.session_id, request.user_id)
    stage = (
        request.situation_stage.value
        if request.situation_stage
        else previous.get("situation_stage", "received_message")
    )
    if request.stage_confirmation:
        stage_confirmation = request.stage_confirmation.value
    elif stage == "transferred_money":
        stage_confirmation = "needs_confirmation"
    else:
        stage_confirmation = "not_required"
    graph_input = {
        **previous,
        "session_id": request.session_id,
        "user_id": request.user_id or previous.get("user_id"),
        "user_input": request.message,
        "input_mode": request.input_mode.value,
        "situation_stage": stage,
        "stage_confirmation": stage_confirmation,
        "trusted_contact_name": request.trusted_contact_name
        or previous.get("trusted_contact_name"),
        "pending_action": None,
    }
    # Tool 감사 로그가 FK를 만족하도록 새 세션도 Graph 실행 전에 먼저 생성합니다.
    await session_store.save(request.session_id, graph_input)
    result = await get_scamflow_graph().ainvoke(graph_input)
    interaction = interactive_agent_service.initialize(result, stage)
    await _phrase_agent_question(interaction)
    result["interactive_agent"] = interaction
    question = interaction.get("next_question")
    action = interaction.get("next_best_action")
    result["follow_up_questions"] = [question["text"]] if question else []
    if action:
        result["next_action"] = action["title"]
        result["recommended_actions"] = [
            action["title"],
            *action.get("follow_up_actions", []),
        ]
    result["messages"] = [
        *result.get("messages", []),
        {"role": "assistant", "content": result["detection"]["headline"]},
    ][-12:]
    await session_store.save(request.session_id, result)
    detection = result["detection"]
    return AnalysisResponse(
        session_id=request.session_id,
        risk_level=detection["risk_level"],
        risk_score=detection["risk_score"],
        scam_likelihood=detection["risk_score"],
        exposure_stage=stage,
        exposure_risk=detection["risk_breakdown"]["exposure_risk"],
        risk_breakdown=detection["risk_breakdown"],
        scam_type=detection["scam_type"],
        headline=detection["headline"],
        explanation=result["explanation"],
        situation_stage=stage,
        stage_confirmation=detection["risk_breakdown"]["stage_confirmation"],
        response_urgency=detection["risk_breakdown"]["response_urgency"],
        flow_stage=result["flow_stage"],
        highlights=detection["highlights"],
        negative_evidence=detection.get("negative_evidence", []),
        scenario_assessment=detection["scenario_assessment"],
        scenario_hypothesis=result["scenario_hypothesis"],
        next_action=result["next_action"],
        actions=result["actions"],
        follow_up_questions=result["follow_up_questions"],
        sources=result["sources"],
        tools_used=result["tools_used"],
        safety_notice=result["safety_notice"],
        model_mode=result["model_mode"],
        context_summary=result["context_summary"],
        extracted_context=result["structured_input"],
        rag=result.get("rag_debug", {"enabled": False}),
        recommended_actions=result.get("recommended_actions", []),
        interactive_agent=interaction,
    )


async def _phrase_agent_question(interaction: dict) -> None:
    """질문 선택은 Policy에 고정하고, Solar는 켜져 있을 때 표현만 다듬습니다."""
    question = interaction.get("next_question")
    if not question:
        return
    original = question["text"]
    phrased = await solar_enricher.phrase_agent_question(
        interaction["scenario"], original, question["reason"]
    )
    question["text"] = phrased
    for item in reversed(interaction.get("conversation", [])):
        if (
            item.get("question_id") == question["id"]
            and item.get("content") == original
        ):
            item["content"] = phrased
            break
