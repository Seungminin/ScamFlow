"""ScamFlow 분석·대화 API 스키마."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class InputMode(StrEnum):
    TEXT = "text"
    IMAGE_OCR = "image_ocr"
    URL_PHONE = "url_phone"


class SituationStage(StrEnum):
    RECEIVED_MESSAGE = "received_message"
    CLICKED_LINK = "clicked_link"
    ENTERED_INFO = "entered_info"
    INSTALLED_APP = "installed_app"
    TRANSFERRED_MONEY = "transferred_money"


class StageConfirmation(StrEnum):
    NOT_REQUIRED = "not_required"
    NEEDS_CONFIRMATION = "needs_confirmation"
    CONFIRMED = "confirmed"


class ResponseUrgency(StrEnum):
    ROUTINE = "routine"
    CAUTION = "caution"
    URGENT = "urgent"
    CRITICAL = "critical"


class SourceItem(BaseModel):
    agency: str
    title: str
    url: str
    phone: str | None = None


class ActionItem(BaseModel):
    id: str
    title: str
    description: str
    priority: int = 1
    action_type: str = "guide"
    target: str | None = None
    requires_approval: bool = False


class HighlightItem(BaseModel):
    phrase: str
    reason: str
    category: str = "risk_signal"
    strength: int = Field(default=1, ge=1, le=3)


class ScenarioAssessment(BaseModel):
    status: str
    stage: str
    title: str
    summary: str
    confidence: str
    confirmed_signals: list[str] = Field(default_factory=list)
    absent_signals: list[str] = Field(default_factory=list)


class RiskAxis(BaseModel):
    score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)


class RiskBreakdown(BaseModel):
    url_risk: int = Field(ge=0, le=100)
    situation_risk: int = Field(ge=0, le=100)
    scam_context_risk: int = Field(ge=0, le=100)
    positive_evidence_score: int = Field(default=0, ge=0, le=100)
    negative_evidence_score: int = Field(default=0, ge=0, le=100)
    stage_confirmation: StageConfirmation = StageConfirmation.NOT_REQUIRED
    response_urgency: ResponseUrgency = ResponseUrgency.ROUTINE
    situation_summary: str = "추가 피해 정황 없음"
    fusion_reason: str
    threat_intelligence: RiskAxis
    domain_reputation: RiskAxis
    url_structure: RiskAxis
    conversation_context: RiskAxis
    exposure_risk: RiskAxis
    scenario_pattern: RiskAxis
    identity_risk: RiskAxis
    financial_credential_request: RiskAxis
    external_verification: RiskAxis
    scenario_rag: RiskAxis = Field(default_factory=lambda: RiskAxis(score=0, reasons=[]))


class RagDebug(BaseModel):
    enabled: bool = False
    scenario_enabled: bool = False
    response_policy_enabled: bool = True
    scenario_query: str = ""
    scenario_results: list[dict[str, Any]] = Field(default_factory=list)
    response_policy: list[dict[str, Any]] = Field(default_factory=list)


class ScamHypothesis(BaseModel):
    primary_type: str
    label: str
    confidence: float = Field(ge=0, le=1)
    confidences: dict[str, float] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    relationships: list[str] = Field(default_factory=list)
    requires_external_verification: list[str] = Field(default_factory=list)
    risk_axes: dict[str, RiskAxis] = Field(default_factory=dict)
    source: str = "scenario-pattern-engine"
    llm_candidate: dict[str, Any] | None = None


class ToolTrace(BaseModel):
    name: str
    status: str = "completed"
    summary: str


class EventEvidence(BaseModel):
    value: bool = False
    evidence: str | None = None


class StructuredInput(BaseModel):
    conversation_text: str
    message_content: str = ""
    ocr_messages: list[dict[str, Any]] = Field(default_factory=list)
    system_notices: list[str] = Field(default_factory=list)
    sender: str | None = None
    timestamp: str | None = None
    claimed_identity: str | None = None
    claimed_institution: str | None = None
    institution: str | None = None
    message_purpose: str = "unknown"
    financial_context_present: bool = False
    urls: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    link_present: bool = False
    url_present: bool = False
    url_click_request: bool = False
    phone_number_present: bool = False
    contact_request: bool = False
    international_sender: bool = False
    international_sender_notice: bool = False
    financial_request: bool = False
    money_transfer_request: bool = False
    payment_request: bool = False
    gift_card_request: bool = False
    bank_transfer_request: bool = False
    requested_asset: str | None = None
    authentication_request: bool = False
    credential_request: bool = False
    authentication_present: bool = False
    protective_notice: bool = False
    account_use_request: bool = False
    proxy_action_request: bool = False
    link_access_request: bool = False
    callback_request: bool = False
    unauthorized_claim: bool = False
    money_request: bool = False
    urgency: bool = False
    threat_or_pressure: bool = False
    account_problem_claim: bool = False
    device_problem_claim: bool = False
    authentication_problem_claim: bool = False
    new_contact: bool = False
    device_failure_pretext: bool = False
    contact_avoidance: bool = False
    channel_restriction: bool = False
    vague_favor_request: bool = False
    relationship_mention: bool = False
    family_impersonation: bool = False
    identity_grooming: bool = False
    institution_impersonation: bool = False
    personal_info_request: bool = False
    app_install_request: bool = False
    direct_contact_willingness: bool = False
    everyday_conversation: bool = False
    event_details: dict[str, EventEvidence] = Field(default_factory=dict)
    validated_events: dict[str, EventEvidence] = Field(default_factory=dict)
    supporting_evidence: list[str] = Field(default_factory=list)
    benign_signals: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    session_id: str = Field(min_length=1, max_length=100)
    user_id: str | None = Field(default=None, max_length=100)
    input_mode: InputMode = InputMode.TEXT
    situation_stage: SituationStage | None = None


class ChatResponse(BaseModel):
    message: str
    tool_used: str | None = None
    cached: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AnalyzeRequest(ChatRequest):
    trusted_contact_name: str | None = Field(default=None, max_length=100)
    stage_confirmation: StageConfirmation | None = None


class AgentQuestion(BaseModel):
    id: str
    text: str
    reason: str
    answer_type: str = "boolean"


class NextBestAction(BaseModel):
    title: str
    description: str
    priority: str = "high"
    policy_id: str | None = None
    follow_up_actions: list[str] = Field(default_factory=list)


class InteractiveAgentState(BaseModel):
    scenario: str
    scam_likelihood: int = Field(ge=0, le=100)
    status: str
    initial_context_hint: str
    exposure_state: dict[str, bool | None]
    known_facts: list[str] = Field(default_factory=list)
    unknown_facts: list[str] = Field(default_factory=list)
    questions_asked: list[str] = Field(default_factory=list)
    next_question: AgentQuestion | None = None
    next_best_action: NextBestAction | None = None
    conversation: list[dict[str, Any]] = Field(default_factory=list)
    confirmed_details: dict[str, Any] = Field(default_factory=dict)


class SituationReportRequest(BaseModel):
    mask_sensitive: bool = True
    edited_text: str | None = Field(default=None, max_length=30000)


class SituationReportResponse(BaseModel):
    session_id: str
    generated_at: str
    title: str
    simple_text: str
    detailed_text: str
    mask_sensitive: bool
    next_best_action: str


class AgentAnswerRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=100)
    question_id: str | None = Field(default=None, max_length=100)
    answer: bool | None = None
    message: str | None = Field(default=None, max_length=1000)


class AgentInteractionResponse(BaseModel):
    session_id: str
    interactive_agent: InteractiveAgentState
    next_action: str
    follow_up_questions: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    session_id: str
    risk_level: str
    risk_score: int = Field(ge=0, le=100)
    scam_likelihood: int = Field(ge=0, le=100)
    exposure_stage: SituationStage
    exposure_risk: RiskAxis
    risk_breakdown: RiskBreakdown
    scam_type: str
    headline: str
    explanation: str
    situation_stage: SituationStage
    stage_confirmation: StageConfirmation
    response_urgency: ResponseUrgency
    flow_stage: str
    highlights: list[HighlightItem] = Field(default_factory=list)
    negative_evidence: list[HighlightItem] = Field(default_factory=list)
    scenario_assessment: ScenarioAssessment
    scenario_hypothesis: ScamHypothesis
    next_action: str
    actions: list[ActionItem] = Field(default_factory=list)
    follow_up_questions: list[str] = Field(default_factory=list)
    sources: list[SourceItem] = Field(default_factory=list)
    tools_used: list[ToolTrace] = Field(default_factory=list)
    safety_notice: str
    model_mode: str = "local-rule-engine"
    context_summary: str
    extracted_context: StructuredInput
    rag: RagDebug = Field(default_factory=RagDebug)
    recommended_actions: list[str] = Field(default_factory=list)
    interactive_agent: InteractiveAgentState


class ImageAnalyzeRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=100)
    image_base64: str = Field(min_length=10)
    filename: str = Field(default="capture.png", max_length=255)
    situation_stage: SituationStage = SituationStage.RECEIVED_MESSAGE
    stage_confirmation: StageConfirmation | None = None


class ImageItem(BaseModel):
    image_base64: str = Field(min_length=10)
    filename: str = Field(default="capture.png", max_length=255)


class ImageExtractRequest(BaseModel):
    images: list[ImageItem] = Field(min_length=1, max_length=10)


class ImageExtractResponse(BaseModel):
    conversation_text: str
    urls: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    image_count: int = Field(ge=1)
    system_notices: list[str] = Field(default_factory=list)
    ocr_messages: list[dict[str, Any]] = Field(default_factory=list)


class ActionRequest(BaseModel):
    session_id: str
    action_id: str


class ActionApprovalRequest(ActionRequest):
    approved: bool


class ActionApprovalResponse(BaseModel):
    status: str
    message: str
    action_url: str | None = None


class SessionResponse(BaseModel):
    session_id: str
    state: dict[str, Any]
