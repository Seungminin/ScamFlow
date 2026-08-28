"use client";

import { ChangeEvent, DragEvent, useEffect, useRef, useState } from "react";
import Image from "next/image";
import { apiDownload, apiRequest } from "@/lib/api";

type Stage = "received_message" | "clicked_link" | "entered_info" | "installed_app" | "transferred_money";
type InputSection = "conversation" | "identifiers";
type EvidenceSection = "signals" | "risk" | "mitigation";
type StageConfirmation = "not_required" | "needs_confirmation" | "confirmed";
type ResponseUrgency = "routine" | "caution" | "urgent" | "critical";
type ScenarioAssessment = {
  status: "normal_likely" | "verification_required" | "suspicious" | "high_risk" | "harm_exposure" | "harm_confirmed" | "unclear";
  stage: string;
  title: string;
  summary: string;
  confidence: "low" | "medium" | "high" | "confirmed";
  confirmed_signals: string[];
  absent_signals: string[];
};
type View = "input" | "analyzing" | "result";

type ActionItem = {
  id: string;
  title: string;
  description: string;
  priority: number;
  action_type: string;
  target: string | null;
  requires_approval: boolean;
};

type AgentQuestion = { id: string; text: string; reason: string; answer_type: "boolean" };
type NextBestAction = {
  title: string;
  description: string;
  priority: "high" | "critical";
  policy_id: string | null;
  follow_up_actions: string[];
};
type InteractiveAgent = {
  scenario: string;
  scam_likelihood: number;
  status: "questioning" | "action_ready";
  initial_context_hint: Stage;
  exposure_state: Record<string, boolean | null>;
  known_facts: string[];
  unknown_facts: string[];
  questions_asked: string[];
  next_question: AgentQuestion | null;
  next_best_action: NextBestAction | null;
  conversation: { role: string; content: string; facts?: Record<string, boolean> }[];
  confirmed_details: Record<string, string | number>;
};

type RiskAxis = { score: number; reasons: string[] };

type StructuredContext = {
  conversation_text: string;
  message_content: string;
  system_notices: string[];
  claimed_identity: string | null;
  institution: string | null;
  urls: string[];
  phone_numbers: string[];
  international_sender: boolean;
  financial_request: boolean;
  gift_card_request: boolean;
  bank_transfer_request: boolean;
  authentication_request: boolean;
  account_use_request: boolean;
  proxy_action_request: boolean;
  money_request: boolean;
  urgency: boolean;
  new_contact: boolean;
  contact_avoidance: boolean;
  relationship_mention: boolean;
  family_impersonation: boolean;
  institution_impersonation: boolean;
  personal_info_request: boolean;
  app_install_request: boolean;
  direct_contact_willingness: boolean;
  everyday_conversation: boolean;
  device_failure_pretext: boolean;
  channel_restriction: boolean;
  vague_favor_request: boolean;
  identity_grooming: boolean;
  callback_request: boolean;
  unauthorized_claim: boolean;
};

type AnalysisResult = {
  session_id: string;
  risk_level: "critical" | "warning" | "low";
  risk_score: number;
  scam_likelihood: number;
  exposure_stage: Stage;
  exposure_risk: RiskAxis;
  risk_breakdown: {
    url_risk: number;
    situation_risk: number;
    scam_context_risk: number;
    positive_evidence_score: number;
    negative_evidence_score: number;
    stage_confirmation: StageConfirmation;
    response_urgency: ResponseUrgency;
    situation_summary: string;
    fusion_reason: string;
    threat_intelligence: RiskAxis;
    domain_reputation: RiskAxis;
    url_structure: RiskAxis;
    conversation_context: RiskAxis;
    exposure_risk: RiskAxis;
    scenario_pattern: RiskAxis;
    identity_risk: RiskAxis;
    financial_credential_request: RiskAxis;
    external_verification: RiskAxis;
  };
  scam_type: string;
  headline: string;
  explanation: string;
  situation_stage: Stage;
  stage_confirmation: StageConfirmation;
  response_urgency: ResponseUrgency;
  flow_stage: "action" | "recovery";
  highlights: { phrase: string; reason: string; category: string; strength: number }[];
  negative_evidence: { phrase: string; reason: string; category: string; strength: number }[];
  scenario_assessment: ScenarioAssessment;
  scenario_hypothesis: {
    primary_type: string;
    label: string;
    confidence: number;
    confidences: Record<string, number>;
    evidence: string[];
    relationships: string[];
    source: string;
  };
  next_action: string;
  actions: ActionItem[];
  follow_up_questions: string[];
  sources: { agency: string; title: string; url: string; phone?: string }[];
  tools_used: { name: string; status: string; summary: string }[];
  safety_notice: string;
  model_mode: string;
  context_summary: string;
  extracted_context: StructuredContext;
  interactive_agent: InteractiveAgent;
};

type AgentInteractionResult = {
  session_id: string;
  interactive_agent: InteractiveAgent;
  next_action: string;
  follow_up_questions: string[];
};

type SituationReport = {
  session_id: string;
  generated_at: string;
  title: string;
  simple_text: string;
  detailed_text: string;
  mask_sensitive: boolean;
  next_best_action: string;
};

type ModalConfig = {
  kicker: string;
  title: string;
  body: string;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm?: () => void | Promise<void>;
};

type UploadedImage = { file: File; preview: string };
type ImageExtractResult = {
  conversation_text: string;
  urls: string[];
  phone_numbers: string[];
  image_count: number;
  system_notices: string[];
  ocr_messages: Record<string, unknown>[];
};

const stages: { value: Stage; title: string; subtitle: string }[] = [
  { value: "received_message", title: "메시지만 받음", subtitle: "누르거나 답하지 않음" },
  { value: "clicked_link", title: "링크 클릭", subtitle: "페이지를 열어봄" },
  { value: "entered_info", title: "정보 입력", subtitle: "개인·금융정보 전달" },
  { value: "installed_app", title: "앱 설치", subtitle: "원격·보안앱 설치" },
  { value: "transferred_money", title: "송금 완료", subtitle: "선택 후 관련성 재확인" },
];

const presets = {
  family: "엄마 나 폰 액정 깨져서 수리 맡겼어. 임시폰이라 전화는 안돼. 급한데 문화상품권 5만원권 10장 사서 핀번호 사진 보내줘.",
  institution: "[서울중앙지검] 귀하 명의 대포통장이 범죄에 연루됐습니다. 보안을 유지하고 금감원 안전계좌로 즉시 자금을 이체하세요.",
  smishing: "[택배] 주소지 불일치로 배송이 보류되었습니다. 아래 링크에서 확인 후 앱을 설치하세요. http://delivery-check.xyz/app.apk",
  safe: "[KB국민은행] 김*우님 08/24 14:30 체크카드 출금 15,000원, 잔액 1,245,000원. 고객센터 1588-9999",
};

const analysisTasks = [
  ["받은 내용 확인", "대화와 이미지에서 주요 내용을 읽고 있습니다."],
  ["의심 정황 분석", "여러 문장의 흐름을 함께 확인하고 있습니다."],
  ["공식 정보 대조", "기관과 연락처 정보를 공식 자료와 비교하고 있습니다."],
  ["대응 방법 준비", "현재 상황에서 해야 할 일을 정리하고 있습니다."],
];

function createSessionId() {
  return `sf-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function wait(milliseconds: number) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

export default function Home() {
  const [sessionId, setSessionId] = useState("");
  const [view, setView] = useState<View>("input");
  const [activeSection, setActiveSection] = useState<InputSection>("conversation");
  const [stage, setStage] = useState<Stage | null>(null);
  const [message, setMessage] = useState("");
  const [urlPhone, setUrlPhone] = useState("");
  const [images, setImages] = useState<UploadedImage[]>([]);
  const [isExtracting, setIsExtracting] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const imageInputRef = useRef<HTMLInputElement>(null);
  const extractionSequence = useRef(0);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [analysisPhase, setAnalysisPhase] = useState(0);
  const [modal, setModal] = useState<ModalConfig | null>(null);
  const [pendingAction, setPendingAction] = useState<ActionItem | null>(null);
  const [agentBusy, setAgentBusy] = useState(false);
  const [report, setReport] = useState<SituationReport | null>(null);
  const [reportText, setReportText] = useState("");
  const [reportView, setReportView] = useState<"simple" | "detailed">("simple");
  const [reportBusy, setReportBusy] = useState(false);
  const [reportCopied, setReportCopied] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("scamflow_session") || createSessionId();
    localStorage.setItem("scamflow_session", stored);
    const timer = window.setTimeout(() => setSessionId(stored), 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (view !== "analyzing") return;
    const timer = window.setInterval(
      () => setAnalysisPhase((current) => Math.min(current + 1, analysisTasks.length - 1)),
      650,
    );
    return () => window.clearInterval(timer);
  }, [view]);

  async function analyze(override?: { message?: string; stage?: Stage | null; stageConfirmation?: StageConfirmation }) {
    const conversation = override?.message ?? message.trim();
    const identifiers = override?.message ? "" : urlPhone.trim();
    const nextMessage = [
      conversation && `[대화 내용]\n${conversation}`,
      identifiers && `[URL·전화번호]\n${identifiers}`,
    ].filter(Boolean).join("\n\n");
    const nextMode = conversation ? "text" : "url_phone";
    const nextStage = override?.stage !== undefined ? override.stage : stage;
    const nextConfirmation = override?.stageConfirmation ?? (nextStage === "transferred_money" ? "needs_confirmation" : "not_required");
    if (!nextMessage) {
      return showInfo("내용을 입력해 주세요", "받은 메시지, URL, 전화번호 또는 현재 상황을 입력해 주세요.");
    }
    if (isExtracting) return showInfo("이미지 내용을 추출하고 있습니다", "추출이 끝난 뒤 입력 내용을 확인하고 분석을 요청해 주세요.");

    setAnalysisPhase(0);
    setView("analyzing");
    const minimumDisplay = wait(1800);
    try {
      const request = apiRequest<AnalysisResult>("/api/v1/analyze", {
        method: "POST",
        body: JSON.stringify({
          message: nextMessage,
          session_id: sessionId,
          input_mode: nextMode,
          ...(nextStage ? { situation_stage: nextStage } : {}),
          stage_confirmation: nextConfirmation,
        }),
      });
      const [data] = await Promise.all([request, minimumDisplay]);
      setAnalysisPhase(analysisTasks.length - 1);
      setResult(data);
      await wait(300);
      setView("result");
    } catch (error) {
      setView("input");
      showInfo("분석을 완료하지 못했습니다", error instanceof Error ? error.message : "잠시 후 다시 시도해 주세요.");
    }
  }

  function selectPreset(name: keyof typeof presets) {
    setActiveSection("conversation");
    setMessage(presets[name]);
    setUrlPhone("");
    setStage(name === "smishing" ? "clicked_link" : "received_message");
  }

  async function extractImageContext(nextImages: UploadedImage[]) {
    if (!nextImages.length) return;
    const requestSequence = ++extractionSequence.current;
    setIsExtracting(true);
    try {
      const extracted = await apiRequest<ImageExtractResult>("/api/v1/extract/images", {
        method: "POST",
        body: JSON.stringify({
          images: nextImages.map((item) => ({ image_base64: item.preview, filename: item.file.name })),
        }),
      });
      if (requestSequence === extractionSequence.current) {
        setMessage(extracted.conversation_text);
        setUrlPhone([...extracted.urls, ...extracted.phone_numbers].join("\n"));
        setActiveSection("conversation");
      }
    } catch (error) {
      showInfo("이미지 내용을 추출하지 못했습니다", error instanceof Error ? error.message : "직접 입력하거나 다시 시도해 주세요.");
    } finally {
      if (requestSequence === extractionSequence.current) setIsExtracting(false);
    }
  }

  async function handleImageFiles(fileList?: FileList | File[]) {
    const incoming = Array.from(fileList || []);
    if (!incoming.length) return;
    const supportedTypes = new Set(["image/png", "image/jpeg", "image/webp"]);
    if (incoming.some((file) => !supportedTypes.has(file.type))) {
      return showInfo("지원하지 않는 파일입니다", "PNG, JPG, JPEG 또는 WEBP 이미지만 업로드할 수 있습니다.");
    }
    if (incoming.some((file) => file.size > 10 * 1024 * 1024)) {
      return showInfo("파일이 너무 큽니다", "이미지 한 장당 최대 10MB까지 업로드할 수 있습니다.");
    }
    if (images.length + incoming.length > 10) {
      return showInfo("이미지가 너무 많습니다", "대화 흐름을 분석할 캡처는 최대 10장까지 올릴 수 있습니다.");
    }
    try {
      const additions = await Promise.all(incoming.map(async (file) => ({ file, preview: await fileToBase64(file) })));
      const nextImages = [...images, ...additions];
      setImages(nextImages);
      await extractImageContext(nextImages);
    } catch (error) {
      showInfo("이미지를 읽지 못했습니다", error instanceof Error ? error.message : "파일을 다시 선택해 주세요.");
    }
  }

  function removeImage(index: number) {
    const nextImages = images.filter((_, itemIndex) => itemIndex !== index);
    setImages(nextImages);
    if (nextImages.length) void extractImageContext(nextImages);
    if (imageInputRef.current) imageInputRef.current.value = "";
  }

  function clearImages() {
    extractionSequence.current += 1;
    setImages([]);
    setMessage("");
    setUrlPhone("");
    setIsExtracting(false);
    setIsDragging(false);
    if (imageInputRef.current) imageInputRef.current.value = "";
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setIsDragging(false);
    void handleImageFiles(event.dataTransfer.files);
  }

  function resetSession() {
    const previousSessionId = sessionId;
    const next = createSessionId();
    localStorage.setItem("scamflow_session", next);
    setSessionId(next);
    setView("input");
    setResult(null);
    setActiveSection("conversation");
    setMessage("");
    setUrlPhone("");
    clearImages();
    setStage(null);
    setAnalysisPhase(0);
    setPendingAction(null);
    setModal(null);
    if (previousSessionId) {
      void apiRequest(`/api/v1/sessions/${encodeURIComponent(previousSessionId)}`, {
        method: "DELETE",
      }).catch(() => {
        // 새 세션 ID는 이미 적용되므로 이전 세션 삭제 실패가 Context를 재사용시키지 않습니다.
      });
    }
  }

  function startEmergency() {
    const emergencyMessage = message.trim() || "사기 의심 상대에게 이미 송금했습니다.";
    setMessage(emergencyMessage);
    void analyze({ message: emergencyMessage, stage: "transferred_money", stageConfirmation: "confirmed" });
  }

  function continueWithTransferStatus(status: "confirmed" | "not_transferred") {
    const confirmed = status === "confirmed";

    // 송금 단계를 선택하지 않은 분석에서 "보내지 않았어요"를 누른 경우에는
    // 이미 받은 분석 결과가 그대로 정답입니다. 확인 응답 문장을 새 대화로
    // 분석하면 "돈·상품권" 표현이 사기 요청으로 오인될 수 있으므로 재분석하지 않습니다.
    if (!confirmed && stage !== "transferred_money") return;

    const nextStage: Stage | null = confirmed
      ? "transferred_money"
      : stage === "transferred_money"
        ? "received_message"
        : stage;
    setStage(nextStage);

    // 피해 여부는 Exposure Stage만 변경합니다. Scam Likelihood는 확인 답변이
    // 아니라 사용자가 처음 입력한 원문 대화와 URL을 기준으로 다시 계산합니다.
    void analyze({
      stage: nextStage,
      stageConfirmation: confirmed ? "confirmed" : "not_required",
    });
  }

  async function respondToAgent(payload: { questionId: string; answer?: boolean; message?: string }) {
    if (!result || agentBusy) return;
    setAgentBusy(true);
    try {
      const data = await apiRequest<AgentInteractionResult>("/api/v1/agent/respond", {
        method: "POST",
        body: JSON.stringify({
          session_id: sessionId,
          question_id: payload.questionId,
          ...(payload.answer !== undefined ? { answer: payload.answer } : {}),
          ...(payload.message ? { message: payload.message } : {}),
        }),
      });
      setResult((current) => current ? {
        ...current,
        interactive_agent: data.interactive_agent,
        next_action: data.next_action,
        follow_up_questions: data.follow_up_questions,
      } : current);
    } catch (error) {
      showInfo("답변을 반영하지 못했습니다", error instanceof Error ? error.message : "예 또는 아니요로 다시 알려주세요.");
    } finally {
      setAgentBusy(false);
    }
  }

  async function openSituationReport(maskSensitive = true) {
    if (!result) return;
    setReportBusy(true);
    try {
      const data = await apiRequest<SituationReport>(`/api/v1/sessions/${encodeURIComponent(sessionId)}/report`, {
        method: "POST",
        body: JSON.stringify({ mask_sensitive: maskSensitive }),
      });
      setReport(data);
      setReportText(data.detailed_text);
      setReportView("simple");
    } catch (error) {
      showInfo("상황 정리를 만들지 못했습니다", error instanceof Error ? error.message : "다시 시도해 주세요.");
    } finally {
      setReportBusy(false);
    }
  }

  async function downloadReport(format: "pdf" | "txt") {
    if (!report) return;
    setReportBusy(true);
    try {
      const file = await apiDownload(`/api/v1/sessions/${encodeURIComponent(sessionId)}/report/${format}`, {
        mask_sensitive: report.mask_sensitive,
        edited_text: reportText,
      });
      const url = URL.createObjectURL(file.blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = file.filename; anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      showInfo("파일을 다운로드하지 못했습니다", error instanceof Error ? error.message : "다시 시도해 주세요.");
    } finally {
      setReportBusy(false);
    }
  }

  async function copyReport() {
    await navigator.clipboard.writeText(reportView === "simple" ? report?.simple_text || "" : reportText);
    setReportCopied(true);
    window.setTimeout(() => setReportCopied(false), 1800);
  }

  async function requestAction(action: ActionItem) {
    if (!action.requires_approval) return showInfo(action.title, action.description);
    try {
      await apiRequest("/api/v1/actions/request", {
        method: "POST",
        body: JSON.stringify({ session_id: sessionId, action_id: action.id }),
      });
      setPendingAction(action);
      setModal({
        kicker: "사용자 승인 필요",
        title: `${action.target} 번호로 연결할까요?`,
        body: "ScamFlow는 통화를 대신 수행하거나 신고 완료를 보증하지 않습니다. 승인하면 이 기기의 전화 앱을 엽니다.",
        confirmLabel: "승인하고 전화 앱 열기",
        onConfirm: () => approveAction(true, action),
      });
    } catch (error) {
      showInfo("연결을 준비하지 못했습니다", error instanceof Error ? error.message : "다시 시도해 주세요.");
    }
  }

  async function approveAction(approved: boolean, action = pendingAction) {
    if (!action) return;
    const data = await apiRequest<{ action_url?: string }>("/api/v1/actions/approve", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionId, action_id: action.id, approved }),
    });
    setPendingAction(null);
    setModal(null);
    if (approved && data.action_url) window.location.href = data.action_url;
  }

  function directCall(number: string) {
    setModal({
      kicker: "사용자 승인 필요",
      title: `${number} 번호로 연결할까요?`,
      body: "전화 앱을 여는 것만 준비합니다. 실제 상담·신고 완료 여부는 사용자가 직접 확인해야 합니다.",
      confirmLabel: "승인하고 전화 앱 열기",
      onConfirm: () => {
        setModal(null);
        window.location.href = `tel:${number}`;
      },
    });
  }

  function showInfo(title: string, body: string) {
    setModal({ kicker: "SCAMFLOW 안내", title, body });
  }

  function quickAction(type: string) {
    if (type === "emergency") return startEmergency();
    if (type === "url" || type === "phone") {
      setView("input");
      setActiveSection("identifiers");
      return;
    }
    if (type === "family") return showInfo("가족·지인 확인", "메시지에 적힌 새 번호가 아니라 평소 저장된 가족 번호로 직접 음성 통화하세요.");
    if (type === "report") return directCall("112");
    showInfo("사기 예방 5대 수칙", "수사기관의 송금 요구에 응하지 말고, 가족사칭 연락은 기존 번호로 확인하며, 낯선 링크와 파일을 열지 마세요.");
  }

  return (
    <>
      <header className="site-header">
        <div className="header-inner">
          <button className="brand brand-button" onClick={() => setView("input")} aria-label="ScamFlow 홈">
            <span className="brand-mark">S</span>
            <span><strong>ScamFlow</strong><small>금융사기 위험 확인·대응 안내</small></span>
          </button>
          <div className="header-actions">
            <span className="privacy-chip"><span className="status-dot" />상담 내용 안전 유지</span>
            <button className="ghost-button" onClick={resetSession}>새 상담 시작</button>
          </div>
        </div>
      </header>

      <main>
        <section className="hero">
          <div className="eyebrow"><span>금융사기 위험 확인 · 단계별 대응 안내</span><span className="eyebrow-line" /></div>
          <div className="hero-copy">
            <div>
              <h1>멈추고, 확인하고,<br /><em>안전하게 대응하세요.</em></h1>
              <p>상황만 알려주세요. ScamFlow가 의심 정황과 공식 정보를 확인해 지금 해야 할 일을 안내합니다.</p>
            </div>
            <button className="emergency-button" onClick={startEmergency}>
              <span className="button-icon">!</span>
              <span><strong>이미 송금했나요?</strong><small>긴급 피해 대응 바로가기</small></span>
              <span aria-hidden="true">→</span>
            </button>
          </div>
        </section>

        <section className="workspace">
          <div className="primary-column">
            {view === "input" && (
              <article className="panel input-panel">
                <div className="panel-heading">
                  <div><span className="step-label">상황 전달</span><h2>어떤 연락을 받으셨나요?</h2><p>AI 기능을 고를 필요 없이, 아는 만큼만 입력하면 됩니다. 민감한 개인정보는 가려주세요.</p></div>
                  <span className="local-mode">분석 준비 완료</span>
                </div>

                <section className="input-block capture-block standalone-capture">
                  <div className="input-block-heading"><span>1</span><div><h3>캡처·사진 <small>선택</small>{images.length > 0 && <b className="image-count">{images.length}</b>}</h3><p>여러 장을 올리면 AI가 순서대로 읽어 대화 내용과 URL·전화번호를 자동으로 채웁니다.</p></div>{images.length > 0 && <button type="button" onClick={clearImages}>전체 삭제</button>}</div>
                    <div
                      className={`upload-area ${isDragging ? "dragging" : ""} ${images.length ? "has-images" : ""}`}
                      onDragEnter={(event) => { event.preventDefault(); setIsDragging(true); }}
                      onDragOver={(event) => { event.preventDefault(); event.dataTransfer.dropEffect = "copy"; setIsDragging(true); }}
                      onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node)) setIsDragging(false); }}
                      onDrop={handleDrop}
                    >
                      <input ref={imageInputRef} type="file" multiple accept="image/png,image/jpeg,image/webp" hidden onChange={(event: ChangeEvent<HTMLInputElement>) => { void handleImageFiles(event.target.files || undefined); event.target.value = ""; }} />
                      <button type="button" className="upload-button" onClick={() => imageInputRef.current?.click()} disabled={isExtracting || images.length >= 10}>
                        <span className="upload-icon">{isExtracting ? "…" : "+"}</span>
                        <strong>{isExtracting ? `${images.length}장 대화 내용 추출 중` : isDragging ? "여기에 놓아주세요" : images.length ? "캡처 더 추가하기" : "카카오톡·문자 캡처 선택"}</strong>
                        <small>PNG, JPG, WEBP · 장당 최대 10MB · 최대 10장</small>
                      </button>
                      {images.length > 0 && <div className="image-list" aria-label={`업로드한 캡처 ${images.length}장`}>
                        {images.map((item, index) => <div className="image-item" key={`${item.file.name}-${item.file.lastModified}-${index}`}>
                          <Image src={item.preview} alt={`업로드한 캡처 ${index + 1}`} width={150} height={112} unoptimized />
                          <span>{index + 1}</span>
                          <button type="button" aria-label={`${item.file.name} 삭제`} onClick={() => removeImage(index)}>×</button>
                          <small title={item.file.name}>{item.file.name}</small>
                        </div>)}
                      </div>}
                    </div>
                    {isExtracting && <p className="extract-status" role="status"><span />AI가 이미지의 대화, URL, 전화번호를 분리하고 있습니다.</p>}
                </section>

                <div className="mode-tabs content-tabs" role="tablist" aria-label="추출·직접 입력 내용">
                  {([['conversation', '⌨', '대화 내용'], ['identifiers', '⌕', 'URL·전화번호']] as const).map(([section, icon, label]) => (
                    <button key={section} type="button" role="tab" aria-selected={activeSection === section} className={`mode-tab ${activeSection === section ? "active" : ""}`} onClick={() => setActiveSection(section)}>
                      <span>{icon}</span>{label}
                    </button>
                  ))}
                </div>

                <div className="tab-panel" role="tabpanel">

                  {activeSection === "conversation" && <section className="input-block">
                    <div className="input-block-heading"><span>2</span><div><h3>대화 내용 <small>{images.length ? "AI 추출 후 수정 가능" : "직접 입력"}</small></h3><p>캡처가 없다면 받은 메시지나 대화 흐름을 직접 입력해 주세요.</p></div></div>
                    <div className="input-area">
                      <textarea value={message} maxLength={8000} onChange={(event) => setMessage(event.target.value)} placeholder="예: 엄마, 나 폰 액정이 깨져서 임시폰이야. 급하게 상품권 핀번호가 필요해..." />
                      <div className="input-meta"><span>주민번호·계좌 비밀번호·인증번호는 입력하지 마세요.</span><span><b>{message.length.toLocaleString("ko-KR")}</b> / 8,000</span></div>
                    </div>
                  </section>}

                  {activeSection === "identifiers" && <section className="input-block">
                    <div className="input-block-heading"><span>3</span><div><h3>URL·전화번호 <small>{images.length ? "AI 자동 분리" : "직접 입력"}</small></h3><p>대화 내용과 별도로 검사할 주소나 번호를 한 줄에 하나씩 입력해 주세요.</p></div></div>
                    <div className="input-area compact-input">
                      <textarea value={urlPhone} maxLength={2000} onChange={(event) => setUrlPhone(event.target.value)} placeholder={'예: https://www.naver.com/\n010-1234-5678'} />
                      <div className="input-meta"><span>이곳의 입력은 대화 내용 박스에 복사되지 않습니다.</span><span><b>{urlPhone.length.toLocaleString("ko-KR")}</b> / 2,000</span></div>
                    </div>
                  </section>}
                </div>

                <fieldset className="situation-fieldset">
                  <legend><span className="step-label">현재 진행 단계</span>현재 어디까지 진행했나요?</legend>
                  <div className="situation-grid">
                    {stages.map((item, index) => (
                      <button type="button" key={item.value} aria-pressed={stage === item.value} className={`situation ${stage === item.value ? "active" : ""} ${item.value === "transferred_money" ? "danger" : ""}`} onClick={() => setStage((current) => current === item.value ? null : item.value)}>
                        <span>{index + 1}</span><strong>{item.title}</strong><small>{item.subtitle}</small>
                      </button>
                    ))}
                  </div>
                  <p className="context-separation-note">선택하지 않아도 분석할 수 있습니다. 선택한 항목을 한 번 더 누르면 해제됩니다.</p>
                </fieldset>

                <div className="preset-row"><span>예시로 테스트</span>{([['family', '가족사칭'], ['institution', '기관사칭'], ['smishing', '택배 스미싱'], ['safe', '정상 알림']] as const).map(([key, label]) => <button key={key} onClick={() => selectPreset(key)}>{label}</button>)}</div>
                <button className="primary-button" onClick={() => void analyze()}><span>사기 위험 분석하기</span><span aria-hidden="true">→</span></button>
                <p className="consent-note">분석 결과는 금융거래의 안전이나 상대방의 신원을 보증하지 않습니다.</p>
              </article>
            )}

            {view === "analyzing" && <AnalysisPanel phase={analysisPhase} />}

            {view === "result" && result && (
              <ResultPanel
                result={result}
                onBack={() => setView("input")}
                onAction={requestAction}
                onAgentAnswer={respondToAgent}
                agentBusy={agentBusy}
                onCreateReport={() => void openSituationReport()}
                reportBusy={reportBusy}
              />
            )}

            <section className="quick-actions">
              <div className="quick-heading"><div><span className="step-label">공식 안전 경로</span><h2>국민안전 빠른 바로가기</h2></div><span>모든 외부 연결은 승인 후 진행</span></div>
              <div className="quick-grid">
                {[['emergency','!','긴급 피해 대응','계좌 지급정지·골든타임'],['family','♙','가족·지인 확인','기존 번호로 목소리 확인'],['url','↗','의심 URL 확인','스미싱·악성링크 검사'],['phone','✓','전화번호·기관 확인','공식 대표번호와 대조'],['report','☎','신고 및 상담','112 경찰 · 1332 금감원'],['guide','▤','사기 예방 가이드','꼭 기억할 5대 수칙']].map(([type, icon, title, subtitle]) => (
                  <button key={type} className={`quick-card ${type === 'emergency' ? 'urgent' : ''}`} onClick={() => quickAction(type)}><span className="quick-icon">{icon}</span><span><strong>{title}</strong><small>{subtitle}</small></span>{type === 'emergency' && <b>긴급</b>}</button>
                ))}
              </div>
            </section>
          </div>

          <aside className="side-column">
            {result && !result.interactive_agent && !(result.situation_stage === "transferred_money" && result.stage_confirmation === "confirmed") && (
              <section className="context-card transfer-status-card">
                <div className="context-heading"><span className="pulse" /><div><strong>추가 확인</strong><small>피해 여부에 맞춰 대응을 다시 안내합니다</small></div></div>
                <h3>혹시 이미 돈이나 상품권을 보내셨나요?</h3>
                <div className="transfer-status-actions"><button className="danger-choice" onClick={() => continueWithTransferStatus("confirmed")}>네, 보냈어요</button><button onClick={() => continueWithTransferStatus("not_transferred")}>아니요, 보내지 않았어요</button></div>
              </section>
            )}

            <section className="context-card">
              <div className="context-heading"><span className="pulse" /><div><strong>현재 상담 상황</strong><small>후속 확인에도 이어서 반영됩니다</small></div></div>
              <dl><div><dt>현재 진행 단계</dt><dd>{stages.find((item) => item.value === stage)?.title || "선택 안 함"}</dd></div>{result && <><div><dt>판단 상태</dt><dd>{scenarioStatusLabel(result.scenario_assessment.status)}</dd></div><div><dt>단계 확인 상태</dt><dd>{confirmationLabel(result.stage_confirmation)}</dd></div></>}</dl>
            </section>

            <section className="agency-card"><h3>긴급 공식 연락처</h3>{[['112','경찰청 범죄신고'],['1332','금융감독원 피해상담'],['118','KISA 스미싱·악성앱']].map(([number, label]) => <button key={number} onClick={() => directCall(number)}><span><b>{number}</b><small>{label}</small></span><i>전화 준비 →</i></button>)}<p>번호를 누르면 승인 확인 후 기기의 전화 앱으로 연결됩니다.</p></section>
          </aside>
        </section>
      </main>

      <footer><div><strong>ScamFlow</strong><span>금융사기 대응을 위한 AI 의사결정 보조 서비스</span></div><p>긴급 피해는 지체하지 말고 112 또는 거래 금융회사 공식 대표번호로 직접 연락하세요.</p></footer>

      {report && <div className="modal-backdrop report-backdrop"><section className="report-modal" role="dialog" aria-modal="true" aria-labelledby="report-title">
        <button className="modal-close" aria-label="닫기" onClick={() => setReport(null)}>×</button>
        <span className="modal-kicker">AGENT STATE SNAPSHOT</span><h2 id="report-title">상황 정리 미리보기</h2>
        <p className="report-intro">AI 판단과 사용자가 직접 확인한 내용을 구분해 정리했습니다. 다운로드 전에 내용을 확인하고 수정해 주세요.</p>
        <div className="report-toolbar">
          <div className="report-tabs"><button className={reportView === "simple" ? "active" : ""} onClick={() => setReportView("simple")}>간단 요약</button><button className={reportView === "detailed" ? "active" : ""} onClick={() => setReportView("detailed")}>신고용 상세 요약</button></div>
          <label className="mask-toggle"><input type="checkbox" checked={report.mask_sensitive} onChange={(event) => void openSituationReport(event.target.checked)} />민감정보 마스킹</label>
        </div>
        {reportView === "simple" ? <pre className="report-preview">{report.simple_text}</pre> : <textarea className="report-editor" aria-label="상황 정리 내용 수정" value={reportText} onChange={(event) => setReportText(event.target.value)} />}
        <p className="report-confirmation">파일 생성 시 현재 미리보기와 사용자가 수정한 내용을 최종본으로 사용합니다.</p>
        <div className="report-actions"><button disabled={reportBusy} onClick={() => void downloadReport("pdf")}>PDF 다운로드</button><button disabled={reportBusy} onClick={() => void downloadReport("txt")}>TXT 다운로드</button><button disabled={reportBusy} onClick={() => void copyReport()}>{reportCopied ? "복사되었습니다" : "내용 복사"}</button></div>
      </section></div>}

      {modal && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setModal(null); }}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><button className="modal-close" aria-label="닫기" onClick={() => setModal(null)}>×</button><span className="modal-kicker">{modal.kicker}</span><h2 id="modal-title">{modal.title}</h2><div id="modalBody"><p>{modal.body}</p></div><div className="modal-actions"><button onClick={() => setModal(null)}>취소</button>{modal.onConfirm && <button className={modal.danger ? "danger-confirm" : "confirm"} onClick={() => void modal.onConfirm?.()}>{modal.confirmLabel || "확인"}</button>}</div></section></div>}
    </>
  );
}

function AnalysisPanel({ phase }: { phase: number }) {
  return (
    <article className="panel analyzing-panel" aria-live="polite" aria-busy="true">
      <div className="analysis-intro"><div className="scanner"><div className="scanner-core">S</div><span /><span /></div><div><span className="step-label">SCAMFLOW 분석 중</span><h2>받은 연락을 확인하고 있습니다</h2><p>의심 정황과 공식 정보를 함께 확인하고 있습니다.</p></div></div>
      <div className="progress-track" aria-label={`분석 진행 ${Math.min(((phase + 1) / analysisTasks.length) * 100, 95)}%`}><span style={{ width: `${Math.min(((phase + 1) / analysisTasks.length) * 100, 95)}%` }} /></div>
      <ol className="analysis-steps">
        {analysisTasks.map(([title, description], index) => {
          const status = index < phase ? "complete" : index === phase ? "current" : "pending";
          return <li className={status} key={title}><span className="analysis-status">{status === "complete" ? "✓" : `0${index + 1}`}</span><div><strong>{title}</strong><small>{description}</small></div><b>{status === "complete" ? "완료" : status === "current" ? "확인 중" : "대기"}</b></li>;
        })}
      </ol>
      <p className="analysis-privacy">AI의 내부 추론은 표시하지 않으며, 사용자가 이해할 수 있는 작업 상태만 안내합니다.</p>
    </article>
  );
}

function ResultPanel({ result, onBack, onAction, onAgentAnswer, agentBusy, onCreateReport, reportBusy }: { result: AnalysisResult; onBack: () => void; onAction: (action: ActionItem) => void; onAgentAnswer: (payload: { questionId: string; answer?: boolean; message?: string }) => Promise<void>; agentBusy: boolean; onCreateReport: () => void; reportBusy: boolean }) {
  const [activeEvidenceSection, setActiveEvidenceSection] = useState<EvidenceSection>("signals");
  const [agentMessage, setAgentMessage] = useState("");
  const [showFollowUps, setShowFollowUps] = useState(false);
  const typeLabels: Record<string, string> = { family_impersonation: "가족사칭", institution_impersonation: "기관사칭", financial_institution_impersonation: "금융기관 사칭", government_impersonation: "정부·수사기관 사칭", delivery_customs_smishing: "택배·통관 스미싱", card_payment_impersonation: "카드·결제 사칭", gift_card_request: "상품권 요구", credential_theft: "인증정보 탈취", malicious_app: "악성앱", loan_fraud: "대출사기", smishing: "스미싱", investment_fraud: "투자사기", remote_control_app: "악성앱", safe_message: "낮은 위험", unknown: "확인 필요" };
  const likelihoodLabel = result.risk_level === "critical" ? "사기 가능성 높음" : result.risk_level === "warning" ? "사기 가능성 주의" : "사기 가능성 낮음";
  const exposureLabel = result.exposure_stage === "received_message" ? "아직 피해 전 단계" : stageLabel(result.exposure_stage);
  const riskLabel = `${likelihoodLabel} · ${exposureLabel} · ${typeLabels[result.scam_type] || result.scam_type}`;
  const firstAction = result.actions[0];
  const signals = contextSignals(result.extracted_context);

  return (
    <article className="panel result-panel" aria-live="polite">
      <div className="result-topline"><button className="back-button" onClick={onBack}>← 입력 내용 수정</button><span>{new Date().toLocaleString("ko-KR")}</span></div>
      <InteractiveAgentCard
        agent={result.interactive_agent}
        busy={agentBusy}
        message={agentMessage}
        showFollowUps={showFollowUps}
        onMessageChange={setAgentMessage}
        onToggleFollowUps={() => setShowFollowUps((current) => !current)}
        onCreateReport={onCreateReport}
        reportBusy={reportBusy}
        onAnswer={(answer) => {
          const questionId = result.interactive_agent.next_question?.id;
          if (!questionId) return;
          const message = typeof answer === "string" ? answer : undefined;
          void onAgentAnswer({ questionId, ...(typeof answer === "boolean" ? { answer } : { message }) });
          if (message) setAgentMessage("");
        }}
      />
      <section className={`risk-hero ${result.risk_level}`} style={{ "--risk-angle": `${result.risk_score * 3.6}deg` } as React.CSSProperties}>
        <div className="risk-gauge-wrap"><span className="risk-gauge-label">Scam Likelihood</span><div className="risk-gauge"><strong>{result.scam_likelihood}</strong></div></div>
        <div><span className="risk-badge">{riskLabel}</span><h2>{result.headline}</h2><p>{result.explanation}</p></div>
      </section>

      <section className="risk-breakdown assessment-grid" aria-label="분리된 위험 평가">
        <div><span>사기 시나리오</span><strong>{result.risk_breakdown.scenario_pattern.score}</strong><small>/100</small></div>
        <div><span>URL 자체 위험</span><strong>{result.risk_breakdown.url_risk}</strong><small>/100</small></div>
        <div className="text-assessment"><span>현재 피해 단계</span><strong>{stageLabel(result.exposure_stage)}</strong><small>{confirmationLabel(result.stage_confirmation)}</small></div>
        <div className={`text-assessment urgency-${result.response_urgency}`}><span>대응 긴급도</span><strong>{urgencyLabel(result.response_urgency)}</strong><small>{result.risk_breakdown.situation_summary}</small></div>
        <p>{result.risk_breakdown.fusion_reason}</p>
        <div className="evidence-balance"><span>판단 근거</span><b>위험 {result.risk_breakdown.positive_evidence_score}</b><b className="negative-score">완화 {result.risk_breakdown.negative_evidence_score}</b></div>
      </section>

      <section className={`scenario-assessment status-${result.scenario_assessment.status}`}>
        <div className="scenario-heading"><span>{scenarioStatusLabel(result.scenario_assessment.status)}</span><small>판단 신뢰도 {confidenceLabel(result.scenario_assessment.confidence)}</small></div>
        <h3>{result.scenario_assessment.title}</h3>
        <p>{result.scenario_assessment.summary}</p>
        {(result.scenario_assessment.confirmed_signals.length > 0 || result.scenario_assessment.absent_signals.length > 0) && (
          <div className="scenario-evidence-grid">
            <div><strong>확인된 정황</strong>{result.scenario_assessment.confirmed_signals.length ? <ul>{result.scenario_assessment.confirmed_signals.map((signal) => <li key={signal}>{signal}</li>)}</ul> : <span>아직 확정된 복합 정황이 없습니다.</span>}</div>
            <div><strong>아직 확인되지 않은 정황</strong>{result.scenario_assessment.absent_signals.length ? <ul>{result.scenario_assessment.absent_signals.map((signal) => <li key={signal}>{signal}</li>)}</ul> : <span>추가로 완화할 정황이 확인되지 않았습니다.</span>}</div>
          </div>
        )}
        {result.scenario_assessment.status === "verification_required" && <div className="verification-callout"><b>다음 판단 기준</b><span>이 번호에 답장하기보다, 평소 저장된 가족 번호로 직접 통화해 확인하세요.</span></div>}
      </section>

      {!result.interactive_agent && result.stage_confirmation === "needs_confirmation" && (
        <section className="agent-question transfer-confirmation">
          <div><span className="step-label">송금 단계 확인 필요</span><h3>이 대화 상대의 요청으로 실제 돈이나 상품권을 보내셨나요?</h3><p>‘송금 완료’ 선택만으로 사기로 단정하지 않습니다. 실제 관련성을 확인한 뒤 긴급 대응 여부를 결정합니다.</p></div>
          <div className="confirmation-choices" />
        </section>
      )}

      {!result.interactive_agent && result.stage_confirmation === "confirmed" && (
        <section className="confirmed-damage"><strong>확인된 피해 단계</strong><span>이 대화와 관련된 송금이 확인되어 Recovery Flow가 활성화됐습니다.</span></section>
      )}

      <section className="result-evidence-pages">
        <div className="result-evidence-tabs" role="tablist" aria-label="분석 근거 선택">
          <button id="evidence-tab-signals" role="tab" aria-selected={activeEvidenceSection === "signals"} aria-controls="result-evidence-page" className={activeEvidenceSection === "signals" ? "active" : ""} onClick={() => setActiveEvidenceSection("signals")}>
            <span>✓</span>메시지에서 확인한 정황<b>{signals.length}</b>
          </button>
          <button id="evidence-tab-risk" role="tab" aria-selected={activeEvidenceSection === "risk"} aria-controls="result-evidence-page" className={activeEvidenceSection === "risk" ? "active" : ""} onClick={() => setActiveEvidenceSection("risk")}>
            <span>⌁</span>위험 근거<b>{result.highlights.length}</b>
          </button>
          <button id="evidence-tab-mitigation" role="tab" aria-selected={activeEvidenceSection === "mitigation"} aria-controls="result-evidence-page" className={activeEvidenceSection === "mitigation" ? "active" : ""} onClick={() => setActiveEvidenceSection("mitigation")}>
            <span>✓</span>정상·완화 근거<b>{result.negative_evidence.length}</b>
          </button>
        </div>

        <div id="result-evidence-page" className={`result-evidence-page ${activeEvidenceSection === "mitigation" ? "negative-evidence-section" : ""}`} role="tabpanel" aria-labelledby={`evidence-tab-${activeEvidenceSection}`}>
          {activeEvidenceSection === "signals" && <>
            <div className="section-title"><span>✓</span><div><h3>메시지에서 확인한 정황</h3><p>분석에 반영된 주요 내용을 알기 쉽게 정리했습니다.</p></div></div>
            <div className="signal-list">{signals.length ? signals.map((signal) => <span key={signal}>✓ {signal}</span>) : <span className="neutral">추가로 확인할 명확한 요청 신호가 없습니다.</span>}</div>
          </>}

          {activeEvidenceSection === "risk" && <>
            <div className="section-title"><span>⌁</span><div><h3>위험 근거</h3><p>원문에서 확인된 표현과 외부 검증 결과입니다.</p></div></div>
            <div className="highlights">{result.highlights.length ? result.highlights.map((item) => <div className="highlight" key={`${item.phrase}-${item.reason}`}><strong>“{item.phrase}”</strong><small>{item.reason}</small></div>) : <p className="empty-evidence">특정 위험 표현이 충분하지 않습니다. 상대방의 신원은 기존 연락수단으로 다시 확인하세요.</p>}</div>
          </>}

          {activeEvidenceSection === "mitigation" && <>
            <div className="section-title"><span>✓</span><div><h3>정상·완화 근거</h3><p>오탐을 줄이기 위해 위험을 낮추는 대화 정황도 함께 반영합니다.</p></div></div>
            <div className="highlights negative-highlights">{result.negative_evidence.length ? result.negative_evidence.map((item) => <div className="highlight" key={`${item.category}-${item.phrase}`}><strong>{item.phrase}</strong><small>{item.reason} · 강도 {item.strength}</small></div>) : <p className="empty-evidence">현재 확인된 정상·완화 근거가 없습니다.</p>}</div>
          </>}
        </div>
      </section>

      {!result.interactive_agent && <section className="next-action">
        <span>지금 가장 먼저 해야 할 일</span>
        <h3>{result.next_action}</h3>
        <p>{result.safety_notice}</p>
        {firstAction && <button onClick={() => onAction(firstAction)}>{firstAction.title}<span aria-hidden="true">→</span></button>}
      </section>}

      <section className="result-section">
        <div className="section-title"><span>→</span><div><h3>상황에 맞는 대응 순서</h3><p>외부 전화·페이지 연결은 사용자 승인 후에만 진행됩니다.</p></div></div>
        <div className="action-list">{result.actions.map((action, index) => <div className="action-card" key={action.id}><span>{index + 1}</span><div><strong>{action.title}</strong><small>{action.description}</small></div><button onClick={() => onAction(action)}>{action.requires_approval ? "승인 후 연결" : "안내 보기"}</button></div>)}</div>
      </section>

      {!result.interactive_agent && result.follow_up_questions.length > 0 && <section className="result-section"><div className="section-title"><span>?</span><div><h3>추가로 확인할 내용</h3><p>다음 상담에서 알려주면 더 정확한 대응 순서를 정할 수 있습니다.</p></div></div><div className="question-list">{result.follow_up_questions.map((question) => <div className="question" key={question}>{question}</div>)}</div></section>}

    </article>
  );
}

function InteractiveAgentCard({ agent, busy, message, showFollowUps, onMessageChange, onToggleFollowUps, onAnswer, onCreateReport, reportBusy }: {
  agent: InteractiveAgent;
  busy: boolean;
  message: string;
  showFollowUps: boolean;
  onMessageChange: (value: string) => void;
  onToggleFollowUps: () => void;
  onAnswer: (answer: boolean | string) => void;
  onCreateReport: () => void;
  reportBusy: boolean;
}) {
  const question = agent.next_question;
  const action = agent.next_best_action;
  return (
    <section className={`interactive-agent-card ${action?.priority === "critical" ? "critical" : ""}`}>
      <div className="interactive-agent-heading">
        <span className="agent-orb">S</span>
        <div><span>SCAMFLOW SAFETY AGENT</span><strong>{question ? "현재 상황을 한 가지만 확인할게요" : "확인이 끝났습니다"}</strong></div>
        <small>{agent.known_facts.length}개 사실 확인</small>
      </div>
      {question && <>
        <div className="interactive-question"><h2>{question.text}</h2><p>{question.reason}</p></div>
        <div className="agent-answer-buttons">
          <button disabled={busy} className="yes" onClick={() => onAnswer(true)}>네, 했어요</button>
          <button disabled={busy} onClick={() => onAnswer(false)}>아니요, 안 했어요</button>
        </div>
        <form className="agent-freeform" onSubmit={(event) => { event.preventDefault(); if (message.trim()) onAnswer(message.trim()); }}>
          <label htmlFor="agent-answer">상황을 직접 설명해도 돼요</label>
          <div><input id="agent-answer" value={message} onChange={(event) => onMessageChange(event.target.value)} placeholder="예: 상품권은 샀지만 번호는 아직 안 보냈어요" disabled={busy} /><button disabled={busy || !message.trim()}>{busy ? "반영 중" : "답변 보내기"}</button></div>
        </form>
      </>}
      {action && <div className="interactive-action">
        <span>지금 가장 먼저 해야 할 일</span>
        <h2>{action.title}</h2>
        <p>{action.description}</p>
        <div className="agent-action-buttons">{action.follow_up_actions.length > 0 && <button className="follow-up-toggle" onClick={onToggleFollowUps}>{showFollowUps ? "후속 행동 접기" : "그다음 행동 보기"}</button>}<button className="create-report-button" disabled={reportBusy} onClick={onCreateReport}>{reportBusy ? "정리 중" : "상황 정리 만들기"}</button></div>
        {showFollowUps && <ol>{action.follow_up_actions.map((item) => <li key={item}>{item}</li>)}</ol>}
      </div>}
      <p className="agent-state-note">처음 선택한 피해 단계는 힌트로만 사용하며, 위 답변으로 실제 행동 여부를 확인합니다.</p>
    </section>
  );
}

function contextSignals(context: StructuredContext) {
  const signals: string[] = [];
  if (context.urls.length) signals.push(`URL ${context.urls.length}개`);
  if (context.phone_numbers.length) signals.push(`전화번호 ${context.phone_numbers.length}개`);
  if (context.institution) signals.push(`주장 기관: ${context.institution}`);
  if (context.claimed_identity) signals.push(`주장 신원: ${context.claimed_identity}`);
  if (context.international_sender) signals.push("국제발신 시스템 안내");
  if (context.callback_request) signals.push("메시지에 표시된 번호로 문의 유도");
  if (context.unauthorized_claim) signals.push("미신청·미승인 거래 불안 조성");
  if (context.new_contact) signals.push("새 연락처 사용 정황");
  if (context.device_failure_pretext) signals.push("휴대전화 고장 명분");
  if (context.contact_avoidance) signals.push("기존 통화 회피 정황");
  if (context.channel_restriction) signals.push("문자 답장 유도");
  if (context.vague_favor_request) signals.push("모호한 부탁 예고");
  if (context.urgency) signals.push("긴급성·재촉 표현");
  if (context.money_request) signals.push("송금·상품권 요구");
  if (context.gift_card_request) signals.push("상품권·핀번호 요구");
  if (context.authentication_request) signals.push("인증번호 요구");
  if (context.account_use_request || context.proxy_action_request) signals.push("타인 명의·대리 행동 요구");
  if (context.family_impersonation) signals.push("가족·지인 사칭 정황");
  if (context.institution_impersonation) signals.push("기관 사칭 정황");
  if (context.personal_info_request) signals.push("개인정보 요구");
  if (context.app_install_request) signals.push("앱 설치 요구");
  if (context.direct_contact_willingness) signals.push("직접 통화 의사");
  if (context.everyday_conversation) signals.push("일상 대화 흐름");
  return signals;
}

function stageLabel(stage: Stage) {
  return stages.find((item) => item.value === stage)?.title || stage;
}

function confirmationLabel(status: StageConfirmation) {
  if (status === "confirmed") return "사용자 확인 완료";
  if (status === "needs_confirmation") return "실제 관련성 확인 필요";
  return "별도 확인 불필요";
}

function urgencyLabel(urgency: ResponseUrgency) {
  if (urgency === "critical") return "즉시 대응";
  if (urgency === "urgent") return "빠른 대응";
  if (urgency === "caution") return "추가 확인";
  return "일반 주의";
}

function scenarioStatusLabel(status: ScenarioAssessment["status"]) {
  if (status === "verification_required") return "신원 확인 필요";
  if (status === "suspicious") return "사기 의심 정황";
  if (status === "high_risk") return "고위험 요구";
  if (status === "harm_exposure") return "피해 노출 단계";
  if (status === "harm_confirmed") return "피해 발생 확인";
  if (status === "normal_likely") return "정상 정황 우세";
  return "문맥 추가 확인";
}

function confidenceLabel(confidence: ScenarioAssessment["confidence"]) {
  if (confidence === "confirmed") return "확인됨";
  if (confidence === "high") return "높음";
  if (confidence === "medium") return "중간";
  return "낮음";
}
