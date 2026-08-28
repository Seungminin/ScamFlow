"""텍스트/OCR 입력을 Entity·Event·시스템 metadata로 구조화합니다."""

import re

from app.tools.scam_tools import extract_phone_numbers, extract_urls

INSTITUTION_ALIASES = {
    "우리은행": ("우리은행", "우리 은행", "Woori Bank"),
    "롯데카드": ("롯데카드", "롯데 카드", "Lotte Card"),
    "KB국민은행": ("국민은행", "KB국민", "KB 국민"),
    "신한은행": ("신한은행", "신한 은행"),
    "하나은행": ("하나은행", "하나 은행"),
    "NH농협은행": ("농협은행", "NH농협", "농협"),
    "한국투자증권": ("한국투자증권", "한투증권", "한국투자"),
    "금융감독원": ("금감원", "금융감독원"),
    "경찰청": ("경찰", "경찰청"),
    "검찰청": ("검찰", "검찰청", "검사"),
    "관세청": ("관세청", "세관", "통관"),
    "법원": ("법원",),
}

SYSTEM_NOTICE_PATTERNS = (
    "해외에서 발송되었습니다",
    "해외에서 발송된 메시지",
    "국제발신",
    "국외발신",
    "발신번호 변작",
)


def extract_structured_context(text: str) -> dict:
    records, system_notices = _split_ocr_records(text)
    message_content = "\n".join(record["message_content"] for record in records).strip()
    analysis_text = message_content or text
    normalized = analysis_text.lower()
    full_normalized = text.lower()
    urls = extract_urls(text)
    phone_numbers = extract_phone_numbers(text)
    institution = _extract_institution(analysis_text)

    financial_context_evidence = _find_evidence_line(
        analysis_text,
        ("계좌", "수수료", "카드", "주식", "투자", "거래", "금액", "증권", "은행"),
    )
    financial_context_present = bool(institution or financial_context_evidence)

    money_transfer_evidence = _find_request_evidence(
        analysis_text,
        ("송금", "입금", "이체", "돈 보내", "계좌로 보내"),
        ("해주세요", "해줘", "해라", "하세요", "보내줘", "보내세요", "보내라", "부탁", "요청"),
    )
    money_transfer_request = bool(money_transfer_evidence)
    bank_transfer_request = money_transfer_request

    gift_card_evidence = _find_request_evidence(
        analysis_text,
        ("상품권", "문화상품권", "기프트카드", "핀번호", "pin 번호"),
        ("사줘", "사줄", "구매해", "구매 해", "보내줘", "보내세요", "알려줘", "알려주세요", "전달", "부탁"),
    )
    gift_card_request = bool(gift_card_evidence)

    payment_evidence = _find_request_evidence(
        analysis_text,
        ("결제", "납부", "지불", "수수료", "비용", "미납금", "세금"),
        ("해주세요", "하세요", "해줘", "내세요", "납부 바랍니다", "지불하세요", "지불해주세요", "부탁", "요청"),
    )
    if not payment_evidence and money_transfer_request and _contains(
        normalized, "비용", "미납", "세금", "결제", "납부", "수수료", "보증료"
    ):
        payment_evidence = money_transfer_evidence
    payment_request = bool(payment_evidence)
    financial_request = money_transfer_request or payment_request or gift_card_request

    urgency_evidence = _find_evidence_line(
        analysis_text,
        (
            "긴급",
            "즉시",
            "지금 바로",
            "오늘까지",
            "금일",
            "기한 내",
            "처리 예정",
            "정지 예정",
            "차단 예정",
            "자동이체 예정",
            "빨리 해",
            "서둘러",
        ),
    )
    if not urgency_evidence and financial_request:
        urgency_evidence = _find_evidence_line(
            analysis_text, ("급해", "급하", "지금", "빨리")
        )
    urgency = bool(urgency_evidence)
    threat_evidence = _find_evidence_line(
        analysis_text,
        ("계정 정지", "사용 정지", "법적 조치", "처벌", "압류", "손해배상", "차단됩니다"),
    )
    threat_or_pressure = bool(threat_evidence)
    device_problem_evidence = _find_evidence_line(
        analysis_text,
        ("액정 깨", "폰 고장", "폰고장", "휴대폰 고장", "핸드폰 고장", "수리 맡", "as 맡", "as맡"),
    )
    device_failure_pretext = bool(device_problem_evidence)
    new_contact = device_failure_pretext or _contains(
        normalized, "새 번호", "번호 바뀌", "임시폰", "연락처에 추가", "처음 보는 번호"
    )
    contact_avoidance = _contains(
        normalized,
        "전화 안돼",
        "전화는 안돼",
        "통화 안돼",
        "통화 못해",
        "전화하지 마",
        "연락하지 마",
    )
    relationship_mention = _contains(
        normalized, "엄마", "아빠", "어머니", "아버지", "딸", "아들", "가족", "지인"
    )
    authentication_present = _contains(
        normalized, "인증번호", "otp", "보안코드", "승인번호", "인증 코드", "인증코드"
    )
    protective_notice = _contains(
        normalized,
        "알려주지 마",
        "제공하지 마",
        "공유하지 마",
        "타인에게 알려주지",
        "절대 알려",
    )
    credential_evidence = _find_request_evidence(
        analysis_text,
        ("인증번호", "otp", "비밀번호", "보안코드", "카드번호", "cvc"),
        ("알려주세요", "알려줘", "보내주세요", "보내줘", "전달해", "전달 해", "회신해", "공유해"),
    )
    credential_request = bool(credential_evidence and not protective_notice)
    authentication_request = credential_request
    personal_info_evidence = _find_request_evidence(
        analysis_text,
        (
            "주민번호",
            "주민등록번호",
            "신분증",
            "개인정보",
            "계좌번호",
            "계좌 정보",
            "배송지",
            "배송 주소",
            "주소",
            "개인통관고유부호",
            "통관번호",
        ),
        (
            "알려주세요",
            "알려줘",
            "보내주세요",
            "보내줘",
            "전달해",
            "제공해",
            "회신해",
            "입력하세요",
            "입력해주세요",
            "재입력",
            "수정하세요",
            "수정해주세요",
            "기입하세요",
            "기입해주세요",
            "기입해 주세요",
            "기재하세요",
            "기재해주세요",
            "기재해 주세요",
            "작성하세요",
            "작성해주세요",
            "확인부탁드립니다",
            "확인 부탁드립니다",
            "확인해주세요",
            "확인해 주세요",
        ),
    )
    personal_info_request = bool(personal_info_evidence and not protective_notice)
    app_install_evidence = _find_request_evidence(
        analysis_text,
        ("앱", "어플", ".apk", "원격지원", "anydesk", "teamviewer"),
        (
            "설치하세요",
            "설치해",
            "설치 후",
            "설치하여",
            "설치해서",
            "설치 바랍니다",
            "다운로드하세요",
            "다운로드해",
            "실행하세요",
            "실행해",
            "권한 허용하세요",
        ),
    )
    app_install_request = bool(app_install_evidence)
    channel_restriction = _contains(
        normalized,
        "문자로만",
        "문자 확인하는대로",
        "문자 확인하는 대로",
        "문자확인하는대로",
        "문자확인하는 대로",
        "문자로 답",
        "카톡으로만",
        "전화 말고",
        "전화말고",
    )
    vague_favor_request = _contains(
        normalized,
        "부탁할거",
        "부탁할 게",
        "부탁할게",
        "부탁이 있어",
        "부탁 좀",
        "도와줄 게",
        "도와줘야",
    )
    account_use_evidence = _find_evidence_line(
        analysis_text,
        ("엄마 명의", "아빠 명의", "부모님 명의", "네 명의", "계정 좀 빌려", "명의로 인증", "대신 인증"),
    )
    account_use_request = bool(account_use_evidence)
    proxy_evidence = account_use_evidence or _find_evidence_line(
        analysis_text,
        ("대신 사줘", "대신 구매", "대신 보내", "대신 해줘", "구매해줘", "결제해줘"),
    )
    proxy_action_request = bool(proxy_evidence)
    url_click_evidence = _find_request_evidence(
        analysis_text,
        ("링크", "url", "http", "주소", "홈페이지", "사이트"),
        ("클릭", "누르", "눌러", "접속해", "들어가", "확인하세요", "이동하세요"),
    )
    url_click_request = bool(url_click_evidence)
    link_access_request = url_click_request

    phone_evidence = _find_phone_evidence(analysis_text, phone_numbers)
    contact_evidence = _find_request_evidence(
        analysis_text,
        ("전화", "연락", "문의", "상담"),
        ("하세요", "해주세요", "해라", "바랍니다", "필수", "즉시", "바로"),
    )
    contact_request = bool(phone_numbers and contact_evidence)
    callback_request = contact_request
    unauthorized_claim = _contains(
        normalized,
        "발급 아닌 경우",
        "발급아닌경우",
        "본인 발급 아닌",
        "본인 아닌 경우",
        "본인이 아닌 경우",
        "본인 거래 아닌",
        "본인 결제 아닌",
        "본인 신청 아닌",
        "신청하지 않은",
        "미신청",
        "이용하지 않은",
        "결제한 적 없",
    )
    international_sender_notice = any(
        pattern.lower() in full_normalized for pattern in SYSTEM_NOTICE_PATTERNS
    )
    direct_contact_willingness = _contains(
        normalized, "전화할게", "전화 할게", "전화해", "전화 줘", "통화하자", "통화 가능"
    )
    everyday_markers = (
        "집에 와",
        "집에와",
        "학교",
        "픽업",
        "밥",
        "갈 때",
        "갈때",
        "날씨",
        "더워",
        "알았어",
        "오케이",
    )
    everyday_conversation = sum(marker in normalized for marker in everyday_markers) >= 2
    claimed_identity = _extract_claimed_identity(normalized)
    claimed_institution = institution
    account_problem_evidence = _find_evidence_line(
        analysis_text,
        ("계정 정지", "계좌 정지", "계좌 동결", "미납", "비정상 거래", "사용 제한"),
    )
    account_problem_claim = bool(account_problem_evidence)
    authentication_problem_evidence = _find_evidence_line(
        analysis_text,
        ("인증이 안", "인증 안돼", "인증번호가 안", "본인확인이 안", "로그인이 안"),
    )
    authentication_problem_claim = bool(authentication_problem_evidence)
    message_purpose = _message_purpose(normalized, {
        "fee_change_notice": _contains(normalized, "수수료") and _contains(normalized, "변경") and not financial_request,
        "transaction_notice": _contains(normalized, "승인내역", "거래내역", "입출금 내역") and not financial_request,
        "authentication_notice": authentication_present and not credential_request,
        "account_security_warning": account_problem_claim and not financial_request,
        "payment_request": payment_request or money_transfer_request,
        "delivery_notice": _contains(normalized, "택배", "배송", "배달", "주문 주소") and not financial_request,
        "customs_notice": _contains(normalized, "통관", "관세", "세관"),
        "family_request": relationship_mention and (financial_request or proxy_action_request),
        "investment_offer": _contains(normalized, "수익 보장", "리딩방", "고수익"),
        "loan_offer": _contains(normalized, "대출 승인", "저금리", "대환"),
    })
    money_request = financial_request
    family_impersonation = bool(
        relationship_mention
        and (new_contact or device_failure_pretext)
        and (contact_avoidance or channel_restriction or urgency)
        and (financial_request or personal_info_request or proxy_action_request)
    )
    identity_grooming = bool(
        relationship_mention
        and new_contact
        and (vague_favor_request or channel_restriction or contact_avoidance)
        and not (financial_request or personal_info_request or app_install_request)
    )
    institution_evidence = (
        _find_evidence_line(analysis_text, (institution,)) if institution else None
    )
    url_evidence = urls[0] if urls else None
    event_details = {
        "financial_context_present": _validated_event(financial_context_present, financial_context_evidence or institution_evidence),
        "money_transfer_request": _validated_event(money_transfer_request, money_transfer_evidence),
        "payment_request": _validated_event(payment_request, payment_evidence),
        "gift_card_request": _validated_event(gift_card_request, gift_card_evidence),
        "credential_request": _validated_event(credential_request, credential_evidence),
        "personal_info_request": _validated_event(personal_info_request, personal_info_evidence),
        "url_present": _validated_event(bool(urls), url_evidence),
        "url_click_request": _validated_event(url_click_request, url_click_evidence),
        "phone_number_present": _validated_event(bool(phone_numbers), phone_evidence),
        "contact_request": _validated_event(contact_request, contact_evidence),
        "app_install_request": _validated_event(app_install_request, app_install_evidence),
        "urgency": _validated_event(urgency, urgency_evidence),
        "threat_or_pressure": _validated_event(threat_or_pressure, threat_evidence),
        "account_problem_claim": _validated_event(account_problem_claim, account_problem_evidence),
        "device_problem_claim": _validated_event(device_failure_pretext, device_problem_evidence),
        "authentication_problem_claim": _validated_event(authentication_problem_claim, authentication_problem_evidence),
        "proxy_action_request": _validated_event(proxy_action_request, proxy_evidence),
    }
    # 하위 로직과 RAG는 반드시 evidence validation을 통과한 값만 사용합니다.
    money_transfer_request = event_details["money_transfer_request"]["value"]
    bank_transfer_request = money_transfer_request
    payment_request = event_details["payment_request"]["value"]
    gift_card_request = event_details["gift_card_request"]["value"]
    credential_request = event_details["credential_request"]["value"]
    authentication_request = credential_request
    personal_info_request = event_details["personal_info_request"]["value"]
    url_click_request = event_details["url_click_request"]["value"]
    link_access_request = url_click_request
    contact_request = event_details["contact_request"]["value"]
    callback_request = bool(
        contact_request
        or (
            phone_numbers
            and institution
            and unauthorized_claim
        )
    )
    app_install_request = event_details["app_install_request"]["value"]
    urgency = event_details["urgency"]["value"]
    threat_or_pressure = event_details["threat_or_pressure"]["value"]
    account_problem_claim = event_details["account_problem_claim"]["value"]
    device_failure_pretext = event_details["device_problem_claim"]["value"]
    authentication_problem_claim = event_details["authentication_problem_claim"]["value"]
    proxy_action_request = event_details["proxy_action_request"]["value"]
    financial_request = money_transfer_request or payment_request or gift_card_request
    money_request = financial_request

    benign_signals = _benign_signals(
        normalized,
        message_purpose,
        event_details,
        bool(re.search(r"\d[\d-]*\*{2,}[\d*-]*", analysis_text)),
    )
    supporting_evidence = [
        event["evidence"]
        for name, event in event_details.items()
        if name not in {"financial_context_present", "url_present", "phone_number_present"}
        and event["value"]
        and event["evidence"]
    ]
    institution_impersonation = bool(
        institution
        and any(
            (
                financial_request,
                credential_request,
                personal_info_request,
                url_click_request,
                contact_request,
                app_install_request,
                urgency,
                threat_or_pressure,
                unauthorized_claim,
                international_sender_notice,
            )
        )
    )
    return {
        "conversation_text": text[:8000],
        "message_content": message_content[:8000],
        "ocr_messages": records,
        "system_notices": system_notices,
        "sender": next((record["sender"] for record in records if record.get("sender")), None),
        "timestamp": next((record["timestamp"] for record in records if record.get("timestamp")), None),
        "claimed_identity": claimed_identity,
        "claimed_institution": claimed_institution,
        "institution": institution,
        "message_purpose": message_purpose,
        "financial_context_present": financial_context_present,
        "urls": urls,
        "phone_numbers": phone_numbers,
        "link_present": bool(urls),
        "url_present": bool(urls),
        "url_click_request": url_click_request,
        "phone_number_present": bool(phone_numbers),
        "contact_request": contact_request,
        "international_sender": international_sender_notice,
        "international_sender_notice": international_sender_notice,
        "financial_request": financial_request,
        "money_transfer_request": money_transfer_request,
        "payment_request": payment_request,
        "gift_card_request": gift_card_request,
        "bank_transfer_request": bank_transfer_request,
        "requested_asset": "gift_card" if gift_card_request else "bank_transfer" if bank_transfer_request else None,
        "authentication_request": authentication_request,
        "credential_request": credential_request,
        "authentication_present": authentication_present,
        "protective_notice": protective_notice,
        "account_use_request": account_use_request,
        "proxy_action_request": proxy_action_request,
        "link_access_request": link_access_request,
        "callback_request": callback_request,
        "unauthorized_claim": unauthorized_claim,
        "money_request": money_request,
        "urgency": urgency,
        "threat_or_pressure": threat_or_pressure,
        "account_problem_claim": account_problem_claim,
        "device_problem_claim": device_failure_pretext,
        "authentication_problem_claim": authentication_problem_claim,
        "new_contact": new_contact,
        "device_failure_pretext": device_failure_pretext,
        "contact_avoidance": contact_avoidance,
        "channel_restriction": channel_restriction,
        "vague_favor_request": vague_favor_request,
        "relationship_mention": relationship_mention,
        "family_impersonation": family_impersonation,
        "identity_grooming": identity_grooming,
        "institution_impersonation": institution_impersonation,
        "personal_info_request": personal_info_request,
        "app_install_request": app_install_request,
        "direct_contact_willingness": direct_contact_willingness,
        "everyday_conversation": everyday_conversation,
        "event_details": event_details,
        "validated_events": event_details,
        "supporting_evidence": list(dict.fromkeys(supporting_evidence)),
        "benign_signals": benign_signals,
        "contradicting_evidence": benign_signals,
    }


def _split_ocr_records(text: str) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    system_notices: list[str] = []
    current_capture = 1
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        capture_match = re.fullmatch(r"\[캡처\s*(\d+)\]", line)
        if capture_match:
            current_capture = int(capture_match.group(1))
            continue
        line, notices = _separate_system_notices(line)
        system_notices.extend(notices)
        if not line:
            continue
        timestamp_match = re.search(r"(?:오전|오후)?\s*\d{1,2}:\d{2}", line)
        sender_match = re.match(r"(?:보낸 사람|발신자|From)\s*[:：]\s*(.+)", line, re.IGNORECASE)
        records.append(
            {
                "capture_index": current_capture,
                "sender": sender_match.group(1).strip() if sender_match else None,
                "phone_number": (extract_phone_numbers(line) or [None])[0],
                "timestamp": timestamp_match.group(0).strip() if timestamp_match else None,
                "message_content": line,
                "system_notice": False,
            }
        )
    if not records and text.strip():
        records.append(
            {
                "capture_index": 1,
                "sender": None,
                "phone_number": (extract_phone_numbers(text) or [None])[0],
                "timestamp": None,
                "message_content": text.strip(),
                "system_notice": False,
            }
        )
    return records, list(dict.fromkeys(system_notices))


def _separate_system_notices(line: str) -> tuple[str, list[str]]:
    """한 줄 OCR에서도 시스템 표식만 떼고 실제 사기 메시지는 보존합니다."""
    cleaned = line
    notices: list[str] = []
    for pattern in SYSTEM_NOTICE_PATTERNS:
        match = re.search(re.escape(pattern), cleaned, flags=re.IGNORECASE)
        if not match:
            continue
        notices.append(match.group(0))
        cleaned = f"{cleaned[:match.start()]} {cleaned[match.end():]}"
    cleaned = re.sub(r"\[\s*\]", " ", cleaned)
    cleaned = re.sub(r"\[\s*시스템\s*안내\s*\]", " ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip(" \t:：|-·")
    return cleaned, notices


def _extract_institution(text: str) -> str | None:
    normalized = text.lower()
    for official_name, aliases in INSTITUTION_ALIASES.items():
        if any(alias.lower() in normalized for alias in aliases):
            return official_name
    return None


def _extract_claimed_identity(text: str) -> str | None:
    identities = (
        ("daughter", ("딸이야", "딸인데", "딸이", "딸인데요")),
        ("son", ("아들이야", "아들인데", "아들이")),
        ("mother", ("엄마야", "엄마인데")),
        ("father", ("아빠야", "아빠인데")),
        ("friend", ("친구야", "친구인데", "지인이야")),
    )
    for identity, phrases in identities:
        if any(phrase in text for phrase in phrases):
            return identity
    return None


def _find_evidence_line(text: str, keywords: tuple[str, ...]) -> str | None:
    normalized_keywords = tuple(str(keyword).lower() for keyword in keywords if keyword)
    for line in _evidence_lines(text):
        normalized_line = line.lower()
        if any(keyword in normalized_line for keyword in normalized_keywords):
            return line
    return None


def _find_request_evidence(
    text: str,
    subjects: tuple[str, ...],
    actions: tuple[str, ...],
) -> str | None:
    normalized_subjects = tuple(subject.lower() for subject in subjects)
    normalized_actions = tuple(action.lower() for action in actions)
    for line in _evidence_lines(text):
        normalized_line = line.lower()
        if any(subject in normalized_line for subject in normalized_subjects) and any(
            action in normalized_line for action in normalized_actions
        ):
            return line
    return None


def _find_phone_evidence(text: str, phone_numbers: list[str]) -> str | None:
    for line in _evidence_lines(text):
        compact_line = re.sub(r"[^0-9]", "", line)
        for phone in phone_numbers:
            compact_phone = re.sub(r"[^0-9]", "", phone)
            if compact_phone and compact_phone in compact_line:
                return line
    return None


def _evidence_lines(text: str) -> list[str]:
    return [
        re.sub(r"\s+", " ", line).strip()
        for line in text.splitlines()
        if line.strip()
    ]


def _validated_event(value: bool, evidence: str | None) -> dict:
    cleaned_evidence = re.sub(r"\s+", " ", evidence).strip() if evidence else None
    validated_value = bool(value and cleaned_evidence)
    return {
        "value": validated_value,
        "evidence": cleaned_evidence if validated_value else None,
    }


def _message_purpose(normalized_text: str, candidates: dict[str, bool]) -> str:
    for purpose, matched in candidates.items():
        if matched:
            return purpose
    if _contains(normalized_text, "안내", "알림"):
        return "informational_notice"
    return "unknown"


def _benign_signals(
    normalized_text: str,
    message_purpose: str,
    events: dict[str, dict],
    masked_account: bool,
) -> list[str]:
    signals: list[str] = []
    purpose_labels = {
        "fee_change_notice": "단순 수수료 변경 안내",
        "transaction_notice": "단순 거래내역 안내",
        "authentication_notice": "상대방에게 전달하라는 요구가 없는 인증 안내",
        "delivery_notice": "금전·링크 행동 요구가 없는 배송 안내",
        "informational_notice": "정보성 안내 형식",
    }
    if message_purpose in purpose_labels:
        signals.append(purpose_labels[message_purpose])
    absent_labels = {
        "money_transfer_request": "송금 요구 없음",
        "payment_request": "결제·비용 지불 요구 없음",
        "gift_card_request": "상품권 요구 없음",
        "credential_request": "인증정보 제공 요구 없음",
        "personal_info_request": "개인정보 제공 요구 없음",
        "url_click_request": "URL 접속 요구 없음",
        "app_install_request": "앱 설치 요구 없음",
    }
    for event_name, label in absent_labels.items():
        if not events[event_name]["value"]:
            signals.append(label)
    if masked_account and "계좌" in normalized_text:
        signals.append("계좌번호 일부 마스킹")
    return signals


def _contains(text: str, *keywords: str) -> bool:
    return any(keyword.lower() in text for keyword in keywords)
