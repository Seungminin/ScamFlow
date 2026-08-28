"""URL·전화번호·기관정보를 검증하는 비금융 Tool."""

import re

from app.services.url_analysis import UrlRuleEngine

OFFICIAL_NUMBERS = {
    "112": "경찰청 범죄신고",
    "118": "한국인터넷진흥원 상담",
    "1301": "검찰청 콜센터",
    "1332": "금융감독원 상담",
    "1397": "서민금융진흥원",
    "15889999": "KB국민은행 대표번호",
    "15778000": "신한은행 대표번호",
    "15885000": "우리은행 대표번호",
    "15995000": "우리은행 대표번호",
    "15335000": "우리은행 대표번호",
    "15888100": "롯데카드 대표번호",
    "15888300": "롯데카드 분실·승인상담",
    "125": "관세청 고객지원센터",
    "15991111": "하나은행 대표번호",
    "16613000": "NH농협은행 대표번호",
}

OFFICIAL_INSTITUTION_NUMBERS = {
    "우리은행": {"15885000", "15995000", "15335000"},
    "롯데카드": {"15888100", "15888300"},
    "KB국민은행": {"15889999"},
    "신한은행": {"15778000"},
    "하나은행": {"15991111"},
    "NH농협은행": {"16613000"},
    "경찰청": {"112"},
    "검찰청": {"1301"},
    "금융감독원": {"1332"},
    "관세청": {"125"},
}

OFFICIAL_CONTACT_SOURCES = {
    "우리은행": "https://spot.wooribank.com/pot/Dream?withyou=ln",
    "롯데카드": "https://www.lottecard.co.kr/app/LPCOIAH_V100.lc",
    "관세청": "https://www.customs.go.kr/",
}

url_rule_engine = UrlRuleEngine()


URL_CANDIDATE_PATTERN = re.compile(
    r"(?:"
    r"(?:https?|hxxps?)://[a-z0-9][a-z0-9.-]*(?::\d{2,5})?(?:/[a-z0-9/_~%?=&+#:;.,@!$()*-]*)?"
    r"|www\.[a-z0-9][a-z0-9.-]*(?:\.[a-z]{2,63}|\.xn--[a-z0-9-]+)(?::\d{2,5})?(?:/[a-z0-9/_~%?=&+#:;.,@!$()*-]*)?"
    r"|(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]+)(?::\d{2,5})?(?:/[a-z0-9/_~%?=&+#:;.,@!$()*-]*)?"
    r")",
    flags=re.IGNORECASE,
)


def extract_urls(text: str) -> list[str]:
    """scheme이 없는 단축 URL과 OCR 간격까지 복원해 검증 가능한 URL로 정규화합니다."""
    repaired = _repair_ocr_url_spacing(text)
    urls: list[str] = []
    for match in URL_CANDIDATE_PATTERN.finditer(repaired):
        candidate = _normalize_url_candidate(match.group(0))
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls


def _repair_ocr_url_spacing(text: str) -> str:
    repaired = re.sub(
        r"(?i)\b(h(?:tt|xx)p[s]?)\s*:\s*/\s*/",
        lambda match: f"{match.group(1)}://",
        text,
    )
    # OCR이 `bit . ly /abc`처럼 도메인 구분자 주변에만 넣은 공백을 제거합니다.
    repaired = re.sub(
        r"(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\s*\.\s*([a-z]{2,63}|xn--[a-z0-9-]+)\b",
        r"\1.\2",
        repaired,
    )
    repaired = re.sub(
        r"(?i)\b((?:[a-z0-9-]+\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]+))\s*/\s*",
        r"\1/",
        repaired,
    )
    return repaired


def _normalize_url_candidate(candidate: str) -> str | None:
    cleaned = candidate.strip().rstrip(".,!?;:ㆍ。，！？；：’”')]}>")
    cleaned = re.sub(r"(?i)^hxxp", "http", cleaned)
    if not cleaned:
        return None
    if not re.match(r"(?i)^https?://", cleaned):
        cleaned = f"https://{cleaned}"
    return cleaned


def extract_phone_numbers(text: str) -> list[str]:
    candidates = re.findall(
        r"(?<!\d)(?:00\d{8,15}|0\d{1,2}[)\-. ]?\d{3,4}[-. ]?\d{4}|1\d{2,3})(?!\d)",
        text,
    )
    return list(dict.fromkeys(candidates))


def inspect_url(url: str) -> dict:
    analysis = url_rule_engine.analyze(url)
    score = int(analysis["score"])
    risk = "suspicious" if score >= 45 else "low" if analysis["is_allowlisted"] else "unknown"
    return {
        **analysis,
        "risk": risk,
        "risk_score": score,
        "known_domain": analysis["official_name"],
        "signals": analysis["reasons"],
        "notice": "낮은 URL 위험도는 해당 페이지나 상대방의 신원을 보증하지 않습니다.",
    }


def inspect_phone(phone: str) -> dict:
    normalized = re.sub(r"\D", "", phone)
    agency = OFFICIAL_NUMBERS.get(normalized)
    return {
        "phone": phone,
        "normalized": normalized,
        "is_known_official": agency is not None,
        "agency": agency,
        "notice": "발신번호는 조작될 수 있으므로 화면에 표시된 번호만으로 신원을 보증할 수 없습니다.",
    }
