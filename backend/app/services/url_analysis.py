"""eTLD+1 기준 allowlist와 URL 구조 위험을 계산하는 결정론적 엔진."""

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import tldextract

ALLOWLIST_PATH = Path(__file__).parents[2] / "data" / "official_domains.json"
OFFICIAL_DOMAINS: dict[str, str] = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
SHORTENER_DOMAINS = {
    "bit.ly",
    "han.gl",
    "is.gd",
    "me2.do",
    "t.co",
    "tinyurl.com",
    "url.kr",
}
SUSPICIOUS_TLDS = {"cam", "click", "loan", "mov", "top", "work", "xyz", "zip"}
BRAND_LABELS = {
    domain: re.split(r"[.-]", domain)[0]
    for domain in OFFICIAL_DOMAINS
}
_extract = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def registrable_domain(host: str) -> str:
    """Public Suffix List snapshot으로 실제 등록 가능 도메인(eTLD+1)을 반환합니다."""
    normalized = host.strip(".").lower()
    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass
    parts = _extract(normalized)
    return parts.top_domain_under_public_suffix or normalized


class UrlRuleEngine:
    def analyze(self, url: str) -> dict:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").strip(".").lower()
        registered = registrable_domain(host)
        official_name = OFFICIAL_DOMAINS.get(registered)
        reasons: list[str] = []
        score = 0

        if parsed.scheme.lower() != "https":
            score += 15
            reasons.append("HTTPS가 아닌 연결입니다.")
        is_ip = self._is_ip(host)
        if is_ip:
            score += 30
            reasons.append("도메인 대신 IP 주소를 직접 사용합니다.")
        if host.startswith("xn--") or ".xn--" in host:
            score += 24
            reasons.append("Punycode 국제화 도메인으로 표시 위장이 가능한 형태입니다.")
        if "@" in parsed.netloc or "@" in unquote(url):
            score += 50
            reasons.append("@ 문자로 실제 접속 호스트를 혼동시킬 수 있습니다.")

        suffix = _extract(host).suffix
        subdomain_depth = max(0, len(host.split(".")) - len(suffix.split(".")) - 1) if suffix else 0
        if subdomain_depth >= 4:
            score += min(24, 8 + (subdomain_depth - 4) * 4)
            reasons.append(f"하위 도메인이 과도하게 많습니다({subdomain_depth}단계).")
        if len(url) >= 120:
            score += 12 if len(url) < 200 else 20
            reasons.append(f"URL 길이가 비정상적으로 깁니다({len(url)}자).")
        special_count = sum(url.count(char) for char in ("%", "=", "&", ";", "_", "~"))
        if special_count >= 10:
            score += min(18, special_count)
            reasons.append("인코딩·특수문자가 과도하게 포함돼 있습니다.")
        if registered in SHORTENER_DOMAINS:
            score += 30
            reasons.append("최종 목적지를 숨기는 단축 URL입니다.")
        if suffix.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            score += 25
            reasons.append("피싱에 자주 악용되는 최상위 도메인 형태입니다.")
        if parsed.path.lower().endswith(".apk") or ".apk" in parsed.path.lower():
            score += 45
            reasons.append("앱 설치 파일을 직접 배포하는 주소입니다.")
        if self._has_redirect_parameter(parsed.query):
            score += 14
            reasons.append("다른 주소로 이동시키는 redirect 파라미터가 포함돼 있습니다.")

        impersonated = self._impersonated_brand(host, registered)
        if impersonated:
            score += 38
            reasons.append(f"공식 {impersonated} 도메인과 유사하지만 실제 등록 도메인이 다릅니다.")

        if official_name:
            # eTLD+1이 정확히 일치한 공식 도메인은 구조적 오탐을 억제합니다.
            score = min(score, 8 if parsed.scheme.lower() == "https" else 18)
            reasons = [f"실제 등록 도메인이 공식 {official_name} allowlist와 일치합니다."] + [
                reason for reason in reasons if "HTTPS" in reason
            ]

        return {
            "url": url,
            "host": host,
            "registrable_domain": registered,
            "is_allowlisted": bool(official_name),
            "official_name": official_name,
            "is_ip": is_ip,
            "subdomain_depth": subdomain_depth,
            "score": min(score, 100),
            "reasons": reasons or ["URL 구조에서 뚜렷한 위험 신호가 확인되지 않았습니다."],
        }

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _has_redirect_parameter(query: str) -> bool:
        redirect_keys = {"continue", "dest", "destination", "next", "redirect", "redirect_uri", "return", "returnurl", "url"}
        values = parse_qs(query, keep_blank_values=True)
        return any(key.lower() in redirect_keys and any("://" in value for value in entries) for key, entries in values.items())

    @staticmethod
    def _impersonated_brand(host: str, registered: str) -> str | None:
        candidate = re.sub(r"[^a-z0-9]", "", registered.split(".")[0])
        for official_domain in BRAND_LABELS:
            if registered == official_domain:
                continue
            official_label = re.sub(r"[^a-z0-9]", "", official_domain.split(".")[0])
            if official_label and (
                official_label in re.sub(r"[^a-z0-9]", "", host)
                or _levenshtein(candidate, official_label) <= 1
            ):
                return OFFICIAL_DOMAINS[official_domain]
        return None


def _levenshtein(left: str, right: str) -> int:
    if not left:
        return len(right)
    previous = list(range(len(right) + 1))
    for index, left_char in enumerate(left, start=1):
        current = [index]
        for right_index, right_char in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_char != right_char),
                )
            )
        previous = current
    return previous[-1]
