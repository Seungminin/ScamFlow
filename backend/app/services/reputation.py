"""URL 위협정보 provider를 독립 실행하고 실패를 중립 결과로 격리합니다."""

import base64
import ipaddress
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import unquote, urlparse

import httpx
from loguru import logger

from app.core.config import settings
from app.services.url_analysis import registrable_domain


class ReputationProvider(Protocol):
    name: str

    async def lookup(self, url: str) -> dict | None: ...


def is_kisa_whois_target(url: str) -> bool:
    """KISA가 제공하는 .kr·.한국 도메인과 IP 조회 대상인지 판별합니다."""
    host = (urlparse(url).hostname or "").lower()
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return registrable_domain(host).endswith((".kr", ".한국"))


class GoogleSafeBrowsingProvider:
    name = "google_safe_browsing"

    async def lookup(self, url: str) -> dict | None:
        if not settings.google_safe_browsing_api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=settings.external_api_timeout_seconds) as client:
                response = await client.post(
                    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                    params={"key": settings.google_safe_browsing_api_key},
                    json={
                        "client": {"clientId": "scamflow", "clientVersion": "0.1.0"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": url}],
                        },
                    },
                )
                response.raise_for_status()
            matches = response.json().get("matches", [])
            return {
                "provider": self.name,
                "status": "malicious" if matches else "no_detection",
                "threat_types": sorted({item.get("threatType", "UNKNOWN") for item in matches}),
                "score": 100 if matches else 0,
                "notice": "미탐지 결과는 URL의 안전을 보증하지 않습니다.",
            }
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            logger.warning(f"Google Safe Browsing 조회 실패: {_safe_error(exc)}")
            return {"provider": self.name, "status": "unavailable", "score": 0, "notice": "Safe Browsing 조회 실패로 중립 처리했습니다."}


class KisaWhoisProvider:
    name = "kisa_whois"

    async def lookup(self, url: str) -> dict | None:
        if not settings.kisa_whois_api_key:
            return None
        host = (urlparse(url).hostname or "").lower()
        query = host if self._is_ip(host) else registrable_domain(host)
        if not is_kisa_whois_target(url):
            return {"provider": self.name, "status": "not_applicable", "score": 0, "query": query, "notice": "KISA 등록정보 대상(.kr·.한국·IP)이 아닙니다."}
        try:
            endpoint, key_name = self._request_target(query)
            async with httpx.AsyncClient(timeout=settings.external_api_timeout_seconds) as client:
                response = await client.get(
                    endpoint,
                    params={
                        "query": query,
                        key_name: unquote(settings.kisa_whois_api_key),
                        "answer": "json",
                    },
                )
                response.raise_for_status()
            payload = _response_payload(response)
            result_code = _find_value(
                payload,
                "result_code",
                "resultCode",
                "error_code",
                "returnReasonCode",
            )
            if result_code and result_code != "10000":
                status = "not_found" if result_code in {"100", "200", "300", "400", "900"} else "unavailable"
                return {
                    "provider": self.name,
                    "status": status,
                    "score": 0,
                    "query": query,
                    "error_code": result_code,
                    "notice": "WHOIS 조회 결과가 없거나 제공기관이 요청을 처리하지 못해 중립 처리했습니다.",
                }
            created = _find_value(payload, "createdDate", "created_date", "regDate", "registrationDate")
            age_days = _domain_age_days(created)
            score = 0
            reasons: list[str] = []
            if age_days is not None and age_days < 30:
                score = 85
                reasons.append(f"등록 후 {age_days}일인 신규 도메인입니다.")
            elif age_days is not None and age_days < 180:
                score = 55
                reasons.append(f"등록 후 {age_days}일로 비교적 최근 생성된 도메인입니다.")
            elif age_days is not None:
                reasons.append(f"도메인 등록 후 {age_days}일이 경과했습니다.")
            return {
                "provider": self.name,
                "status": "found",
                "score": score,
                "query": query,
                "created_date": created,
                "domain_age_days": age_days,
                "registrar": _find_value(payload, "registrar", "registrarName", "agency"),
                "country_code": _find_value(payload, "countryCode", "country_code"),
                "asn": _find_value(payload, "asn", "ASNumber", "asNumber"),
                "reasons": reasons or ["등록일 위험 신호를 확인할 수 없습니다."],
                "notice": "WHOIS 정보는 등록 주체의 신뢰성을 보증하지 않습니다.",
            }
        except (httpx.HTTPError, ET.ParseError, KeyError, TypeError, ValueError) as exc:
            logger.warning(f"KISA WHOIS 조회 실패: {_safe_error(exc)}")
            return {"provider": self.name, "status": "unavailable", "score": 0, "query": query, "notice": "WHOIS 조회 실패로 domain age를 중립 처리했습니다."}

    def _request_target(self, query: str) -> tuple[str, str]:
        """공공데이터포털 일반 인증키와 구형 KISA OpenAPI를 모두 지원합니다."""
        base_url = settings.kisa_whois_api_url.rstrip("/")
        if "apis.data.go.kr" in base_url or base_url.endswith("/whois"):
            resource = "ip_address" if self._is_ip(query) else "domain_name"
            return f"{base_url}/{resource}", "serviceKey"
        return base_url, "key"

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


class VirusTotalProvider:
    """기존 분석 기록만 조회합니다. 신규 URL 제출은 하지 않습니다."""

    name = "virustotal"

    async def lookup(self, url: str) -> dict | None:
        if not settings.virustotal_api_key:
            return None
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            async with httpx.AsyncClient(timeout=settings.external_api_timeout_seconds) as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": settings.virustotal_api_key},
                )
            if response.status_code == 404:
                return {"provider": self.name, "status": "not_found", "score": 0, "notice": "기존 분석 기록이 없습니다. 안전하다는 의미가 아닙니다."}
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            status = "malicious" if malicious else "suspicious" if suspicious else "no_detection"
            return {
                "provider": self.name,
                "status": status,
                "score": 95 if malicious else 65 if suspicious else 0,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": int(stats.get("harmless", 0)),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "redirect_target": attributes.get("last_final_url"),
                "community_reputation": attributes.get("reputation"),
                "notice": "미탐지 결과는 URL의 안전을 보증하지 않습니다.",
            }
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            logger.warning(f"VirusTotal 조회 실패: {_safe_error(exc)}")
            return {"provider": self.name, "status": "unavailable", "score": 0, "notice": "VirusTotal 조회 실패로 중립 처리했습니다."}


class UrlReputationService:
    def __init__(self, providers: list[ReputationProvider] | None = None):
        self.providers = providers or [GoogleSafeBrowsingProvider(), KisaWhoisProvider(), VirusTotalProvider()]

    async def lookup(
        self,
        url: str,
        selected_providers: set[str] | None = None,
    ) -> list[dict]:
        if not settings.enable_url_reputation:
            return []
        results: list[dict] = []
        for provider in self.providers:
            if selected_providers is not None and provider.name not in selected_providers:
                continue
            result = await provider.lookup(url)
            if result:
                results.append(result)
        return results


def _find_value(value: object, *keys: str) -> str | None:
    wanted = {key.lower() for key in keys}
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in wanted and item not in (None, ""):
                return str(item)
        for item in value.values():
            found = _find_value(item, *keys)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_value(item, *keys)
            if found:
                return found
    return None


def _response_payload(response: httpx.Response) -> object:
    """JSON 우선, 공공데이터포털 게이트웨이 오류는 XML로 안전하게 파싱합니다."""
    try:
        return response.json()
    except ValueError:
        root = ET.fromstring(response.text)
        return {
            element.tag.rsplit("}", 1)[-1]: element.text.strip()
            for element in root.iter()
            if element.text and element.text.strip()
        }


def _safe_error(exc: Exception) -> str:
    """쿼리스트링의 API 키가 로그에 포함되지 않도록 오류 유형만 남깁니다."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTPStatusError(status={exc.response.status_code})"
    return type(exc).__name__


def _domain_age_days(value: str | None) -> int | None:
    if not value:
        return None
    match = re.search(
        r"(\d{4})\s*[-./]?\s*(\d{2})\s*[-./]?\s*(\d{2})",
        value,
    )
    if not match:
        return None
    try:
        created = datetime(*map(int, match.groups()), tzinfo=UTC)
        return max(0, (datetime.now(UTC) - created).days)
    except ValueError:
        return None
