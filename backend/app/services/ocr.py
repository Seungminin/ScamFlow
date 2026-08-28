"""Upstage Document Digitization 기반 선택적 OCR."""

import base64
import html
import re
from typing import Any

import httpx

from app.core.config import settings


class OcrService:
    async def extract(self, image_base64: str, filename: str) -> str:
        if not settings.enable_ocr or not settings.upstage_api_key:
            raise ValueError("OCR이 비활성화되어 있습니다. 텍스트를 직접 붙여넣거나 ENABLE_OCR=true로 설정하세요.")
        if not filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            raise ValueError("PNG, JPG, JPEG 또는 WEBP 이미지만 업로드할 수 있습니다.")
        data_uri = re.match(r"^data:([^;]+);base64,", image_base64)
        if data_uri and data_uri.group(1) not in {"image/png", "image/jpeg", "image/webp"}:
            raise ValueError("PNG, JPG, JPEG 또는 WEBP 이미지만 업로드할 수 있습니다.")
        payload = re.sub(r"^data:[^;]+;base64,", "", image_base64)
        try:
            image_bytes = base64.b64decode(payload, validate=True)
        except ValueError as exc:
            raise ValueError("올바른 Base64 이미지가 아닙니다.") from exc
        if len(image_bytes) > 10 * 1024 * 1024:
            raise ValueError("이미지는 10MB 이하여야 합니다.")
        async with httpx.AsyncClient(timeout=40) as client:
            response = await client.post(
                "https://api.upstage.ai/v1/document-digitization",
                headers={"Authorization": f"Bearer {settings.upstage_api_key}"},
                files={"document": (filename, image_bytes)},
                data={"ocr": "force", "model": "document-parse"},
            )
            response.raise_for_status()
        text = self._collect_text(response.json())
        if not text.strip():
            raise ValueError("이미지에서 분석할 텍스트를 찾지 못했습니다.")
        return text[:8000]

    def _collect_text(self, value: Any) -> str:
        if isinstance(value, str):
            # Document Parse가 HTML을 반환해도 문자/메시지의 줄 경계를 보존합니다.
            # 모든 태그를 공백으로 바꾸면 `[국제발신]`과 실제 메시지가 한 줄이 되어
            # 시스템 안내로 전체 문장이 제거될 수 있습니다.
            text = re.sub(
                r"(?i)<\s*(?:br|/p|/div|/li|/tr|/h[1-6])\s*/?>",
                "\n",
                value,
            )
            text = re.sub(r"<[^>]+>", " ", text)
            text = html.unescape(text)
            text = re.sub(r"[ \t]+", " ", text)
            text = re.sub(r" *\n *", "\n", text)
            return text.strip()
        if isinstance(value, list):
            return "\n".join(filter(None, (self._collect_text(item) for item in value)))
        if isinstance(value, dict):
            preferred = [value[key] for key in ("text", "content", "html", "markdown") if key in value]
            return "\n".join(filter(None, (self._collect_text(item) for item in (preferred or value.values()))))
        return ""
