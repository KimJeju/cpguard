"""LLM 프로바이더 어댑터 — Claude / OpenAI / Gemini.

트리아지 로직은 프로바이더를 모른다. 각 어댑터는 "시스템 지시 + 사용자 프롬프트를 받아
JSON 문자열을 돌려준다"는 하나의 계약만 지킨다.

키 탐색 순서(자동 선택 시): Claude → OpenAI → Gemini.
명시적으로 고르려면 provider 이름을 넘긴다.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod

# 판정 결과 JSON 스키마 (프로바이더마다 표현 방식이 달라 각자 변환한다)
RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "verdict": {"type": "string",
                                "enum": ["true_positive", "false_positive", "uncertain"]},
                    "confidence": {"type": "number"},
                    "reason": {"type": "string"},
                },
                "required": ["index", "verdict", "confidence", "reason"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["results"],
    "additionalProperties": False,
}


class ProviderUnavailable(RuntimeError):
    """SDK 미설치 또는 API 키 없음."""


class Provider(ABC):
    name: str
    env_key: str
    default_model: str

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or os.environ.get(self.env_key)
        self.model = model or self.default_model
        if not self.api_key:
            raise ProviderUnavailable(
                f"{self.name}: API 키가 없습니다. 환경변수 {self.env_key} 를 설정하세요."
            )
        self._client = self._make_client()

    @abstractmethod
    def _make_client(self): ...

    @abstractmethod
    def complete_json(self, system: str, prompt: str) -> dict:
        """시스템 지시 + 프롬프트를 보내고 스키마에 맞는 dict 를 돌려준다."""

    @abstractmethod
    def complete_text(self, system: str, prompt: str) -> str:
        """자유 서술 답변 (AI 분석 패널용). 마크다운 텍스트를 돌려준다."""


class ClaudeProvider(Provider):
    name = "claude"
    env_key = "ANTHROPIC_API_KEY"
    default_model = "claude-opus-5"

    def _make_client(self):
        try:
            import anthropic
        except ImportError as e:
            raise ProviderUnavailable(
                "claude: anthropic SDK 가 없습니다. pip install anthropic") from e
        return anthropic.Anthropic(api_key=self.api_key)

    def complete_json(self, system: str, prompt: str) -> dict:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=16000,
            system=system,
            thinking={"type": "adaptive"},
            output_config={"format": {"type": "json_schema", "schema": RESULT_SCHEMA}},
            messages=[{"role": "user", "content": prompt}],
        )
        text = next((b.text for b in resp.content if b.type == "text"), "")
        return json.loads(text)

    def complete_text(self, system: str, prompt: str) -> str:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=16000,
            system=system,
            thinking={"type": "adaptive"},
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")


class OpenAIProvider(Provider):
    name = "openai"
    env_key = "OPENAI_API_KEY"
    default_model = "gpt-4o"

    def _make_client(self):
        try:
            from openai import OpenAI
        except ImportError as e:
            raise ProviderUnavailable(
                "openai: openai SDK 가 없습니다. pip install openai") from e
        return OpenAI(api_key=self.api_key)

    def complete_json(self, system: str, prompt: str) -> dict:
        resp = self._client.chat.completions.create(
            model=self.model,
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "triage", "strict": True, "schema": RESULT_SCHEMA},
            },
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        return json.loads(resp.choices[0].message.content)

    def complete_text(self, system: str, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""


class GeminiProvider(Provider):
    name = "gemini"
    env_key = "GEMINI_API_KEY"
    default_model = "gemini-2.0-flash"

    def _make_client(self):
        try:
            from google import genai
        except ImportError as e:
            raise ProviderUnavailable(
                "gemini: google-genai SDK 가 없습니다. pip install google-genai") from e
        return genai.Client(api_key=self.api_key)

    def complete_json(self, system: str, prompt: str) -> dict:
        # Gemini 는 JSON 스키마에서 additionalProperties 를 받지 않으므로 제거해 전달한다
        schema = _strip_unsupported(RESULT_SCHEMA)
        resp = self._client.models.generate_content(
            model=self.model,
            contents=prompt,
            config={
                "system_instruction": system,
                "response_mime_type": "application/json",
                "response_schema": schema,
            },
        )
        return json.loads(resp.text)

    def complete_text(self, system: str, prompt: str) -> str:
        resp = self._client.models.generate_content(
            model=self.model,
            contents=prompt,
            config={"system_instruction": system},
        )
        return resp.text or ""


def _strip_unsupported(schema):
    """Gemini 가 거부하는 키를 재귀적으로 제거."""
    if isinstance(schema, dict):
        return {k: _strip_unsupported(v) for k, v in schema.items()
                if k != "additionalProperties"}
    if isinstance(schema, list):
        return [_strip_unsupported(v) for v in schema]
    return schema


PROVIDERS: dict[str, type[Provider]] = {
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
}

# 자동 선택 순서
AUTO_ORDER = ("claude", "openai", "gemini")


def available() -> list[str]:
    """환경변수에 키가 있는 프로바이더 목록."""
    return [n for n in AUTO_ORDER if os.environ.get(PROVIDERS[n].env_key)]


def get_provider(name: str | None = None, api_key: str | None = None,
                 model: str | None = None) -> Provider:
    """프로바이더를 만든다. name 이 없으면 키가 있는 것을 순서대로 시도한다."""
    if name:
        key = name.lower()
        if key not in PROVIDERS:
            raise ProviderUnavailable(
                f"알 수 없는 프로바이더: {name} (가능: {', '.join(PROVIDERS)})")
        return PROVIDERS[key](api_key=api_key, model=model)

    errors = []
    for candidate in AUTO_ORDER:
        try:
            return PROVIDERS[candidate](api_key=None, model=model)
        except ProviderUnavailable as e:
            errors.append(str(e))
    raise ProviderUnavailable(
        "사용 가능한 LLM 프로바이더가 없습니다. 다음 중 하나의 키를 설정하세요:\n  "
        + "\n  ".join(f"{n}: {PROVIDERS[n].env_key}" for n in AUTO_ORDER)
    )
