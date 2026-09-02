"""LLM 트리아지 검증 — 실제 API 호출 없이 가짜 프로바이더로 확인."""
import json
import os
import types

import pytest

from cpguard.parse import loader, normalize
from cpguard.taint import engine
from cpguard.taint.spec import load_rules
from cpguard.triage import llm, providers

RULES = load_rules(language="javascript")

SRC = """
function a(req){ const c = req.query.c; child_process.exec(c); }
function b(req){ const e = req.body.e; eval(e); }
"""


def _findings():
    mod = normalize.normalize(loader.parse_source(SRC), file="t.js")
    return engine.analyze(mod, SRC.encode(), RULES)


class FakeProvider:
    """Provider 계약(complete_json)만 흉내내는 가짜."""

    name = "fake"

    def __init__(self, payload=None, error=None):
        self.payload = payload or {"results": []}
        self.error = error
        self.calls = []

    def complete_json(self, system, prompt):
        self.calls.append({"system": system, "prompt": prompt})
        if self.error:
            raise self.error
        return json.loads(json.dumps(self.payload))


def _use(monkeypatch, fake):
    monkeypatch.setattr(llm, "get_provider",
                        lambda name=None, api_key=None, model=None: fake)
    return fake


# ---------- 판정 부착 ----------

def test_verdicts_are_attached(monkeypatch):
    fs = _findings()
    assert len(fs) >= 2
    fake = _use(monkeypatch, FakeProvider({"results": [
        {"index": 0, "verdict": "true_positive", "confidence": 0.9, "reason": "정제 없이 도달"},
        {"index": 1, "verdict": "false_positive", "confidence": 0.8, "reason": "상수만 흐름"},
    ]}))

    llm.triage_findings(fs[:2])
    assert fs[0].verdict == "true_positive" and fs[0].confidence == 0.9
    assert fs[1].verdict == "false_positive"
    assert "상수" in fs[1].triage_reason
    assert fs[0].triage_provider == fake.name


def test_findings_are_never_dropped(monkeypatch):
    """오탐 판정이 나도 결과를 지우지 않는다(사람이 최종 판단)."""
    fs = _findings()
    n = len(fs)
    _use(monkeypatch, FakeProvider({"results": [
        {"index": i, "verdict": "false_positive", "confidence": 0.9, "reason": "x"}
        for i in range(n)]}))
    assert len(llm.triage_findings(fs)) == n


def test_unknown_verdict_falls_back_to_uncertain(monkeypatch):
    fs = _findings()[:1]
    _use(monkeypatch, FakeProvider({"results": [
        {"index": 0, "verdict": "definitely_bad", "confidence": 1.0, "reason": "x"}]}))
    llm.triage_findings(fs)
    assert fs[0].verdict == "uncertain"


def test_missing_result_is_uncertain(monkeypatch):
    fs = _findings()[:1]
    _use(monkeypatch, FakeProvider({"results": []}))
    llm.triage_findings(fs)
    assert fs[0].verdict == "uncertain"


def test_api_failure_does_not_crash(monkeypatch):
    fs = _findings()[:1]
    _use(monkeypatch, FakeProvider(error=RuntimeError("network down")))
    llm.triage_findings(fs)
    assert fs[0].verdict == "uncertain"
    assert "실패" in fs[0].triage_reason


def test_batching_splits_requests(monkeypatch):
    fs = _findings()
    fake = _use(monkeypatch, FakeProvider({"results": [
        {"index": i, "verdict": "uncertain", "confidence": 0.5, "reason": "x"}
        for i in range(10)]}))
    llm.triage_findings(fs, batch_size=1)
    assert len(fake.calls) == len(fs)


def test_prompt_contains_flow_and_context(monkeypatch):
    fs = _findings()[:1]
    fake = _use(monkeypatch, FakeProvider({"results": [
        {"index": 0, "verdict": "true_positive", "confidence": 0.9, "reason": "x"}]}))
    llm.triage_findings(fs)
    call = fake.calls[0]
    assert "데이터 흐름" in call["prompt"]
    assert "[source]" in call["prompt"] and "[sink]" in call["prompt"]
    assert call["system"].startswith("당신은")


def test_empty_findings_short_circuits(monkeypatch):
    def explode(name=None, api_key=None, model=None):
        raise AssertionError("빈 목록에서는 프로바이더를 만들지 않아야 한다")

    monkeypatch.setattr(llm, "get_provider", explode)
    assert llm.triage_findings([]) == []


# ---------- 프로바이더 선택 ----------

def _clear_keys(monkeypatch):
    for cls in providers.PROVIDERS.values():
        monkeypatch.delenv(cls.env_key, raising=False)


def test_three_providers_registered():
    assert set(providers.PROVIDERS) == {"claude", "openai", "gemini"}


def test_no_key_raises_with_guidance(monkeypatch):
    _clear_keys(monkeypatch)
    with pytest.raises(providers.ProviderUnavailable) as e:
        providers.get_provider()
    msg = str(e.value)
    for env in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
        assert env in msg


def test_available_reflects_env(monkeypatch):
    _clear_keys(monkeypatch)
    assert providers.available() == []
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    assert providers.available() == ["gemini"]
    monkeypatch.setenv("OPENAI_API_KEY", "y")
    assert providers.available() == ["openai", "gemini"]


def test_unknown_provider_name(monkeypatch):
    with pytest.raises(providers.ProviderUnavailable):
        providers.get_provider("llama")


def test_missing_key_for_named_provider(monkeypatch):
    _clear_keys(monkeypatch)
    with pytest.raises(providers.ProviderUnavailable) as e:
        providers.get_provider("gemini")
    assert "GEMINI_API_KEY" in str(e.value)


def test_gemini_schema_strips_additional_properties():
    """Gemini 는 additionalProperties 를 거부하므로 제거해 보내야 한다."""
    cleaned = providers._strip_unsupported(providers.RESULT_SCHEMA)
    dumped = json.dumps(cleaned)
    assert "additionalProperties" not in dumped
    assert "results" in cleaned["properties"]


def test_schema_defines_three_verdicts():
    item = providers.RESULT_SCHEMA["properties"]["results"]["items"]
    assert set(item["properties"]["verdict"]["enum"]) == {
        "true_positive", "false_positive", "uncertain"}
