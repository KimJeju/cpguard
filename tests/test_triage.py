"""LLM 트리아지 로직 검증 — 실제 API 호출 없이 스텁 클라이언트로 확인."""
import json
import types

import pytest

from cpguard.parse import loader, normalize
from cpguard.taint import engine
from cpguard.taint.spec import load_rules
from cpguard.triage import llm

RULES = load_rules(language="javascript")

SRC = """
function a(req){ const c = req.query.c; child_process.exec(c); }
function b(req){ const e = req.body.e; eval(e); }
"""


def _findings():
    mod = normalize.normalize(loader.parse_source(SRC), file="t.js")
    return engine.analyze(mod, SRC.encode(), RULES)


def _stub_client(payload):
    """messages.create 가 정해진 JSON 을 돌려주는 가짜 클라이언트."""
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        block = types.SimpleNamespace(type="text", text=json.dumps(payload))
        return types.SimpleNamespace(content=[block])

    client = types.SimpleNamespace(messages=types.SimpleNamespace(create=create))
    return client, calls


def test_verdicts_are_attached(monkeypatch):
    fs = _findings()
    assert len(fs) >= 2
    payload = {"results": [
        {"index": 0, "verdict": "true_positive", "confidence": 0.9, "reason": "정제 없이 도달"},
        {"index": 1, "verdict": "false_positive", "confidence": 0.8, "reason": "상수만 흐름"},
    ]}
    client, _ = _stub_client(payload)
    monkeypatch.setattr(llm, "_client", lambda api_key=None: client)

    llm.triage_findings(fs[:2])
    assert fs[0].verdict == "true_positive" and fs[0].confidence == 0.9
    assert fs[1].verdict == "false_positive"
    assert "상수" in fs[1].triage_reason


def test_findings_are_never_dropped(monkeypatch):
    """오탐 판정이 나도 결과를 지우지 않는다(사람이 최종 판단)."""
    fs = _findings()
    n = len(fs)
    payload = {"results": [{"index": i, "verdict": "false_positive", "confidence": 0.9,
                            "reason": "x"} for i in range(n)]}
    client, _ = _stub_client(payload)
    monkeypatch.setattr(llm, "_client", lambda api_key=None: client)

    out = llm.triage_findings(fs)
    assert len(out) == n


def test_unknown_verdict_falls_back_to_uncertain(monkeypatch):
    fs = _findings()[:1]
    client, _ = _stub_client({"results": [
        {"index": 0, "verdict": "definitely_bad", "confidence": 1.0, "reason": "x"}]})
    monkeypatch.setattr(llm, "_client", lambda api_key=None: client)
    llm.triage_findings(fs)
    assert fs[0].verdict == "uncertain"


def test_missing_result_is_uncertain(monkeypatch):
    fs = _findings()[:1]
    client, _ = _stub_client({"results": []})
    monkeypatch.setattr(llm, "_client", lambda api_key=None: client)
    llm.triage_findings(fs)
    assert fs[0].verdict == "uncertain"


def test_api_failure_does_not_crash(monkeypatch):
    fs = _findings()[:1]

    def boom(**kwargs):
        raise RuntimeError("network down")

    client = types.SimpleNamespace(messages=types.SimpleNamespace(create=boom))
    monkeypatch.setattr(llm, "_client", lambda api_key=None: client)

    llm.triage_findings(fs)  # 예외가 밖으로 새면 안 됨
    assert fs[0].verdict == "uncertain"
    assert "실패" in fs[0].triage_reason


def test_batching_splits_requests(monkeypatch):
    fs = _findings()
    payload = {"results": [{"index": i, "verdict": "uncertain", "confidence": 0.5,
                            "reason": "x"} for i in range(10)]}
    client, calls = _stub_client(payload)
    monkeypatch.setattr(llm, "_client", lambda api_key=None: client)

    llm.triage_findings(fs, batch_size=1)
    assert len(calls) == len(fs)          # 건당 한 번씩 호출
    assert calls[0]["model"] == "claude-opus-5"


def test_prompt_contains_flow_and_context(monkeypatch):
    fs = _findings()[:1]
    client, calls = _stub_client({"results": [
        {"index": 0, "verdict": "true_positive", "confidence": 0.9, "reason": "x"}]})
    monkeypatch.setattr(llm, "_client", lambda api_key=None: client)
    llm.triage_findings(fs)

    prompt = calls[0]["messages"][0]["content"]
    assert "데이터 흐름" in prompt
    assert "[source]" in prompt and "[sink]" in prompt
    assert calls[0]["system"].startswith("당신은")


def test_empty_findings_short_circuits(monkeypatch):
    def explode(api_key=None):
        raise AssertionError("빈 목록에서는 클라이언트를 만들지 않아야 한다")

    monkeypatch.setattr(llm, "_client", explode)
    assert llm.triage_findings([]) == []
