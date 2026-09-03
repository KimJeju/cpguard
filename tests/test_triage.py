"""LLM 트리아지 재시도 로직 (일시 오류만 재시도)."""
from __future__ import annotations

from cpguard.triage import llm


def test_retry_retries_transient_then_succeeds(monkeypatch):
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    n = {"c": 0}

    def f():
        n["c"] += 1
        if n["c"] < 3:
            raise RuntimeError("503 UNAVAILABLE: high demand")
        return "ok"

    assert llm._retry(f, tries=3, delay=0) == "ok"
    assert n["c"] == 3


def test_retry_raises_non_transient_immediately():
    n = {"c": 0}

    def f():
        n["c"] += 1
        raise ValueError("401 authentication invalid")

    try:
        llm._retry(f, tries=3)
        assert False, "예외가 올라와야 한다"
    except ValueError:
        pass
    assert n["c"] == 1   # 인증오류는 재시도 안 함
