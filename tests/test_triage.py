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


def _mk_finding(rule_id, sink_code):
    from cpguard.ir import Loc
    from cpguard.report.finding import Finding, Step
    loc = Loc(file="a.js", start_line=1, start_col=0, end_line=1, end_col=0, start_byte=0, end_byte=0)
    return Finding(rule_id=rule_id, message="m", severity="high", cwe="CWE-1",
                   steps=[Step("source", loc, "req.q"), Step("sink", loc, sink_code)])


def test_triage_clusters_reps_only_and_propagates(monkeypatch):
    """같은 규칙·sink 코드는 대표 1건만 LLM 에 보내고 결과를 전파한다."""
    from cpguard.triage import llm

    # 4건: 2건 동일(js.sqli / db.query(x)), 2건 서로 다름
    findings = [
        _mk_finding("js.sqli", "db.query(x)"),
        _mk_finding("js.sqli", "db.query(x)"),      # 위와 동일 클러스터
        _mk_finding("js.sqli", "db.query(y)"),      # 다른 sink 코드
        _mk_finding("js.xss", "res.send(x)"),       # 다른 규칙
    ]

    seen = {"reps": 0}

    class Dummy:
        name = "dummy"

    monkeypatch.setattr(llm, "get_provider", lambda *a, **k: Dummy())

    def fake_batch(client, batch, cache):
        seen["reps"] += len(batch)
        return {i: {"verdict": "false_positive", "confidence": 0.9, "reason": "R"} for i, _ in batch}

    monkeypatch.setattr(llm, "_triage_batch", fake_batch)

    llm.triage_findings(findings)

    assert seen["reps"] == 3          # 4건이지만 고유 클러스터는 3개 → LLM 3건만
    # 클러스터 멤버(2번째 finding)가 대표 판정을 물려받음
    assert findings[1].verdict == "false_positive"
    assert findings[1].triage_reason == "R"
    assert findings[1].triage_provider == "dummy"
