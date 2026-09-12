"""Finding → 토큰 예산에 맞춘 표현.

에이전트에게 findings 를 통째로 붓지 않는다. 목록은 요약(흐름 단계 없음)만, 흐름은
요청한 finding 에만 붙인다. 안정적 id 를 여기서 부여해 이후 도구(evidence·probe·
validation)가 같은 finding 을 id 로 가리키게 한다.

순수 모듈 — MCP SDK 에 의존하지 않는다. 테스트도 SDK 없이 돈다.
"""
from __future__ import annotations

from cpguard.report.finding import Finding


def finding_id(f: Finding, used: set[str]) -> str:
    """`rule:file:line` 안정 id. 같은 자리에 여러 건이면 `#2`, `#3` 을 붙인다.

    안정적이어야 재스캔이 같은 id 를 내고(판정 승계), 결정적이어야 에이전트가 id 를
    다시 물어볼 수 있다. 파일은 basename 이 아니라 경로 그대로 쓴다 — 다른 디렉터리의
    동명 파일을 뭉개지 않게.
    """
    base = f"{f.rule_id}:{f.file}:{f.sink.loc.start_line}"
    fid = base
    n = 1
    while fid in used:
        n += 1
        fid = f"{base}#{n}"
    used.add(fid)
    return fid


def to_summary(f: Finding, fid: str) -> dict:
    """목록용 — 흐름 단계를 뺀 한 줄 요약. 토큰을 아낀다."""
    return {
        "id": fid,
        "rule": f.rule_id,
        "title": f.message,
        "severity": f.severity,
        "cwe": f.cwe,
        "file": f.file,
        "line": f.sink.loc.start_line,
        "uncertain": f.uncertain,
        "verdict": f.verdict,
    }


def _node(step) -> dict:
    return {
        "kind": step.kind,            # source | propagation | sink
        "file": step.loc.file,
        "line": step.loc.start_line,
        "code": step.code,
        "uncertain": step.uncertain,
    }


def to_evidence(f: Finding, fid: str) -> dict:
    """증거용 — source→sink 경로 전체. 요청한 finding 에만 붙인다.

    이게 '왜 취약이라 판단했는가'의 답이다. Finding.steps 가 파일을 넘는 경로를 이미
    들고 있으므로 성형만 한다.
    """
    return {
        "id": fid,
        "rule": f.rule_id,
        "cwe": f.cwe,
        "severity": f.severity,
        "source": _node(f.source),
        "sink": _node(f.sink),
        "path": [_node(s) for s in f.steps],
        "uncertain": f.uncertain,
    }
