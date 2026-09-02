"""LLM 트리아지 — 엔진이 뱉은 후보를 재검증해 오탐을 걸러낸다.

정적 분석은 건전성을 위해 과대근사한다(분기 조건을 안 보고, 모르는 함수는 오염을 통과시킨다).
그 대가가 오탐이다. 이 레이어는 각 후보의 데이터 흐름과 주변 코드를 LLM 에 보여주고
"이게 실제로 악용 가능한가"를 판정시켜 오탐을 걸러낸다.

설계 원칙
  - 엔진 결과를 지우지 않는다. 판정(verdict)과 근거를 덧붙이기만 한다.
    최종 취사선택은 사람이 한다 — 도구가 조용히 취약점을 숨기면 더 위험하다.
  - API 키가 없으면 조용히 건너뛴다. 트리아지는 부가 기능이지 필수 경로가 아니다.
  - 한 번에 여러 건을 묶어 보낸다(호출 수·비용 절감).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..report.finding import Finding

MODEL = "claude-opus-5"
BATCH_SIZE = 5          # 한 요청에 담을 finding 수
CONTEXT_LINES = 6       # 각 단계 주변에 붙일 소스 줄 수

VERDICTS = ("true_positive", "false_positive", "uncertain")


class TriageUnavailable(RuntimeError):
    """SDK 미설치 또는 자격증명 없음."""


SYSTEM = """당신은 정적 분석 결과를 검토하는 보안 전문가다.

정적 분석기가 source(사용자 입력) -> sink(위험 함수) 데이터 흐름을 찾아 보고했다.
이 분석기는 건전성을 위해 과대근사한다. 구체적으로:
  - 분기 조건의 참거짓을 해석하지 않는다(경로 민감도 없음).
  - 모르는 함수는 인자의 오염이 반환값으로 흐른다고 가정한다.
  - 별칭 분석이 없다.

따라서 실제로는 악용 불가능한 후보가 섞여 있다. 각 후보에 대해 판정하라.

  true_positive  : 실제로 공격자가 제어 가능한 값이 위험 지점에 도달한다.
  false_positive : 도달 불가능하거나, 이미 안전하게 처리되었거나, 흐름이 잘못 추론되었다.
  uncertain      : 주어진 코드만으로는 판단할 수 없다.

판단 기준:
  - 정제(escape/검증/화이트리스트)가 실제로 적용되었는가.
  - 값이 상수이거나 공격자가 제어할 수 없는 출처인가.
  - 해당 sink 가 그 인자 위치에서 실제로 위험한가.
  - 흐름이 코드상 실제로 이어지는가(분석기의 잘못된 연결이 아닌가).

확신이 없으면 uncertain 을 쓰라. 취약점을 놓치는 것이 오탐보다 위험하므로,
애매하면 false_positive 대신 uncertain 을 택한다.
reason 은 한국어 한두 문장으로 근거를 명확히 쓴다."""

_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "verdict": {"type": "string", "enum": list(VERDICTS)},
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


def _source_lines(path: str, cache: dict[str, list[str]]) -> list[str]:
    if path not in cache:
        try:
            cache[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[path] = []
    return cache[path]


def _context(path: str, line: int, cache: dict[str, list[str]]) -> str:
    lines = _source_lines(path, cache)
    if not lines:
        return ""
    lo = max(0, line - 1 - CONTEXT_LINES // 2)
    hi = min(len(lines), line + CONTEXT_LINES // 2)
    return "\n".join(f"{i + 1:5d}| {lines[i]}" for i in range(lo, hi))


def _describe(idx: int, f: Finding, cache: dict[str, list[str]]) -> str:
    parts = [
        f"### 후보 {idx}",
        f"규칙: {f.rule_id} ({f.cwe}) / 위험도: {f.severity}",
        f"설명: {f.message}",
        "데이터 흐름:",
    ]
    for s in f.steps:
        parts.append(f"  [{s.kind}] {Path(s.loc.file).name}:{s.loc.start_line}  {s.code}")
    parts.append("주변 코드:")
    seen: set[tuple[str, int]] = set()
    for s in (f.steps[0], f.steps[-1]):
        key = (s.loc.file, s.loc.start_line)
        if key in seen:
            continue
        seen.add(key)
        ctx = _context(s.loc.file, s.loc.start_line, cache)
        if ctx:
            parts.append(f"--- {Path(s.loc.file).name} ({s.kind} 부근) ---")
            parts.append(ctx)
    return "\n".join(parts)


def _client(api_key: str | None):
    try:
        import anthropic
    except ImportError as e:
        raise TriageUnavailable(
            "anthropic SDK 가 없습니다. 'pip install anthropic' 후 다시 시도하세요."
        ) from e

    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return anthropic.Anthropic(api_key=key)
    # 키가 없어도 ant auth login 프로필 등 다른 자격증명이 있을 수 있다.
    try:
        return anthropic.Anthropic()
    except Exception as e:
        raise TriageUnavailable(f"Anthropic 자격증명을 찾을 수 없습니다: {e}") from e


def _triage_batch(client, batch: list[tuple[int, Finding]], cache) -> dict[int, dict]:
    prompt = (
        "다음 정적 분석 후보들을 검토하고 각각 판정하라.\n\n"
        + "\n\n".join(_describe(i, f, cache) for i, f in batch)
        + "\n\n각 후보의 index 를 그대로 사용해 결과를 반환하라."
    )
    resp = client.messages.create(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM,
        thinking={"type": "adaptive"},
        output_config={"format": {"type": "json_schema", "schema": _SCHEMA}},
        messages=[{"role": "user", "content": prompt}],
    )
    text = next((b.text for b in resp.content if b.type == "text"), "")
    data = json.loads(text)
    return {r["index"]: r for r in data.get("results", [])}


def triage_findings(findings: list[Finding], api_key: str | None = None,
                    batch_size: int = BATCH_SIZE) -> list[Finding]:
    """각 finding 에 verdict/confidence/reason 을 붙인다(원본 목록은 그대로 유지).

    자격증명이 없거나 SDK 가 없으면 TriageUnavailable 을 던진다 — 호출자가 건너뛰면 된다.
    """
    if not findings:
        return findings

    client = _client(api_key)
    cache: dict[str, list[str]] = {}
    items = list(enumerate(findings))

    for start in range(0, len(items), batch_size):
        batch = items[start:start + batch_size]
        try:
            results = _triage_batch(client, batch, cache)
        except Exception as e:
            # 한 배치 실패가 전체를 죽이지 않게 한다
            for i, f in batch:
                f.verdict = "uncertain"
                f.triage_reason = f"트리아지 실패: {type(e).__name__}"
            continue
        for i, f in batch:
            r = results.get(i)
            if not r:
                f.verdict = "uncertain"
                f.triage_reason = "판정 결과 누락"
                continue
            f.verdict = r["verdict"] if r["verdict"] in VERDICTS else "uncertain"
            f.confidence = float(r.get("confidence", 0.0))
            f.triage_reason = r.get("reason", "")

    return findings
