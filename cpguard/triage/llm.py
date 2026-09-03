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
import time
from pathlib import Path

from ..report.finding import Finding
from .providers import Provider, ProviderUnavailable, get_provider

# LLM 서버 일시 오류(특히 Gemini 503 high-demand)는 흔하다 — 짧게 재시도한다.
_TRANSIENT = ("503", "429", "unavailable", "overloaded", "high demand",
              "rate limit", "timeout", "temporarily")


def _is_transient(e: Exception) -> bool:
    return any(t in str(e).lower() for t in _TRANSIENT)


def _retry(fn, tries: int = 3, delay: float = 2.5):
    """일시 오류면 백오프 재시도, 그 외(인증·모델오류 등)는 즉시 올린다."""
    for i in range(tries):
        try:
            return fn()
        except Exception as e:
            if i == tries - 1 or not _is_transient(e):
                raise
            time.sleep(delay * (i + 1))

BATCH_SIZE = 5          # 한 요청에 담을 finding 수
CONTEXT_LINES = 6       # 각 단계 주변에 붙일 소스 줄 수

VERDICTS = ("true_positive", "false_positive", "uncertain")


# 프로바이더 계층의 예외를 그대로 노출한다(호출자는 이것만 잡으면 된다)
TriageUnavailable = ProviderUnavailable


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


def _triage_batch(provider: Provider, batch: list[tuple[int, Finding]],
                  cache) -> dict[int, dict]:
    prompt = (
        "다음 정적 분석 후보들을 검토하고 각각 판정하라.\n\n"
        + "\n\n".join(_describe(i, f, cache) for i, f in batch)
        + "\n\n각 후보의 index 를 그대로 사용해 결과를 반환하라."
    )
    data = provider.complete_json(SYSTEM, prompt)
    return {r["index"]: r for r in data.get("results", [])}


# ---------- AI 분석 패널: 현재 조사 맥락을 아는 질문 ----------

# 사용자가 매번 맥락을 입력하지 않도록, 프리셋 질문을 제공한다(1.md "AI Analysis").
PRESETS = {
    "explain": "이 탐지가 왜 보고되었는지, 어떤 취약점인지 초보 개발자도 이해할 수 있게 설명하라.",
    "why": "이 코드가 왜 취약한지 데이터 흐름의 각 단계를 짚어 설명하라. 정제가 없는 지점을 명시하라.",
    "trace": "source 에서 sink 까지의 데이터 흐름을 단계별로 추적해 표로 정리하라.",
    "exploit": "실제로 악용 가능한지 판단하라. 공격자가 제어 가능한 입력, 필요한 조건, 예시 페이로드(비파괴적)를 제시하라.",
    "validate": "이 흐름에 검증/정제 지점이 있는지 찾고, 있다면 충분한지 평가하라. 없다면 어디에 넣어야 하는지 제안하라.",
    "fix": "안전한 구현으로 고친 코드를 제시하라. Before/After 로 보여주고 왜 안전한지 한 줄로 설명하라.",
    "guidance": "이 이슈를 담당 개발자에게 전달할 조치 가이드를 작성하라: 위험, 영향, 수정 방법, 검증 방법 순서로.",
}

ASK_SYSTEM = """당신은 정적 분석 결과를 함께 조사하는 시니어 보안 엔지니어다.
주어진 탐지 맥락(규칙, 데이터 흐름, 주변 코드)만 근거로 답한다. 코드에 없는 것을 추측하지 않는다.
답변은 한국어, 마크다운. 코드 위치를 언급할 때는 반드시 파일명:줄번호 형식을 쓴다 — 사용자가 클릭해 이동한다.
간결하게: 핵심 먼저, 근거 다음, 조치 마지막."""


def _context_block(finding: dict, sources: dict[str, str], span: int = 8) -> str:
    """탐지 dict(웹 저장 형식) + 보관된 소스로 AI 에 줄 맥락을 만든다."""
    parts = [
        f"규칙: {finding.get('rule_id')} ({finding.get('cwe', '')} · {finding.get('owasp', '')})",
        f"위험도: {finding.get('severity')} / 규칙 신뢰도: {finding.get('precision', '')}",
        f"설명: {finding.get('message')}",
        f"위치: {finding.get('file')}:{finding.get('line')}",
        "데이터 흐름:",
    ]
    for s in finding.get("steps", []):
        parts.append(f"  [{s['kind']}] {s['file']}:{s['line']}  {s['code']}")
    if finding.get("verdict"):
        parts.append(f"LLM 1차 판정: {finding['verdict']} — {finding.get('triage_reason', '')}")
    if finding.get("audit"):
        parts.append(f"감사 상태: {finding['audit']}")

    shown: set[tuple[str, int]] = set()
    steps = finding.get("steps", [])
    for s in (steps[:1] + steps[-1:]) if steps else []:
        key = (s["file"], s["line"])
        if key in shown:
            continue
        shown.add(key)
        src = sources.get(s["file"])
        if not src:
            continue
        lines = src.splitlines()
        lo, hi = max(0, s["line"] - 1 - span), min(len(lines), s["line"] + span)
        parts.append(f"--- {s['file']} ({s['kind']} 부근) ---")
        parts.extend(f"{i + 1:5d}| {lines[i]}" for i in range(lo, hi))
    return "\n".join(parts)


def ask(finding: dict, sources: dict[str, str], preset: str = "explain",
        question: str | None = None, provider: str | None = None,
        model: str | None = None) -> tuple[str, str]:
    """현재 이슈에 대해 프리셋/자유 질문을 던진다. 반환: (답변, 프로바이더 이름)."""
    client = get_provider(provider, model=model)
    q = question.strip() if question else PRESETS.get(preset, PRESETS["explain"])
    prompt = _context_block(finding, sources) + "\n\n질문:\n" + q
    return _retry(lambda: client.complete_text(ASK_SYSTEM, prompt)), client.name


def triage_findings(findings: list[Finding], api_key: str | None = None,
                    batch_size: int = BATCH_SIZE, provider: str | None = None,
                    model: str | None = None) -> list[Finding]:
    """각 finding 에 verdict/confidence/reason 을 붙인다(원본 목록은 그대로 유지).

    provider: 'claude' | 'openai' | 'gemini'. 생략하면 키가 있는 것을 순서대로 시도한다.
    자격증명이 없거나 SDK 가 없으면 TriageUnavailable 을 던진다 — 호출자가 건너뛰면 된다.
    """
    if not findings:
        return findings

    client = get_provider(provider, api_key=api_key, model=model)
    cache: dict[str, list[str]] = {}

    # ---- 클러스터링 (대규모 최적화) ----
    # 같은 규칙·같은 sink 코드면 판정은 동일하다 → 대표 1건만 LLM 에 보내고 나머지는
    # 결과를 복사한다. 5만 건도 실제 호출 수는 '고유 클러스터 수'로 줄어든다.
    clusters: dict = {}
    for f in findings:
        clusters.setdefault(_cluster_key(f), []).append(f)
    reps = [members[0] for members in clusters.values()]
    items = list(enumerate(reps))

    for start in range(0, len(items), batch_size):
        batch = items[start:start + batch_size]
        try:
            results = _triage_batch(client, batch, cache)
        except Exception as e:
            # 한 배치 실패가 전체를 죽이지 않게 한다
            for i, f in batch:
                f.verdict = "uncertain"
                f.triage_reason = f"트리아지 실패({client.name}): {type(e).__name__}"
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
            f.triage_provider = client.name

    # 대표 판정을 같은 클러스터의 나머지에 전파
    for members in clusters.values():
        rep = members[0]
        for f in members[1:]:
            f.verdict = rep.verdict
            f.confidence = rep.confidence
            f.triage_reason = rep.triage_reason
            f.triage_provider = rep.triage_provider
    return findings


def _cluster_key(f: Finding):
    """같은 규칙 + 같은 sink 코드(공백 정규화) = 같은 판정으로 묶는다."""
    code = "".join((f.steps[-1].code if f.steps else "").split())
    return (f.rule_id, code)
