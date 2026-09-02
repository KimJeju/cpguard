"""Taint 스펙(YAML) 로더.

source/sink/sanitizer 를 코드가 아니라 데이터(YAML)로 정의한다.
규칙 추가는 cpguard/specs/*.yml 파일 하나 더 놓는 것으로 끝난다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

SPEC_DIR = Path(__file__).resolve().parent.parent / "specs"


@dataclass
class SourcePattern:
    """오염 진입점. member: req.query.* 같은 접근, call: process.argv 같은 호출/이름."""
    kind: str                                   # 'member' | 'name'
    object: str | None = None                   # member 의 루트 (예: req)
    property: list[str] = field(default_factory=list)   # member 의 2번째 세그먼트 후보
    name: list[str] = field(default_factory=list)       # name 패턴의 전체 경로 후보


@dataclass
class SinkPattern:
    """위험 지점. callee 경로 목록 + 검사할 인자 인덱스(None = 전체 인자)."""
    callee: list[str]
    arg: int | None = None


@dataclass
class Rule:
    id: str
    message: str
    severity: str
    cwe: str
    owasp: str
    languages: list[str]
    sources: list[SourcePattern]
    sinks: list[SinkPattern]
    sanitizers: list[str]


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def load_rule(path: Path) -> Rule:
    d = yaml.safe_load(path.read_text(encoding="utf-8"))
    sources = []
    for s in d.get("sources", []):
        sources.append(SourcePattern(
            kind=s.get("pattern", "member"),
            object=s.get("object"),
            property=_as_list(s.get("property")),
            name=_as_list(s.get("name")),
        ))
    sinks = [SinkPattern(callee=_as_list(s.get("callee")), arg=s.get("arg"))
             for s in d.get("sinks", [])]
    sanitizers: list[str] = []
    for s in d.get("sanitizers", []):
        sanitizers.extend(_as_list(s.get("callee")))
    return Rule(
        id=d["id"],
        message=d.get("message", d["id"]),
        severity=d.get("severity", "medium"),
        cwe=d.get("cwe", ""),
        owasp=d.get("owasp", ""),
        languages=_as_list(d.get("languages")) or ["javascript", "typescript"],
        sources=sources, sinks=sinks, sanitizers=sanitizers,
    )


def load_rules(directory: str | Path | None = None, language: str | None = None) -> list[Rule]:
    directory = Path(directory) if directory else SPEC_DIR
    rules = [load_rule(p) for p in sorted(directory.glob("*.yml"))]
    if language:
        rules = [r for r in rules if language in r.languages]
    return rules
