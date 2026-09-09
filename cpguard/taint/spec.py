"""Taint 스펙(YAML) 로더.

source/sink/sanitizer 를 코드가 아니라 데이터(YAML)로 정의한다.
규칙 추가는 cpguard/specs/*.yml 파일 하나 더 놓는 것으로 끝난다.

사용자 조정도 같은 YAML 로 한다. USER_SPEC_DIR 에 같은 ``id`` 의 yml 을 두면 동봉
규칙 위에 겹쳐진다 — 금지 함수 목록에 sink 를 더하거나, 사내 검증 함수를 sanitizer 로
인정하거나, severity 를 내리는 일이 소스 수정 없이 된다. 별도의 옵션 스키마를 두지
않는 이유는 규칙 자체가 이미 설정 파일이기 때문이다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SPEC_DIR = Path(__file__).resolve().parent.parent / "specs"


def user_spec_dir() -> Path:
    """사용자 규칙 오버레이 위치. CPGUARD_SPECS > $CPGUARD_HOME/specs > ~/.cpguard/specs."""
    if env := os.environ.get("CPGUARD_SPECS"):
        return Path(env)
    return Path(os.environ.get("CPGUARD_HOME", Path.home() / ".cpguard")) / "specs"


@dataclass
class SourcePattern:
    """오염 진입점.

    member: req.query.* 같은 접근, name: process.argv 같은 호출/이름,
    annotation: @RequestParam 처럼 프레임워크가 요청 값을 파라미터에 주입하는 형태.
    """
    kind: str                                   # 'member' | 'name' | 'annotation'
    object: str | None = None                   # member 의 루트 (예: req)
    property: list[str] = field(default_factory=list)   # member 의 2번째 세그먼트 후보
    name: list[str] = field(default_factory=list)       # name/annotation 패턴의 이름 후보


@dataclass
class SinkPattern:
    """위험 지점.

    kind='call'   : callee 경로 목록 + 검사할 인자 인덱스(None = 전체 인자).
    kind='return' : 이 데코레이터가 붙은 함수의 리턴값 자체가 sink. 웹 프레임워크가
                    핸들러의 리턴을 그대로 응답 본문으로 내보내는 형태(@app.route 등)는
                    호출 형태의 sink 가 없어서 이 종류가 없으면 통째로 미탐이 된다.
    """
    callee: list[str] = field(default_factory=list)
    arg: int | None = None
    kind: str = "call"
    decorator: list[str] = field(default_factory=list)


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
    # 조건문에서 이 표시가 오염 경로에 걸리면 "검증했다"로 본다. 거부하고 돌아가는
    # 코드(`if '../' in name: return`)는 정제 함수를 부르지 않으므로 sanitizers 로는
    # 잡히지 않는다. 무엇을 검증으로 인정할지는 규칙마다 다르므로 규칙이 선언한다.
    validators: list[str] = field(default_factory=list)


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def load_rule(path: Path) -> Rule:
    return rule_from_dict(yaml.safe_load(path.read_text(encoding="utf-8")))


def rule_from_dict(d: dict) -> Rule:
    sources = []
    for s in d.get("sources", []):
        sources.append(SourcePattern(
            kind=s.get("pattern", "member"),
            object=s.get("object"),
            property=_as_list(s.get("property")),
            name=_as_list(s.get("name")),
        ))
    sinks = [SinkPattern(callee=_as_list(s.get("callee")), arg=s.get("arg"),
                         kind=s.get("pattern", "call"),
                         decorator=_as_list(s.get("decorator")))
             for s in d.get("sinks", [])]
    sanitizers: list[str] = []
    for s in d.get("sanitizers", []):
        sanitizers.extend(_as_list(s.get("callee")))
    validators: list[str] = []
    for v in d.get("validators", []):
        validators.extend(_as_list(v.get("token")) if isinstance(v, dict) else [v])
    return Rule(
        id=d["id"],
        message=d.get("message", d["id"]),
        severity=d.get("severity", "medium"),
        cwe=d.get("cwe", ""),
        owasp=d.get("owasp", ""),
        languages=_as_list(d.get("languages")) or ["javascript", "typescript"],
        sources=sources, sinks=sinks, sanitizers=sanitizers, validators=validators,
    )


#: 리스트로 이어붙이는 키. 나머지 스칼라 키는 사용자 값이 덮어쓴다.
_LIST_KEYS = ("sources", "sinks", "sanitizers", "validators", "languages", "legacy_ids")


def merge_spec(base: dict, over: dict) -> dict:
    """동봉 규칙 위에 사용자 규칙을 겹친다.

    리스트 키는 이어붙인다(금지 함수·sink 추가가 주 용도). 스칼라 키는 덮어쓴다
    (severity 하향 등). 동봉 목록을 통째로 버리려면 사용자 yml 에 ``replace: true``.
    """
    if over.get("replace"):
        return {k: v for k, v in over.items() if k != "replace"}
    out = dict(base)
    for k, v in over.items():
        if k in _LIST_KEYS and isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + [x for x in v if x not in out[k]]
        else:
            out[k] = v
    return out


def _read_specs(directory: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(directory.glob("*.yml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if d.get("id"):
            out[d["id"]] = d
    return out


def load_rules(directory: str | Path | None = None, language: str | None = None,
               user_dir: str | Path | None = None) -> list[Rule]:
    """동봉 규칙 + 사용자 오버레이. user_dir=False 로 오버레이를 끌 수 있다."""
    specs = _read_specs(Path(directory) if directory else SPEC_DIR)

    if user_dir is not False:
        udir = Path(user_dir) if user_dir else user_spec_dir()
        if udir.is_dir():
            for rid, d in _read_specs(udir).items():
                specs[rid] = merge_spec(specs[rid], d) if rid in specs else d

    # 개명 이력을 지문 승계 표에 실어준다 — 규칙 이름을 바꿔도 과거 판정이 이어지도록.
    from cpguard.report.finding import RULE_ALIASES
    for rid, d in specs.items():
        for old_id in _as_list(d.get("legacy_ids")):
            RULE_ALIASES[old_id] = rid

    rules = [rule_from_dict(d) for _, d in sorted(specs.items())]
    if language:
        rules = [r for r in rules if language in r.languages]
    return rules
