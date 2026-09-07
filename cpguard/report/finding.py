"""탐지 결과 모델 — source→sink 데이터 흐름 트레이스를 담는다."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..ir import Loc


@dataclass
class Step:
    """흐름의 한 단계. kind: 'source' | 'propagation' | 'sink'.

    uncertain 은 이 단계가 '분석 대상에 코드가 없는 함수'를 지났다는 표시다. 불확실성은
    흐름의 성질이라 단계가 들고 다녀야 한다 — 분석 문맥에 두면 finding 을 내지 않은
    앞선 계산의 흔적이 남거나(오표시), 변수에 담겼다가 나중에 쓰이는 흐름에서 사라진다.
    """
    kind: str
    loc: Loc
    code: str
    uncertain: bool = False


@dataclass
class Finding:
    rule_id: str
    message: str
    severity: str
    cwe: str
    owasp: str = ""
    steps: list[Step] = field(default_factory=list)

    # LLM 트리아지 결과 (triage 미실행 시 None)
    verdict: str | None = None          # true_positive | false_positive | uncertain
    confidence: float | None = None
    triage_reason: str | None = None
    triage_provider: str | None = None

    # 패턴 축 부가 정보 (taint 결과는 기본값)
    precision: str = "high"           # 규칙 자체의 신뢰도: high | medium | low
    fp_hint: bool = False             # 같은 줄에 오탐 신호(process.env 등)가 있었는가
    matched_value: str | None = None  # 탐지값(마스킹됨). 산출물이 유출원이 되지 않게
    category: str = "flow"            # flow | secret | pii | config | hygiene | infra
    # 분석 대상에 코드가 없는 함수를 거친 흐름. 그 함수 안에서 정제됐을 수 있으므로
    # 결과가 부정확할 수 있다 — 진단원이 오탐 우선 검토 순서를 잡는 데 쓴다.
    uncertain: bool = False

    @property
    def source(self) -> Step:
        return self.steps[0]

    @property
    def sink(self) -> Step:
        return self.steps[-1]

    @property
    def file(self) -> str:
        return self.sink.loc.file


#: 규칙 개명 이력. {옛 rule_id: 현재 rule_id}. 규칙 id 를 바꾸면 여기 한 줄 추가한다.
#: 지문이 rule_id 로 만들어지므로, 이 표가 없으면 개명하는 순간 과거 스캔의 판정 승계와
#: 신규/해결 비교가 통째로 끊긴다(전부 신규로 보인다).
RULE_ALIASES: dict[str, str] = {}


def canonical_rule_id(rule_id: str) -> str:
    """옛 rule_id 를 현재 이름으로. 연쇄 개명(a->b->c)도 따라가고 순환은 끊는다."""
    seen = set()
    while rule_id in RULE_ALIASES and rule_id not in seen:
        seen.add(rule_id)
        rule_id = RULE_ALIASES[rule_id]
    return rule_id


def fingerprint(rule_id: str, rel_file: str, sink_code: str) -> str:
    """스캔 간 같은 이슈를 잇는 지문. 줄 번호는 넣지 않는다 — 위에 코드가 추가되면 밀리므로.

    규칙 + 파일 + 위험 지점 코드(공백 제거) 로 만든다. 같은 파일에 같은 sink 가 두 번
    있으면 하나로 묶이는 한계가 있지만, 신규/해결 판정에는 이쪽이 더 안정적이다.
    """
    import hashlib
    code = "".join(sink_code.split())   # 포맷터가 띄어쓰기를 바꿔도 같은 이슈여야 한다
    return hashlib.sha1(
        f"{canonical_rule_id(rule_id)}|{rel_file}|{code}".encode("utf-8")).hexdigest()[:16]


def stored_fp(f: dict) -> str:
    """저장된 탐지 dict 의 지문. 그 규칙이 그 뒤 개명됐으면 현재 이름으로 다시 계산한다."""
    rid = f.get("rule_id") or ""
    if canonical_rule_id(rid) == rid:
        return f.get("fp") or ""
    steps = f.get("steps") or []
    if not steps:
        return f.get("fp") or ""     # 옛 스캔에 흐름이 없으면 재계산 불가 — 있는 값 그대로
    return fingerprint(rid, f.get("file") or "", steps[-1].get("code") or "")
