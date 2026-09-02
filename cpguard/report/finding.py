"""탐지 결과 모델 — source→sink 데이터 흐름 트레이스를 담는다."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..ir import Loc


@dataclass
class Step:
    """흐름의 한 단계. kind: 'source' | 'propagation' | 'sink'."""
    kind: str
    loc: Loc
    code: str


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

    @property
    def source(self) -> Step:
        return self.steps[0]

    @property
    def sink(self) -> Step:
        return self.steps[-1]

    @property
    def file(self) -> str:
        return self.sink.loc.file
