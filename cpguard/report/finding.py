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
    steps: list[Step] = field(default_factory=list)

    @property
    def source(self) -> Step:
        return self.steps[0]

    @property
    def sink(self) -> Step:
        return self.steps[-1]

    @property
    def file(self) -> str:
        return self.sink.loc.file
