"""함수 오염 요약(summary).

프로시저간 분석의 핵심 자료구조. 함수 하나에 대해 다음 두 질문의 답을 담는다.

  1) param i 가 오염되면 → 리턴값도 오염되는가?      (returns_tainted)
  2) param i 가 오염되면 → 함수 안의 위험 지점에 닿는가? (sink_paths, 내부 경로 포함)
  3) 인자와 무관하게 항상 오염된 값을 리턴하는가?      (returns_source)
     예: function readInput(req){ return req.query.cmd; } 는 자기 안에서 오염을 만든다.

호출지점에서는 이 요약만 보면 되므로, 함수 본문을 매번 다시 분석하지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..report.finding import Step


@dataclass
class Summary:
    # 리턴값을 오염시키는 파라미터 인덱스 집합
    returns_tainted: set[int] = field(default_factory=set)
    # 파라미터 인덱스 -> 그 파라미터에서 시작해 위험 지점까지 가는 함수 내부 경로들
    sink_paths: dict[int, list[list[Step]]] = field(default_factory=dict)
    # 인자와 무관하게 함수 내부에서 오염을 만들어 리턴하는 경우, 그 내부 경로
    source_trace: list[Step] = field(default_factory=list)

    @property
    def returns_source(self) -> bool:
        return bool(self.source_trace)

    def is_empty(self) -> bool:
        return not self.returns_tainted and not self.sink_paths and not self.source_trace
