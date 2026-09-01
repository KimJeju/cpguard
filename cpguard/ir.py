"""언어중립 중간표현(IR).

tree-sitter의 언어별 CST를 taint 분석에 필요한 최소 노드로 정규화한 결과물.
이 IR이 코어(CPG·taint)의 입력이며, 향후 다국어(Java 등) 확장 시 재사용되는 경계다.

설계 원칙:
  - taint에 필요한 노드만 둔다. 그 외 표현식/문은 Opaque로 접는다(자식 taint 합집합 전파).
  - 모든 노드는 원본 위치(Loc)를 보존한다 — 리포트의 dataflow 트레이스에 필요.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Loc:
    """소스 위치. line은 1-indexed, col은 0-indexed(tree-sitter point 기준)."""
    file: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    start_byte: int
    end_byte: int


@dataclass
class Node:
    loc: Loc


# ---------- 표현식 ----------

@dataclass
class Ident(Node):
    """식별자. 예: x, req, child_process"""
    name: str


@dataclass
class Literal(Node):
    """리터럴. value는 파싱 가능하면 파이썬 값, 아니면 None. raw는 원본 텍스트."""
    value: object
    raw: str


@dataclass
class Member(Node):
    """멤버 접근 obj.prop. 계산된 접근 a[expr]는 computed=True, prop=""."""
    obj: Node
    prop: str
    computed: bool = False


@dataclass
class Call(Node):
    """호출 callee(args...)."""
    callee: Node
    args: list[Node] = field(default_factory=list)


@dataclass
class Opaque(Node):
    """정밀 모델링하지 않는 노드. kind=원본 tree-sitter 타입, children=포함된 하위 노드.
    taint는 children의 합집합으로 전파한다."""
    kind: str
    children: list[Node] = field(default_factory=list)


# ---------- 문(statement) ----------

@dataclass
class Assign(Node):
    """할당/선언 초기화. operator: '=', '+=' 등, 선언 초기화는 'declare'."""
    target: Node
    value: Node
    operator: str = "="


@dataclass
class Return(Node):
    value: Optional[Node] = None


@dataclass
class If(Node):
    """조건문. then/orelse는 문 리스트. (CFG 구축은 M2)"""
    test: Node
    then: list[Node] = field(default_factory=list)
    orelse: list[Node] = field(default_factory=list)


@dataclass
class Loop(Node):
    """반복문(while/for 통합). test는 없을 수 있음. (CFG 구축은 M2)"""
    test: Optional[Node] = None
    body: list[Node] = field(default_factory=list)


@dataclass
class Param(Node):
    name: str


@dataclass
class Function(Node):
    """함수/메서드/화살표함수. 익명이면 name=None."""
    name: Optional[str]
    params: list[Param] = field(default_factory=list)
    body: list[Node] = field(default_factory=list)


@dataclass
class Module(Node):
    """파일 하나 = 하나의 Module. body는 최상위 문 리스트."""
    body: list[Node] = field(default_factory=list)
