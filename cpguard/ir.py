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
    # a[i] 의 i. taint 는 인덱스를 구분하지 않지만(과대근사), 상수 전파는 "ABC"[1] 을
    # 접으려면 인덱스를 알아야 한다. 없으면 None.
    index: Optional[Node] = None


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


@dataclass
class Binary(Node):
    """이항 연산 left op right. children 은 [left, right] 와 같다.

    Opaque 로 접어도 taint 는 똑같이 전파되지만, 상수 전파(constfold)가 연산자를
    알아야 분기 조건을 접을 수 있어 별도 노드로 둔다."""
    op: str
    children: list[Node] = field(default_factory=list)
    # 결과가 반드시 수치인 연산인가. `$x + 0` 은 PHP 에서 산술이지만 JS·파이썬의 +
    # 는 문자열 결합이라 언어를 모르는 엔진은 판단할 수 없다 — 정규화기가 표시한다.
    numeric: bool = False


@dataclass
class Unary(Node):
    """단항 연산 op operand. children 은 [operand]."""
    op: str
    children: list[Node] = field(default_factory=list)


@dataclass
class Ternary(Node):
    """조건식 test ? then : orelse. children 은 [test, then, orelse].

    상수 전파가 test 를 접으면 children 을 선택된 가지 하나로 줄인다."""
    children: list[Node] = field(default_factory=list)


#: children 합집합으로 taint 를 전파하는 노드들(엔진이 한 덩어리로 다룬다)
FOLDED = (Opaque, Binary, Unary, Ternary)


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
    # 파라미터에 붙은 어노테이션 이름들(@RequestParam 등). 프레임워크가 요청 값을
    # 파라미터로 주입하는 형태를 source 로 잡는 데 쓴다. 없으면 빈 리스트.
    annotations: list[str] = field(default_factory=list)


@dataclass
class Function(Node):
    """함수/메서드/화살표함수. 익명이면 name=None."""
    name: Optional[str]
    params: list[Param] = field(default_factory=list)
    body: list[Node] = field(default_factory=list)
    # 함수에 붙은 데코레이터 경로(@app.route -> 'app.route'). 프레임워크가 이 함수를
    # 요청 핸들러로 등록한다는 표시이고, 그때는 리턴값이 곧 응답 본문이다.
    decorators: list[str] = field(default_factory=list)


@dataclass
class Module(Node):
    """파일 하나 = 하나의 Module. body는 최상위 문 리스트."""
    body: list[Node] = field(default_factory=list)
