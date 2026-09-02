"""호출 그래프 — 함수 이름으로 정의를 찾을 수 있게 등록한다.

프로시저간 분석의 전제: 호출지점 f(x) 를 보고 f 의 정의를 찾아야 한다.
여기서는 이름 + 렉시컬 스코프 수준으로 해석한다(완전한 타입 추론은 하지 않음).
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import ir


@dataclass
class FuncInfo:
    """등록된 함수 하나. src 는 스니펫 추출용 원본 바이트."""
    name: str
    fn: ir.Function
    src: bytes
    file: str


def _walk_stmts(stmts: list[ir.Node]):
    """문 리스트를 재귀적으로 훑으며 모든 문을 낸다."""
    for s in stmts:
        yield s
        if isinstance(s, ir.Function):
            yield from _walk_stmts(s.body)
        elif isinstance(s, ir.If):
            yield from _walk_stmts(s.then)
            yield from _walk_stmts(s.orelse)
        elif isinstance(s, ir.Loop):
            yield from _walk_stmts(s.body)


def _named_functions(stmts: list[ir.Node]):
    """이름으로 부를 수 있는 함수를 찾는다.

      function foo(){}            -> 'foo'
      const foo = function(){}    -> 'foo'
      const foo = (x) => ...      -> 'foo'
    익명 콜백은 이름이 없어 등록하지 않는다(호출지점에서 이름으로 찾을 수 없으므로).
    """
    for s in _walk_stmts(stmts):
        if isinstance(s, ir.Function) and s.name:
            yield s.name, s
        elif isinstance(s, ir.Assign) and isinstance(s.value, ir.Function):
            if isinstance(s.target, ir.Ident):
                yield s.target.name, s.value


def collect_functions(modules: list[tuple[ir.Module, bytes, str]]) -> dict[str, FuncInfo]:
    """(module, src, file) 목록에서 이름 -> FuncInfo 레지스트리를 만든다.

    한계: 파일 간 이름이 겹치면 나중 것이 이긴다. import 해석은 하지 않는다.
    """
    registry: dict[str, FuncInfo] = {}
    for module, src, file in modules:
        for name, fn in _named_functions(module.body):
            registry[name] = FuncInfo(name=name, fn=fn, src=src, file=file)
    return registry
