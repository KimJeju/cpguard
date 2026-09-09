"""호출 그래프 — 함수 이름으로 정의를 찾을 수 있게 등록한다.

프로시저간 분석의 전제: 호출지점 f(x) 를 보고 f 의 정의를 찾아야 한다.
여기서는 이름 + 렉시컬 스코프 수준으로 해석한다(완전한 타입 추론은 하지 않음).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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


def file_scoped(file: str, name: str) -> str:
    """같은 파일 안에서만 통하는 키. 전역 이름과 섞이지 않게 구분자를 넣는다."""
    return f"{file}::{name}"


def unique_name(name: str) -> str:
    """프로젝트 전체에서 정의가 하나뿐인 이름의 키. 실제 이름과 섞이지 않게 표식을 붙인다."""
    return f"{name}#unique"


#: 같은 이름의 정의를 몇 개까지 따로 들고 있을지. 이름이 흔할수록(자바 코퍼스의
#: doSomething 은 1802개) 요약을 다 계산하는 비용이 커지고, 그렇게 흔한 이름은 어차피
#: 서로 다를 가능성이 높다. 몇 개 안 되는 경우만 본다.
MAX_ALTS = 4


def alt_name(name: str, i: int) -> str:
    """같은 이름의 i 번째 정의 키. 요약을 각각 계산해 서로 같은지 보기 위한 것."""
    return f"{name}#alt{i}"


def _module_qualified(name: str, file: str, depth: int = 3) -> list[str]:
    """helpers/utils.py 의 f 를 'utils.f', 'helpers.utils.f' 로도 부를 수 있게 한다.

    파이썬은 `import helpers.utils` 뒤 `helpers.utils.f(x)` 로 부르는 것이 표준이다.
    이름 정확 일치로만 찾으면 이런 호출은 영영 정의를 못 만나 '분석 대상 밖 함수'로
    떨어지고, 흐름 전체에 불확실 표시가 찍힌다(실측: 파이썬 코퍼스 불확실의 43%).

    스캔 루트를 모르므로 파일 경로 뒤에서부터 몇 단계를 붙여 후보를 만든다.
    호출 경로의 접두가 정의 파일의 위치와 맞아야만 걸리므로, 'db.query' 가 아무
    파일의 지역 함수 'query' 로 잘못 해석되는 일은 생기지 않는다.
    """
    parts = list(Path(file).with_suffix("").parts)
    return [".".join(parts[-i:] + [name])
            for i in range(1, min(depth, len(parts)) + 1)]


def collect_functions(modules: list[tuple[ir.Module, bytes, str]]) -> dict[str, FuncInfo]:
    """(module, src, file) 목록에서 이름 -> FuncInfo 레지스트리를 만든다.

    한 함수를 맨 이름과 모듈 경로를 붙인 이름 모두로 등록한다(같은 FuncInfo 를 공유).

    한계: 파일 간 이름이 겹치면 나중 것이 이긴다. import 별칭은 해석하지 않는다.
    """
    registry: dict[str, FuncInfo] = {}
    seen: dict[str, int] = {}
    unique: dict[str, FuncInfo] = {}
    alts: dict[str, list[FuncInfo]] = {}
    for module, src, file in modules:
        for name, fn in _named_functions(module.body):
            info = FuncInfo(name=name, fn=fn, src=src, file=file)
            registry[name] = info
            registry[file_scoped(file, name)] = info
            for alias in _module_qualified(name, file):
                registry[alias] = info
            seen[name] = seen.get(name, 0) + 1
            unique[name] = info
            alts.setdefault(name, []).append(info)
    # 프로젝트 전체에서 정의가 하나뿐인 이름은 수신자를 몰라도 그 함수가 확실하다.
    # wrapped.get_form_parameter(x) 처럼 변수에 담긴 객체의 메서드를 부르는 형태는
    # 변수의 타입을 모르면 정의를 못 찾는데, 이름이 유일하면 그 위험이 없다.
    # 이름이 여럿이면 등록하지 않는다 — 그게 doSomething(자바 코퍼스에 1802개) 같은
    # 흔한 이름이 엉뚱한 파일로 이어지는 것을 막는 안전장치다.
    for name, n in seen.items():
        if n == 1:
            registry[unique_name(name)] = unique[name]
        elif n <= MAX_ALTS:
            # 정의가 여럿이어도 동작이 서로 같으면 수신자를 몰라도 답은 하나다.
            # 여기서는 후보만 등록하고, 같은지는 요약을 계산한 뒤에 본다.
            for i, info in enumerate(alts[name]):
                registry[alt_name(name, i)] = info
    return registry
