"""Taint 엔진 (Phase 1: 프로시저 내부).

IR 을 순회하며 source -> ... -> sink 데이터 흐름을 추적한다.

동작 요약
---------
  env : 오염된 접근경로(문자열) -> 여기까지의 트레이스(Step 리스트)
  - 할당문을 만나면 우변의 오염 여부를 계산해 좌변 경로를 env 에 넣거나(오염) 지운다(정제).
  - 호출식을 만나면 callee 경로가 sink 목록과 맞는지 보고, 해당 인자가 오염됐으면 finding.
  - sanitizer 호출을 통과한 값은 오염이 끊긴다.

의도적 한계 (Phase 2에서 해소)
  - CFG 미사용: 문을 순서대로 훑는다. 분기는 양쪽 다 같은 env 로 훑어 합집합처럼 동작.
  - 프로시저 간 전파 없음: 함수마다 새 env. 파라미터는 오염되지 않은 것으로 본다.
  - alias/points-to 없음, 필드 민감도는 경로 문자열 접두 매칭 수준.
"""
from __future__ import annotations

from .. import ir
from ..report.finding import Finding, Step
from .spec import Rule, SinkPattern

Trace = list[Step]


# ---------- 경로/스니펫 유틸 ----------

def path_of(node: ir.Node) -> str | None:
    """식별자/멤버 접근을 'req.query.id' 같은 점 경로 문자열로. 그 외는 None."""
    if isinstance(node, ir.Ident):
        return node.name
    if isinstance(node, ir.Member):
        base = path_of(node.obj)
        if base is None:
            return None
        # a[expr] 는 인덱스를 특정할 수 없어 베이스와 동일 취급(과대근사)
        return base if node.computed else f"{base}.{node.prop}"
    return None


def _snippet(loc: ir.Loc, src: bytes) -> str:
    try:
        return src[loc.start_byte:loc.end_byte].decode("utf-8", "replace").strip()
    except Exception:
        return ""


# ---------- 스펙 매칭 ----------

def _matches_source(path: str, rule: Rule) -> bool:
    segs = path.split(".")
    for s in rule.sources:
        if s.kind == "member":
            if s.object and segs[0] == s.object:
                if not s.property or (len(segs) > 1 and segs[1] in s.property):
                    return True
        elif s.kind == "name":
            for n in s.name:
                if path == n or path.startswith(n + "."):
                    return True
    return False


def _callee_matches(path: str, candidates: list[str]) -> bool:
    for c in candidates:
        if path == c or path.endswith("." + c):
            return True
    return False


def _sink_for(path: str, rule: Rule) -> SinkPattern | None:
    for s in rule.sinks:
        if _callee_matches(path, s.callee):
            return s
    return None


def _is_sanitizer(path: str, rule: Rule) -> bool:
    return _callee_matches(path, rule.sanitizers)


# ---------- 오염 판정 ----------

def _env_lookup(path: str, env: dict[str, Trace]) -> Trace | None:
    """정확 일치 또는 오염된 경로의 하위 경로(x 오염 -> x.y 도 오염)."""
    if path in env:
        return env[path]
    for tp, tr in env.items():
        if path.startswith(tp + "."):
            return tr
    return None


def _taint(node: ir.Node, env: dict[str, Trace], rule: Rule, src: bytes) -> Trace | None:
    """이 표현식이 오염됐으면 여기까지의 트레이스를, 아니면 None."""
    if node is None or isinstance(node, ir.Literal):
        return None

    if isinstance(node, (ir.Ident, ir.Member)):
        p = path_of(node)
        if p:
            if _matches_source(p, rule):
                return [Step("source", node.loc, _snippet(node.loc, src))]
            hit = _env_lookup(p, env)
            if hit is not None:
                return hit + [Step("propagation", node.loc, _snippet(node.loc, src))]
        if isinstance(node, ir.Member):
            return _taint(node.obj, env, rule, src)
        return None

    if isinstance(node, ir.Call):
        cp = path_of(node.callee)
        if cp and _is_sanitizer(cp, rule):
            return None  # 정제 통과 -> 오염 끊김
        for a in node.args:
            tr = _taint(a, env, rule, src)
            if tr:
                return tr + [Step("propagation", node.loc, _snippet(node.loc, src))]
        return _taint(node.callee, env, rule, src)

    if isinstance(node, ir.Assign):
        return _taint(node.value, env, rule, src)

    if isinstance(node, ir.Opaque):
        for c in node.children:
            tr = _taint(c, env, rule, src)
            if tr:
                return tr + [Step("propagation", node.loc, _snippet(node.loc, src))]
        return None

    return None


# ---------- sink 검사 ----------

def _iter_calls(node: ir.Node):
    """표현식 트리 안의 모든 Call 을 훑는다."""
    if node is None:
        return
    if isinstance(node, ir.Call):
        yield node
        for a in node.args:
            yield from _iter_calls(a)
        yield from _iter_calls(node.callee)
    elif isinstance(node, ir.Member):
        yield from _iter_calls(node.obj)
    elif isinstance(node, ir.Assign):
        yield from _iter_calls(node.value)
        yield from _iter_calls(node.target)
    elif isinstance(node, ir.Opaque):
        for c in node.children:
            yield from _iter_calls(c)


def _iter_functions(node: ir.Node):
    """표현식 안에 중첩된 함수를 찾는다.

    app.get('/x', function (req, res) {...}) 처럼 콜백으로 넘어가는 핸들러가 여기 해당.
    실제 웹앱은 취약 코드가 대부분 이런 콜백 안에 있으므로 반드시 들어가야 한다.
    """
    if node is None:
        return
    if isinstance(node, ir.Function):
        yield node
        return  # 내부는 _run_function 이 다시 훑는다
    if isinstance(node, ir.Call):
        for a in node.args:
            yield from _iter_functions(a)
        yield from _iter_functions(node.callee)
    elif isinstance(node, ir.Member):
        yield from _iter_functions(node.obj)
    elif isinstance(node, ir.Assign):
        yield from _iter_functions(node.value)
    elif isinstance(node, ir.Opaque):
        for c in node.children:
            yield from _iter_functions(c)


def _run_nested(node: ir.Node, rule: Rule, src: bytes, out: list[Finding]) -> None:
    for fn in _iter_functions(node):
        _run_function(fn, rule, src, out)


def _check_sinks(node: ir.Node, env: dict[str, Trace], rule: Rule, src: bytes,
                 out: list[Finding]) -> None:
    for call in _iter_calls(node):
        cp = path_of(call.callee)
        if not cp:
            continue
        sink = _sink_for(cp, rule)
        if sink is None:
            continue
        targets = ([call.args[sink.arg]] if sink.arg is not None and sink.arg < len(call.args)
                   else call.args)
        for arg in targets:
            tr = _taint(arg, env, rule, src)
            if tr:
                out.append(Finding(
                    rule_id=rule.id, message=rule.message,
                    severity=rule.severity, cwe=rule.cwe,
                    steps=tr + [Step("sink", call.loc, _snippet(call.loc, src))],
                ))
                break


# ---------- 문 실행 ----------

def _run(stmts: list[ir.Node], env: dict[str, Trace], rule: Rule, src: bytes,
         out: list[Finding]) -> None:
    for s in stmts:
        if isinstance(s, ir.Function):
            _run_function(s, rule, src, out)

        elif isinstance(s, ir.Assign):
            _check_sinks(s.value, env, rule, src, out)
            _run_nested(s.value, rule, src, out)
            tr = _taint(s.value, env, rule, src)
            p = path_of(s.target)
            if p:
                if tr:
                    env[p] = tr + [Step("propagation", s.loc, _snippet(s.loc, src))]
                else:
                    env.pop(p, None)

        elif isinstance(s, ir.Return):
            _check_sinks(s.value, env, rule, src, out)
            _run_nested(s.value, rule, src, out)

        elif isinstance(s, ir.If):
            _check_sinks(s.test, env, rule, src, out)
            _run(s.then, env, rule, src, out)
            _run(s.orelse, env, rule, src, out)

        elif isinstance(s, ir.Loop):
            _check_sinks(s.test, env, rule, src, out)
            _run(s.body, env, rule, src, out)

        else:
            _check_sinks(s, env, rule, src, out)
            _run_nested(s, rule, src, out)


def _run_function(fn: ir.Function, rule: Rule, src: bytes, out: list[Finding]) -> None:
    # Phase 1: 함수마다 새 env (파라미터 오염 전파는 Phase 2 프로시저간 요약에서)
    _run(fn.body, {}, rule, src, out)


# ---------- 진입점 ----------

def analyze(module: ir.Module, src: bytes, rules: list[Rule]) -> list[Finding]:
    """모듈 하나를 모든 규칙으로 분석해 finding 리스트 반환."""
    out: list[Finding] = []
    for rule in rules:
        _run(module.body, {}, rule, src, out)
    return out
