"""Taint 엔진 — 프로시저 내부 + 프로시저 간(함수 요약 기반).

동작 요약
---------
1) 프로시저 내부
   env : 오염된 접근경로(문자열) -> 여기까지의 트레이스(Step 리스트)
   - 할당문: 우변의 오염 여부를 계산해 좌변 경로를 env 에 넣거나(오염) 지운다(정제).
   - 호출식: callee 가 sink 목록과 맞고 해당 인자가 오염됐으면 finding.
   - sanitizer 를 통과한 값은 오염이 끊긴다.

2) 프로시저 간 (summary.py 참조)
   함수마다 "param i 가 오염되면 리턴이 오염되는가 / 위험 지점에 닿는가"를 미리 계산해 둔다.
   호출지점에서는 요약만 적용하므로 함수 본문을 반복 분석하지 않는다.
   요약은 고정점에 이를 때까지 반복 계산하여 재귀·상호재귀를 처리한다.

의도적 한계
   - CFG 미사용: 문을 순서대로 훑는다(경로 민감도 없음).
   - alias/points-to 없음, 필드 민감도는 경로 문자열 접두 매칭 수준.
   - 호출 해석은 이름 정확 일치만(import 별칭·동적 디스패치 미해석).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .. import ir
from ..cpg.callgraph import FuncInfo, collect_functions
from ..report.finding import Finding, Step
from .spec import Rule, SinkPattern
from .summary import Summary

Trace = list[Step]

# 요약 고정점 반복 상한 (재귀 함수에서 무한 반복 방지)
MAX_SUMMARY_ITERATIONS = 5


@dataclass
class Ctx:
    """분석 한 번의 문맥. 규칙·원본·결과 수집기와 요약 테이블을 함께 들고 다닌다."""
    rule: Rule
    src: bytes
    out: list[Finding]
    summaries: dict[str, Summary] = field(default_factory=dict)
    return_traces: list[Trace] = field(default_factory=list)  # 요약 계산용: 오염된 리턴들


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


def _user_function(path: str | None, ctx: Ctx) -> Summary | None:
    """호출 대상이 우리가 요약을 가진 사용자 정의 함수인지.

    이름 정확 일치만 인정한다. 'db.query' 같은 점 경로가 지역 함수 'query' 로
    잘못 해석되는 것을 막기 위함이다.
    """
    if not path:
        return None
    return ctx.summaries.get(path)


# ---------- 오염 판정 ----------

def _env_lookup(path: str, env: dict[str, Trace]) -> Trace | None:
    """정확 일치 또는 오염된 경로의 하위 경로(x 오염 -> x.y 도 오염)."""
    if path in env:
        return env[path]
    for tp, tr in env.items():
        if path.startswith(tp + "."):
            return tr
    return None


def _taint(node: ir.Node, env: dict[str, Trace], ctx: Ctx) -> Trace | None:
    """이 표현식이 오염됐으면 여기까지의 트레이스를, 아니면 None."""
    if node is None or isinstance(node, ir.Literal):
        return None

    if isinstance(node, (ir.Ident, ir.Member)):
        p = path_of(node)
        if p:
            if _matches_source(p, ctx.rule):
                return [Step("source", node.loc, _snippet(node.loc, ctx.src))]
            hit = _env_lookup(p, env)
            if hit is not None:
                return hit + [Step("propagation", node.loc, _snippet(node.loc, ctx.src))]
        if isinstance(node, ir.Member):
            return _taint(node.obj, env, ctx)
        return None

    if isinstance(node, ir.Call):
        cp = path_of(node.callee)
        if cp and _is_sanitizer(cp, ctx.rule):
            return None  # 정제 통과 -> 오염 끊김

        step = Step("propagation", node.loc, _snippet(node.loc, ctx.src))
        summ = _user_function(cp, ctx)

        if summ is not None:
            # 함수가 자기 안에서 오염을 만들어 리턴하면, 인자와 무관하게 결과가 오염이다.
            if summ.returns_source:
                return summ.source_trace + [step]
            # 그 외에는 요약에 따라 "인자 오염 -> 리턴 오염" 여부를 정확히 판단한다.
            for i, a in enumerate(node.args):
                tr = _taint(a, env, ctx)
                if tr and i in summ.returns_tainted:
                    return tr + [step]
            return None  # 인자가 오염돼도 리턴으로 흐르지 않으면 오염 아님(정밀도)

        # 알 수 없는 함수(라이브러리 등): 인자 오염이 결과로 흐른다고 과대근사
        for a in node.args:
            tr = _taint(a, env, ctx)
            if tr:
                return tr + [step]
        return _taint(node.callee, env, ctx)

    if isinstance(node, ir.Assign):
        return _taint(node.value, env, ctx)

    if isinstance(node, ir.Opaque):
        for c in node.children:
            tr = _taint(c, env, ctx)
            if tr:
                return tr + [Step("propagation", node.loc, _snippet(node.loc, ctx.src))]
        return None

    return None


# ---------- 중첩 함수 / sink 검사 ----------

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


def _emit(ctx: Ctx, steps: list[Step]) -> None:
    ctx.out.append(Finding(
        rule_id=ctx.rule.id, message=ctx.rule.message,
        severity=ctx.rule.severity, cwe=ctx.rule.cwe, steps=steps,
    ))


def _check_sinks(node: ir.Node, env: dict[str, Trace], ctx: Ctx) -> None:
    for call in _iter_calls(node):
        cp = path_of(call.callee)
        if not cp:
            continue

        # (a) 직접 sink 호출
        sink = _sink_for(cp, ctx.rule)
        if sink is not None:
            targets = ([call.args[sink.arg]] if sink.arg is not None and sink.arg < len(call.args)
                       else call.args)
            for arg in targets:
                tr = _taint(arg, env, ctx)
                if tr:
                    _emit(ctx, tr + [Step("sink", call.loc, _snippet(call.loc, ctx.src))])
                    break

        # (b) 프로시저 간: 요약이 "이 파라미터는 내부에서 sink 에 닿는다"고 말하는 경우
        summ = _user_function(cp, ctx)
        if summ is not None and summ.sink_paths:
            for i, arg in enumerate(call.args):
                if i not in summ.sink_paths:
                    continue
                tr = _taint(arg, env, ctx)
                if not tr:
                    continue
                enter = Step("call", call.loc, _snippet(call.loc, ctx.src))
                for inner in summ.sink_paths[i]:
                    _emit(ctx, tr + [enter] + inner)
                break


def _run_nested(node: ir.Node, ctx: Ctx) -> None:
    for fn in _iter_functions(node):
        _run_function(fn, ctx)


# ---------- 문 실행 ----------

def _run(stmts: list[ir.Node], env: dict[str, Trace], ctx: Ctx) -> None:
    for s in stmts:
        if isinstance(s, ir.Function):
            _run_function(s, ctx)

        elif isinstance(s, ir.Assign):
            _check_sinks(s.value, env, ctx)
            _run_nested(s.value, ctx)
            tr = _taint(s.value, env, ctx)
            p = path_of(s.target)
            if p:
                if tr:
                    env[p] = tr + [Step("propagation", s.loc, _snippet(s.loc, ctx.src))]
                else:
                    env.pop(p, None)

        elif isinstance(s, ir.Return):
            _check_sinks(s.value, env, ctx)
            _run_nested(s.value, ctx)
            rt = _taint(s.value, env, ctx)
            if rt:
                ctx.return_traces.append(rt)  # 요약 계산용: 리턴값이 오염됨

        elif isinstance(s, ir.If):
            _check_sinks(s.test, env, ctx)
            _run(s.then, env, ctx)
            _run(s.orelse, env, ctx)

        elif isinstance(s, ir.Loop):
            _check_sinks(s.test, env, ctx)
            _run(s.body, env, ctx)

        else:
            _check_sinks(s, env, ctx)
            _run_nested(s, ctx)


def _run_function(fn: ir.Function, ctx: Ctx) -> None:
    """함수 본문을 빈 env 로 분석한다(파라미터 오염은 요약이 담당)."""
    _run(fn.body, {}, ctx)


# ---------- 요약 계산 ----------

def _summarize(info: FuncInfo, rule: Rule, summaries: dict[str, Summary]) -> Summary:
    """함수 하나의 요약을 만든다.

    먼저 빈 env 로 돌려 "인자와 무관하게 오염을 만들어 리턴하는지"를 본다.
    그다음 파라미터를 하나씩 오염시켜 돌리되, 그 파라미터에서 비롯된 흐름만 채택한다
    (steps[0] 이 param 인 것). 내부 소스에서 온 흐름은 함수 자체를 분석할 때 이미 보고되므로
    여기서 다시 세면 중복이 된다.
    """
    result = Summary()

    # (1) 인자 무관 오염 리턴
    base = Ctx(rule=rule, src=info.src, out=[], summaries=summaries)
    _run(info.fn.body, {}, base)
    if base.return_traces:
        result.source_trace = base.return_traces[0]

    # (2) 파라미터별 전파
    for i, p in enumerate(info.fn.params):
        collected: list[Finding] = []
        ctx = Ctx(rule=rule, src=info.src, out=collected, summaries=summaries)
        env = {p.name: [Step("param", p.loc, f"{info.name}({p.name})")]}
        _run(info.fn.body, env, ctx)

        if any(tr and tr[0].kind == "param" for tr in ctx.return_traces):
            result.returns_tainted.add(i)

        paths = [f.steps for f in collected if f.steps and f.steps[0].kind == "param"]
        if paths:
            result.sink_paths[i] = paths

    return result


def compute_summaries(registry: dict[str, FuncInfo], rule: Rule) -> dict[str, Summary]:
    """레지스트리의 모든 함수 요약을 고정점까지 반복 계산한다.

    호출 순서를 위상 정렬하는 대신 반복한다 — 요약은 단조 증가하므로 몇 번이면 수렴하고,
    재귀·상호재귀도 별도 처리 없이 자연히 다뤄진다(반복 상한으로 종료 보장).
    """
    summaries: dict[str, Summary] = {name: Summary() for name in registry}
    for _ in range(MAX_SUMMARY_ITERATIONS):
        changed = False
        for name, info in registry.items():
            new = _summarize(info, rule, summaries)
            if new != summaries[name]:
                summaries[name] = new
                changed = True
        if not changed:
            break
    return summaries


# ---------- 진입점 ----------

def analyze(module: ir.Module, src: bytes, rules: list[Rule],
            registry: dict[str, FuncInfo] | None = None,
            summaries_by_rule: dict[str, dict[str, Summary]] | None = None) -> list[Finding]:
    """모듈 하나를 모든 규칙으로 분석해 finding 리스트 반환.

    registry / summaries_by_rule 를 주면 파일 경계를 넘는 분석이 된다(scanner 가 전달).
    주지 않으면 이 모듈 안에서만 프로시저간 분석을 수행한다.
    """
    if registry is None:
        registry = collect_functions([(module, src, module.loc.file)])

    out: list[Finding] = []
    for rule in rules:
        summaries = (summaries_by_rule or {}).get(rule.id)
        if summaries is None:
            summaries = compute_summaries(registry, rule)
        _run(module.body, {}, Ctx(rule=rule, src=src, out=out, summaries=summaries))
    return out
