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

3) 흐름 민감도
   자바스크립트는 구조적 제어흐름이라 IR 트리 자체가 CFG 를 품고 있다. 별도의 기본블록
   그래프를 세우는 대신, 분기에서 양쪽을 각각 분석해 합치고(merge) 반복문은 오염이 더
   늘지 않을 때까지 돌려(고정점) 같은 효과를 낸다.

의도적 한계
   - 경로 민감도 없음: 분기 조건의 참거짓을 해석하지 않고 양쪽을 모두 가능하다고 본다.
   - alias/points-to 없음, 필드 민감도는 경로 문자열 접두 매칭 수준.
   - 호출 해석은 이름 정확 일치만(import 별칭·동적 디스패치 미해석).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .. import ir
from ..cpg.callgraph import FuncInfo, collect_functions, file_scoped, unique_name
from ..report.finding import Finding, Step
from .spec import Rule, SinkPattern
from .summary import BLOCK, PROPAGATE, LibraryModel, Summary, load_library_model

Trace = list[Step]

_LIBRARY: LibraryModel | None = None


def _library() -> LibraryModel:
    """라이브러리 요약 모델(프로세스당 1회 로드)."""
    global _LIBRARY
    if _LIBRARY is None:
        _LIBRARY = load_library_model()
    return _LIBRARY


# 요약 고정점 반복 상한 (재귀 함수에서 무한 반복 방지)
MAX_SUMMARY_ITERATIONS = 5
# 반복문 고정점 상한 (오염이 회전을 거쳐 전파되는 경우를 잡되 종료를 보장)
MAX_LOOP_ITERATIONS = 4


@dataclass
class Ctx:
    """분석 한 번의 문맥. 규칙·원본·결과 수집기와 요약 테이블을 함께 들고 다닌다."""
    rule: Rule
    src: bytes
    out: list[Finding]
    file: str = ""                                    # 같은 파일 안 정의를 찾을 때 쓴다
    summaries: dict[str, Summary] = field(default_factory=dict)
    return_traces: list[Trace] = field(default_factory=list)  # 요약 계산용: 오염된 리턴들
    # 지금 분석 중인 함수가 요청 핸들러라서 리턴값이 곧 응답 본문인지(= 리턴이 sink).
    return_is_sink: bool = False


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
    if isinstance(node, ir.Call):
        # Runtime.getRuntime().exec(x) / foo().bar() — 호출 결과를 리시버로 쓰는 체인.
        # 호출 대상 경로를 베이스로 이어야 'exec' 같은 sink 접미가 매칭된다.
        return path_of(node.callee)
    return None


def _snippet(loc: ir.Loc, src: bytes) -> str:
    try:
        return src[loc.start_byte:loc.end_byte].decode("utf-8", "replace").strip()
    except Exception:
        return ""


# ---------- 스펙 매칭 ----------

#: 인스턴스에 담아 둔 요청 객체를 가리키는 접두. self.request.form 처럼 한 겹 감싼
#: 형태는 파이썬·자바 웹 코드에서 표준에 가깝다 — 이 한 겹을 벗겨 소스를 본다.
_SELF_PREFIX = ("self", "this", "cls")


def _matches_source(path: str, rule: Rule) -> bool:
    segs = path.split(".")
    if len(segs) > 1 and segs[0] in _SELF_PREFIX:
        segs = segs[1:]
        path = ".".join(segs)
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


def _returns_are_sink(fn: ir.Function, rule: Rule) -> bool:
    """이 함수의 리턴값 자체가 sink 인지(웹 핸들러 등록 데코레이터가 붙었는지)."""
    return any(s.kind == "return" and any(_callee_matches(d, s.decorator)
                                          for d in fn.decorators)
               for s in rule.sinks)


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

    같은 파일에 같은 이름이 있으면 그쪽이 먼저다. 레지스트리는 맨 이름을 전역 하나로
    들고 있어 같은 이름이 여러 파일에 있으면 나중 것이 이긴다 — 수신자 없는 호출은
    자기 클래스의 메서드를 부르는 것이므로 그 규칙을 그대로 두면 엉뚱한 파일의 동명
    함수에 연결된다(실측: OWASP 자바 코퍼스에 doSomething 정의가 880개 있고, 안전한
    변형의 오탐 287건 중 64건이 이 때문이었다).
    """
    if not path:
        return None
    if ctx.file:
        hit = ctx.summaries.get(file_scoped(ctx.file, path))
        if hit is not None:
            return hit
    return ctx.summaries.get(path)


def _local_function(cp: str | None, callee: ir.Node, ctx: Ctx) -> Summary | None:
    """수신자가 식이라 점 경로가 안 나오는 호출을 같은 파일 안에서만 찾는다.

    new Test().doSomething(x) 는 수신자가 Call 이라 'Test.doSomething' 같은 경로가
    만들어지지 않는다. 그러면 정의를 못 찾아 과대근사로 통과시키는데, 자바에서
    정제 코드를 같은 파일의 내부 클래스에 두는 형태가 흔해 그대로 오탐이 된다
    (실측: OWASP 자바 코퍼스의 안전한 xss 변형 45건 중 19건이 이 모양이다).

    이름만 보고 프로젝트 전체에서 찾으면 다른 파일의 동명 메서드로 잘못 이어진다
    (같은 코퍼스에 doSomething 정의가 880개 있다). 같은 파일로 범위를 좁히면
    그 위험 없이 이 형태만 정확히 해석된다.
    """
    # 수신자가 식인 호출에만 쓴다 — new Test().doSomething(x) 처럼 그 자리에서 만든
    # 객체의 메서드. 이때는 타입이 코드에 그대로 적혀 있어 같은 파일 안에서 찾는 것이
    # 안전하다.
    #
    # 수신자가 변수인 호출(thing.doSomething(x))에는 절대 쓰지 않는다. 변수의 타입을
    # 모르는 채 이름만 보고 이으면 엉뚱한 함수에 연결된다 — 실측에서 helpers 의
    # ThingInterface.doSomething 호출이 같은 파일 내부 클래스의 doSomething(마침 분석
    # 중인 자기 자신)으로 이어져 오염이 통째로 사라졌다(취약 13건이 미탐이 됐다).
    if not ctx.file or not isinstance(callee, ir.Member) or not callee.prop:
        return None
    if not isinstance(callee.obj, ir.Call):
        return None
    return ctx.summaries.get(file_scoped(ctx.file, callee.prop))


def _self_shift(summ: Summary, callee: ir.Node) -> int:
    """수신자를 통해 부른 파이썬 메서드면 요약의 파라미터 자리가 한 칸 앞선다.

    obj.m(a) 는 인자가 [a] 뿐이지만 요약은 self 를 파라미터 0 으로 센다. 맞추지
    않으면 프로시저간 판정이 한 칸씩 어긋나 엉뚱한 인자를 보게 된다.
    """
    return 1 if (summ.implicit_self and isinstance(callee, ir.Member)) else 0


def _unique_function(cp: str | None, callee: ir.Node, nargs: int, ctx: Ctx) -> Summary | None:
    """수신자를 모르는 호출의 마지막 수단 — 그 이름의 정의가 프로젝트에 하나뿐일 때만.

    wrapped.get_form_parameter("x") 처럼 변수에 담긴 객체의 메서드는 변수의 타입을
    모르면 정의를 찾을 수 없다. 그런데 그 함수가 안에서 소스를 읽어 돌려주는 경우
    (요청 래퍼가 흔히 그렇다) 과대근사로도 오염이 생기지 않는다 — 인자가 깨끗하기
    때문이다. 그래서 이 형태는 통째로 미탐이 된다.

    이름이 유일하면 수신자를 몰라도 그 함수가 맞다. 여럿이면 등록 자체를 안 했으므로
    여기서 걸리지 않는다(자바 코퍼스의 doSomething 은 정의가 1802개다).
    """
    if not cp or "." not in cp:
        return None                      # 맨 이름은 앞의 두 경로가 이미 처리했다
    # 수신자가 단순 변수일 때만. org.apache.X.foo(...) 처럼 점 경로가 긴 라이브러리
    # 호출까지 이름만 보고 이으면 엉뚱한 함수의 요약을 씌운다.
    if not (isinstance(callee, ir.Member) and isinstance(callee.obj, ir.Ident)):
        return None
    hit = ctx.summaries.get(unique_name(cp.rpartition(".")[2]))
    if hit is None:
        return None
    # 인자 수가 안 맞으면 같은 이름의 다른 함수다. 수신자 호출이면 self 한 자리를 뺀다.
    want = hit.arity - (1 if hit.implicit_self else 0)
    return hit if want < 0 or want == nargs else None


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

        # map.get("키") — 넣을 때 키 단위로 기록했으므로 읽을 때도 그 슬롯만 본다.
        if cp and "." in cp and node.args and not _matches_source(cp, ctx.rule):
            recv, _, meth = cp.rpartition(".")
            if meth in _MAP_GET:
                key = _literal_key(node.args[0], ctx)
                if key is not None:
                    hit = _env_lookup(f"{recv}.{key}", env) or _env_lookup(recv, env)
                    if hit is None:
                        return None
                    return hit + [Step("propagation", node.loc, _snippet(node.loc, ctx.src))]

        step = Step("propagation", node.loc, _snippet(node.loc, ctx.src))
        summ = (_user_function(cp, ctx) or _local_function(cp, node.callee, ctx)
                or _unique_function(cp, node.callee, len(node.args), ctx))

        if summ is not None:
            # 함수가 자기 안에서 오염을 만들어 리턴하면, 인자와 무관하게 결과가 오염이다.
            if summ.returns_source:
                return summ.source_trace + [step]
            # 그 외에는 요약에 따라 "인자 오염 -> 리턴 오염" 여부를 정확히 판단한다.
            shift = _self_shift(summ, node.callee)
            for i, a in enumerate(node.args):
                tr = _taint(a, env, ctx)
                if tr and (i + shift) in summ.returns_tainted:
                    return tr + [step]
            return None  # 인자가 오염돼도 리턴으로 흐르지 않으면 오염 아님(정밀도)

        # 분석 대상 밖 함수. 표준 라이브러리처럼 동작이 선언된 것은 그대로 쓴다.
        # 수신자가 리터럴이면("abc".equals(x)) 점 경로가 안 나온다 — 메서드 이름은 쓸 수 있다.
        lookup = cp or (node.callee.prop if isinstance(node.callee, ir.Member) else None)
        verdict = _library().verdict(lookup, ctx.rule.languages) if lookup else None
        if verdict == BLOCK:
            # 리턴이 길이·불리언이라 payload 를 sink 로 옮길 수 없다 — 오염이 여기서 끊긴다.
            return None

        # 나머지는 인자 오염이 결과로 흐른다고 과대근사한다. 그 함수 안에서 정제됐을 수도
        # 있으므로 '불확실'로 표시해 둔다 — 동작이 선언된 함수는 확정이라 표시하지 않는다.
        for a in node.args:
            tr = _taint(a, env, ctx)
            if tr:
                if verdict == PROPAGATE:
                    return tr + [step]
                # 이 단계에 표시를 남긴다. 값이 변수에 담겼다가 나중에 sink 로 가도
                # 표시는 트레이스 안에 그대로 따라간다.
                return tr + [Step("propagation", node.loc, _snippet(node.loc, ctx.src),
                                  uncertain=True)]
        return _taint(node.callee, env, ctx)

    if isinstance(node, ir.Assign):
        return _taint(node.value, env, ctx)

    if isinstance(node, ir.FOLDED):
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
    elif isinstance(node, ir.FOLDED):
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
    elif isinstance(node, ir.FOLDED):
        for c in node.children:
            yield from _iter_functions(c)


def _emit(ctx: Ctx, steps: list[Step]) -> None:
    ctx.out.append(Finding(
        rule_id=ctx.rule.id, message=ctx.rule.message,
        severity=ctx.rule.severity, cwe=ctx.rule.cwe,
        owasp=ctx.rule.owasp, steps=steps,
        # 흐름이 미해석 함수를 지났는지는 트레이스가 들고 있다.
        uncertain=any(s.uncertain for s in steps),
    ))


def _check_sinks(node: ir.Node, env: dict[str, Trace], ctx: Ctx) -> None:
    for call in _iter_calls(node):
        cp = path_of(call.callee)

        # (a) 직접 sink 호출
        sink = _sink_for(cp, ctx.rule) if cp else None
        if sink is not None:
            # arg 미지정 = 모든 인자가 대상. arg 를 지정했는데 그 자리가 없는 호출은
            # 규칙이 말하는 sink 가 아니다 — 예전엔 이 경우도 전부 검사로 떨어져서
            # 규칙이 명시적으로 제외한 인자를 잡아 오탐을 냈다.
            if sink.arg is None:
                targets = call.args
            elif sink.arg < len(call.args):
                targets = [call.args[sink.arg]]
            else:
                targets = []
            for arg in targets:
                tr = _taint(arg, env, ctx)
                if tr:
                    _emit(ctx, tr + [Step("sink", call.loc, _snippet(call.loc, ctx.src))])
                    break

        # (b) 프로시저 간: 요약이 "이 파라미터는 내부에서 sink 에 닿는다"고 말하는 경우
        summ = (_user_function(cp, ctx) or _local_function(cp, call.callee, ctx)
                or _unique_function(cp, call.callee, len(call.args), ctx))
        if summ is not None and summ.sink_paths:
            shift = _self_shift(summ, call.callee)
            for i, arg in enumerate(call.args):
                if (i + shift) not in summ.sink_paths:
                    continue
                tr = _taint(arg, env, ctx)
                if not tr:
                    continue
                enter = Step("call", call.loc, _snippet(call.loc, ctx.src))
                for inner in summ.sink_paths[i + shift]:
                    _emit(ctx, tr + [enter] + inner)
                break


# 수신자를 변경하는 메서드. list.add(x) 처럼 인자의 오염이 컨테이너로 옮겨간다.
# 필드 민감도가 없어 컨테이너 전체가 오염되는 과대근사다(안전한 키를 다시 꺼내 써도
# 오염으로 본다). 보안 도구에서는 놓치는 쪽보다 이쪽이 낫다.
_MUTATORS = ("add", "addAll", "addFirst", "addLast", "put", "putAll", "putIfAbsent",
             "append", "insert", "push", "offer", "offerLast", "write", "concat",
             # ConfigParser.set(섹션, 키, 값) · List.set(i, x) · AtomicReference.set(x)
             "set")


# 키가 리터럴인 맵 접근은 키 단위로 구분한다. map.put("a", 오염) 뒤에 map.get("b") 를
# 읽는 코드를 통째로 오염으로 보면 오탐이 된다 — 리터럴 키는 공짜로 정확해진다.
_MAP_PUT = ("put", "putIfAbsent", "setProperty", "setAttribute")
_MAP_GET = ("get", "getOrDefault", "getProperty", "getAttribute")


def _literal_key(node: ir.Node, ctx: Ctx) -> str | None:
    """리터럴 문자열 키. 문자열이 아니거나 보간이 섞였으면 None(= 키를 특정할 수 없음).

    문자열 리터럴은 언어에 따라 Literal 이 아니라 Opaque(string_literal + 조각 자식)로
    오므로 노드 타입 대신 원본 스니펫을 본다."""
    if not isinstance(node, (ir.Literal, ir.Opaque)):
        return None
    raw = _snippet(node.loc, ctx.src)
    if len(raw) < 2 or raw[0] not in "\"'" or raw[-1] != raw[0]:
        return None
    inner = raw[1:-1]
    if any(m in inner for m in ("${", "#{", r"\(", '"', "'")):
        return None   # 보간·중첩 인용 → 상수 키로 보기 어렵다
    return inner


def _apply_mutations(node: ir.Node, env: dict[str, Trace], ctx: Ctx) -> dict[str, Trace]:
    """coll.add(오염) / sb.append(오염) / map.put(키, 오염) → 수신자 경로를 오염시킨다."""
    for call in _iter_calls(node):
        cp = path_of(call.callee)
        if not cp or "." not in cp:
            continue
        recv, _, meth = cp.rpartition(".")

        if meth in _MAP_PUT and len(call.args) >= 2:
            key = _literal_key(call.args[0], ctx)
            tr = _taint(call.args[1], env, ctx)
            if tr:
                # 키를 알면 그 슬롯만, 모르면 맵 전체를 오염으로 본다.
                target = f"{recv}.{key}" if key is not None else recv
                if target not in env:
                    env = dict(env)
                    env[target] = tr + [Step("propagation", call.loc, _snippet(call.loc, ctx.src))]
            continue

        if meth not in _MUTATORS or recv in env:
            continue
        for a in call.args:
            tr = _taint(a, env, ctx)
            if tr:
                env = dict(env)
                env[recv] = tr + [Step("propagation", call.loc, _snippet(call.loc, ctx.src))]
                break
    return env


def _guarded_paths(test: ir.Node, ctx: Ctx) -> set[str]:
    """조건문이 검증한 경로들.

    `if (isNumeric(p)) { use(p); }` 처럼 값을 바꾸지 않고 **검사만** 하는 코드가 흔한데,
    지금까지는 p 가 그대로 오염으로 남아 오탐이 됐다(벤치마크 오탐의 주 원인).
    조건이 규칙의 sanitizer 를 그 경로에 적용했다면, 참 분기 안에서는 검증된 것으로 본다.

    부정형(`!isNumeric(p)`)은 참 분기가 오히려 위험한 쪽이므로 아무것도 지우지 않는다 —
    모르면 오염으로 두는 기존 과대근사를 유지한다. 부정은 노드 타입으로 판별할 수 없다:
    언어에 따라 `!expr` 이 Unary 가 아니라 Opaque 로 정규화되기 때문에 원본을 본다.
    """
    out: set[str] = set()
    for call in _iter_calls(test):
        cp = path_of(call.callee)
        if not cp or not _is_sanitizer(cp, ctx.rule):
            continue
        if _negated(call, ctx):
            continue
        for a in call.args:                      # isNumeric(p) / Integer.parseInt(p)
            p = path_of(a)
            if p:
                out.add(p)
        if "." in cp:                            # p.matches("...") — 수신자가 검증 대상
            out.add(cp.rpartition(".")[0])
    return out


def _negated(call: ir.Call, ctx: Ctx) -> bool:
    """이 호출 앞에 부정 연산자가 붙어 있는가. 원본 바이트를 되짚어 본다."""
    i = call.loc.start_byte - 1
    src = ctx.src
    while i >= 0 and src[i:i + 1] in (b" ", b"\t", b"(", b"\n", b"\r"):
        i -= 1
    if i >= 0 and src[i:i + 1] == b"!":
        return True
    return src[max(0, i - 3):i + 1].lower().endswith(b"not")


def _validated_paths(test: ir.Node, ctx: Ctx) -> set[str]:
    """조건이 검증한 경로들 — 정제 함수를 부르지 않고 형태만 확인하는 형태.

        if '../' in name:      return 오류      # 거부하고 돌아간다
        open(base + name)                       # 여기서부터 name 은 검증됐다

    이 형태는 sanitizers(호출 이름)로는 잡히지 않는다. 무엇을 검증으로 인정할지는
    규칙의 validators 가 선언한다 — 경로 조작은 '..' 포함 검사, 코드 주입은 따옴표
    형식 검사처럼 유형마다 다르기 때문이다.

    한계는 분명하다. `'../' in name` 은 상대경로만 막고 절대경로(/etc/passwd)는 막지
    못한다. 그래도 "검사했으니 넘어간다"가 규칙이 선언한 기준이다.
    """
    if not ctx.rule.validators:
        return set()
    text = _snippet(test.loc, ctx.src)
    if not any(tok in text for tok in ctx.rule.validators):
        return set()
    out: set[str] = set()
    stack = [test]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if isinstance(n, (ir.Ident, ir.Member)):
            if p := path_of(n):
                out.add(p)
        for attr in ("callee", "obj", "value", "target"):
            if isinstance(c := getattr(n, attr, None), ir.Node):
                stack.append(c)
        for attr in ("args", "children"):
            stack.extend(c for c in (getattr(n, attr, None) or []) if isinstance(c, ir.Node))
    return out


def _always_exits(stmts: list[ir.Node]) -> bool:
    """이 블록이 끝까지 가지 않고 반드시 빠져나가는가(현재는 return 만 본다)."""
    return any(isinstance(s, ir.Return) for s in stmts)


def _drop_guarded(env: dict[str, Trace], guarded: set[str]) -> dict[str, Trace]:
    """검증된 경로와 그 하위 경로를 오염 상태에서 뺀다."""
    if not guarded:
        return env
    return {k: v for k, v in env.items()
            if not any(k == g or k.startswith(g + ".") for g in guarded)}


def _run_nested(node: ir.Node, ctx: Ctx) -> None:
    for fn in _iter_functions(node):
        _run_function(fn, ctx)


# ---------- 문 실행 ----------

def _precise_target(node: ir.Node) -> bool:
    """대입 대상이 그 경로 하나만 가리키는지.

    a[i] 는 인덱스를 특정할 수 없어 path_of 가 베이스 'a' 로 뭉갠다. 그 자리에 안전한
    값을 넣었다고 'a' 전체의 오염을 지우면, 다른 슬롯에 들어 있던 오염까지 사라진다
    (실측: m["b"]=오염 다음 줄의 m["c"]="안전" 하나로 미탐이 났다).
    """
    while isinstance(node, ir.Member):
        if node.computed:
            return False
        node = node.obj
    return True


def _merge(a: dict[str, Trace], b: dict[str, Trace]) -> dict[str, Trace]:
    """두 분기의 오염 상태를 합친다.

    한쪽 분기에서만 오염되어도 합류 이후에는 오염 가능성이 있으므로 오염으로 본다
    (건전한 과대근사). 이걸 안 하면 else 분기의 안전한 대입이 then 분기의 오염을
    지워버려 미탐이 생긴다.
    """
    out = dict(a)
    for k, v in b.items():
        out.setdefault(k, v)
    return out


def _run(stmts: list[ir.Node], env: dict[str, Trace], ctx: Ctx) -> dict[str, Trace]:
    """문 리스트를 분석하고 끝난 시점의 오염 상태를 돌려준다."""
    for s in stmts:
        if isinstance(s, ir.Function):
            _run_function(s, ctx)

        elif isinstance(s, ir.Assign):
            _check_sinks(s.value, env, ctx)
            _run_nested(s.value, ctx)
            env = _apply_mutations(s.value, env, ctx)
            tr = _taint(s.value, env, ctx)
            p = path_of(s.target)
            if p:
                env = dict(env)
                if tr:
                    env[p] = tr + [Step("propagation", s.loc, _snippet(s.loc, ctx.src))]
                elif s.operator == "=" and _precise_target(s.target):
                    env.pop(p, None)
                # x += 안전값 은 앞서 담긴 오염을 지우지 않는다 — 덧붙일 뿐이다.
                # m["c"] = 안전값 도 마찬가지다 — 경로가 m 으로 뭉개져 있어서
                # 지우면 m["b"] 에 담긴 오염까지 같이 사라진다.

        elif isinstance(s, ir.Return):
            _check_sinks(s.value, env, ctx)
            _run_nested(s.value, ctx)
            rt = _taint(s.value, env, ctx)
            if rt:
                ctx.return_traces.append(rt)  # 요약 계산용: 리턴값이 오염됨
                if ctx.return_is_sink:
                    _emit(ctx, rt + [Step("sink", s.loc, _snippet(s.loc, ctx.src))])

        elif isinstance(s, ir.If):
            _check_sinks(s.test, env, ctx)
            # 조건이 검증한 경로는 참 분기에서만 오염을 뺀다(경로 민감도 최소판).
            guarded = _guarded_paths(s.test, ctx)
            then_env = _run(s.then, _drop_guarded(dict(env), guarded), ctx)
            else_env = _run(s.orelse, dict(env), ctx)
            if _always_exits(s.then):
                # 참 분기가 돌아가 버리면 그 안의 상태는 이어지지 않는다. 그리고 그
                # 분기가 "형태가 잘못됐으면 거부"였다면, 이어지는 코드에서는 검증된 값이다.
                env = _drop_guarded(else_env, _validated_paths(s.test, ctx))
            else:
                env = _merge(then_env, else_env)

        elif isinstance(s, ir.Loop):
            _check_sinks(s.test, env, ctx)
            env = _run_loop(s, env, ctx)

        else:
            _check_sinks(s, env, ctx)
            _run_nested(s, ctx)
            env = _apply_mutations(s, env, ctx)

    return env


def _run_loop(node: ir.Loop, env: dict[str, Trace], ctx: Ctx) -> dict[str, Trace]:
    """반복문: 오염 상태가 더 늘지 않을 때까지 돌린 뒤 그 상태로 한 번만 실제 분석한다.

    회전을 거쳐야 오염이 도달하는 경우(cur = nxt; nxt = 오염)를 잡기 위해 고정점이 필요하다.
    다만 고정점 반복 중에 매번 보고하면 같은 취약점이 여러 번 나오므로,
    수렴시키는 동안에는 결과를 버리는 문맥으로 돌리고 마지막에 한 번만 실제로 보고한다.
    """
    quiet = Ctx(rule=ctx.rule, src=ctx.src, out=[], summaries=ctx.summaries, file=ctx.file)
    cur = dict(env)
    for _ in range(MAX_LOOP_ITERATIONS):
        nxt = _merge(cur, _run(node.body, dict(cur), quiet))
        if set(nxt) == set(cur):
            break
        cur = nxt
    return _merge(cur, _run(node.body, dict(cur), ctx))


def _annotated_env(fn: ir.Function, ctx: Ctx) -> dict[str, Trace]:
    """프레임워크가 요청 값을 주입하는 파라미터를 오염 상태로 시작시킨다.

    Spring 의 @RequestParam, ASP.NET 의 [FromQuery] 같은 것들. 이 파라미터는 호출자가
    없고 프레임워크가 직접 채우므로, 요약(호출 인자 전파)으로는 절대 오염되지 않는다.
    진입점 자체를 소스로 보지 않으면 컨트롤러가 통째로 미탐이 된다.
    """
    wanted = {n for s in ctx.rule.sources if s.kind == "annotation" for n in s.name}
    if not wanted:
        return {}
    return {p.name: [Step("source", p.loc, _snippet(p.loc, ctx.src))]
            for p in fn.params if wanted.intersection(p.annotations)}


def _run_function(fn: ir.Function, ctx: Ctx) -> None:
    """함수 본문을 분석한다(일반 파라미터 오염은 요약이 담당)."""
    prev = ctx.return_is_sink
    ctx.return_is_sink = _returns_are_sink(fn, ctx.rule)
    try:
        _run(fn.body, _annotated_env(fn, ctx), ctx)
    finally:
        ctx.return_is_sink = prev


# ---------- 요약 계산 ----------

def _summarize(info: FuncInfo, rule: Rule, summaries: dict[str, Summary]) -> Summary:
    """함수 하나의 요약을 만든다.

    먼저 빈 env 로 돌려 "인자와 무관하게 오염을 만들어 리턴하는지"를 본다.
    그다음 파라미터를 하나씩 오염시켜 돌리되, 그 파라미터에서 비롯된 흐름만 채택한다
    (steps[0] 이 param 인 것). 내부 소스에서 온 흐름은 함수 자체를 분석할 때 이미 보고되므로
    여기서 다시 세면 중복이 된다.
    """
    result = Summary()
    result.implicit_self = bool(info.fn.params) and info.fn.params[0].name in ("self", "cls")
    result.arity = len(info.fn.params)

    # (1) 인자 무관 오염 리턴
    base = Ctx(rule=rule, src=info.src, out=[], summaries=summaries, file=info.file)
    _run(info.fn.body, {}, base)
    if base.return_traces:
        result.source_trace = base.return_traces[0]

    # (2) 파라미터별 전파
    for i, p in enumerate(info.fn.params):
        collected: list[Finding] = []
        ctx = Ctx(rule=rule, src=info.src, out=collected, summaries=summaries,
                  file=info.file)
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
    # 한 함수가 여러 이름(맨 이름 + 모듈 경로)으로 등록돼 있다. 이름 단위로 돌면
    # 계산도 비교도 별칭 수만큼 반복된다(실측: 자바 코퍼스 3분 -> 14분, 결과는 동일).
    # 함수 단위로 한 번 계산하고 그 함수의 이름들에 같은 요약을 나눠 준다.
    by_function: dict[int, tuple[FuncInfo, list[str]]] = {}
    for name, info in registry.items():
        by_function.setdefault(id(info), (info, []))[1].append(name)

    for _ in range(MAX_SUMMARY_ITERATIONS):
        changed = False
        for info, names in by_function.values():
            new = _summarize(info, rule, summaries)
            if new != summaries[names[0]]:
                for n in names:
                    summaries[n] = new
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
        _run(module.body, {}, Ctx(rule=rule, src=src, out=out, summaries=summaries,
                                  file=module.loc.file))
    return out
