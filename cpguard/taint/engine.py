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
from ..cpg.callgraph import (FuncInfo, alt_name, collect_functions, file_scoped,
                             unique_name)
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

def _const_key(node: ir.Node | None) -> str | None:
    """첨자가 리터럴이면 그 값. 아니면 None.

    문자열 리터럴은 언어에 따라 Literal 이 아니라 조각을 가진 Opaque 로 오므로
    두 형태를 모두 본다.
    """
    if isinstance(node, ir.Literal):
        raw = (node.raw or "").strip()
        if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
            return raw[1:-1]
        return raw or None
    if isinstance(node, ir.Opaque) and node.kind.endswith("string_literal"):
        parts = [c.raw or "" for c in node.children if isinstance(c, ir.Literal)]
        return "".join(parts) if parts else None
    return None


def path_of(node: ir.Node) -> str | None:
    """식별자/멤버 접근을 'req.query.id' 같은 점 경로 문자열로. 그 외는 None."""
    if isinstance(node, ir.Ident):
        return node.name
    if isinstance(node, ir.Member):
        base = path_of(node.obj)
        if base is None:
            return None
        if node.computed:
            # a["키"] 는 슬롯을 특정할 수 있다 — map.get("키") 에 이미 있던 키 단위
            # 정밀도를 첨자 문법에도 준다. d["a"]=오염 뒤 d["b"] 를 읽는 코드가
            # 오탐이 되지 않는다. 인덱스가 상수가 아니면 예전처럼 베이스로 뭉갠다.
            key = _const_key(node.index)
            return f"{base}.{key}" if key is not None else base
        return f"{base}.{node.prop}"
    if isinstance(node, ir.Call):
        # Runtime.getRuntime().exec(x) / foo().bar() — 호출 결과를 리시버로 쓰는 체인.
        # 호출 대상 경로를 베이스로 이어야 'exec' 같은 sink 접미가 매칭된다.
        return path_of(node.callee)
    return None


def _var_rooted(node: ir.Node) -> bool:
    """변수에서 시작해 알려진 속성만 타고 온 경로인가(a.b.c 는 참, f().b 는 거짓)."""
    while isinstance(node, ir.Member):
        if node.computed:
            return False
        node = node.obj
    return isinstance(node, ir.Ident)


def _snippet(loc: ir.Loc, src: bytes) -> str:
    try:
        return src[loc.start_byte:loc.end_byte].decode("utf-8", "replace").strip()
    except Exception:
        return ""


# ---------- 스펙 매칭 ----------

#: 인스턴스에 담아 둔 요청 객체를 가리키는 접두. self.request.form 처럼 한 겹 감싼
#: 형태는 파이썬·자바 웹 코드에서 표준에 가깝다 — 이 한 겹을 벗겨 소스를 본다.
_SELF_PREFIX = ("self", "this", "cls", "$this")

#: 수신자를 가리키는 이름들. 언어마다 다르고 정규화기가 원문 그대로 두므로 전부 본다.
_RECEIVERS = ("this", "self", "$this")


def _matches_source(path: str, rule: Rule) -> bool:
    if "::" in path:
        # std::getenv 는 getenv 다. 이름공간을 붙여 쓰는 것은 C++ 의 기본 스타일이라
        # 규칙에 두 형태를 다 적게 하면 목록이 두 배가 되고 하나는 반드시 빠진다.
        path = path.rpartition("::")[2]
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
        if path == c or path.endswith("." + c) or path.endswith("::" + c):
            return True                      # std::system 은 system 이다
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


def _is_sanitizer(path: str, rule: Rule, call: "ir.Call | None" = None,
                  ctx: "Ctx | None" = None) -> bool:
    if _callee_matches(path, rule.sanitizers):
        return True
    if call is None or ctx is None or not rule.sanitizer_args:
        return False
    # 인자 원문에 지정 토큰이 있어야 정제로 인정한다(filter_var 의 필터 상수 등).
    for name, tokens in rule.sanitizer_args.items():
        if not _callee_matches(path, [name]):
            continue
        text = " ".join(_snippet(a.loc, ctx.src) for a in call.args)
        if any(t in text for t in tokens):
            return True
    return False


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

#: 값이 아니라 크기를 내는 속성. 읽어도 공격 문자열이 따라오지 않는다.
_SIZE_PROPS = frozenset({"length", "size", "byteLength", "Length"})

#: 결과가 불리언인 연산자. 언어와 무관하게 비교는 참/거짓만 낸다.
_BOOL_OPS = frozenset({"==", "!=", "===", "!==", "<>", "<", ">", "<=", ">=", "<=>",
                       "instanceof", "in", "not in", "is", "is not"})

#: payload 를 담을 수 없는 자료형. 여기로 캐스트하면 오염이 끊긴다.
_NUMERIC_CASTS = ("int", "integer", "float", "double", "real", "bool", "boolean", "long")


def _numeric_cast(node: ir.Opaque, ctx: Ctx) -> bool:
    """이 캐스트가 숫자·불리언으로 바꾸는가. 원문에서 괄호 안 타입을 본다."""
    text = _snippet(node.loc, ctx.src).lstrip()
    if not text.startswith("("):
        return False
    end = text.find(")")
    return end > 0 and text[1:end].strip().lower() in _NUMERIC_CASTS


def _env_lookup(path: str, env: dict[str, Trace], slots: bool = False) -> Trace | None:
    """정확 일치 또는 오염된 경로의 하위 경로(x 오염 -> x.y 도 오염).

    slots=True 면 반대 방향도 본다 — d["b"] 만 오염된 상태에서 d 를 통째로(또는 상수가
    아닌 인덱스로) 읽으면 그 슬롯이 딸려 나온다. 슬롯을 상수 키로 특정한 읽기에는
    쓰지 않는다. 그랬다가는 d["a"] 를 읽어도 d["b"] 의 오염이 나와 키 단위 정밀도가
    무의미해진다.
    """
    if path in env:
        return env[path]
    for tp, tr in env.items():
        if path.startswith(tp + "."):
            return tr
    if slots:
        for tp, tr in env.items():
            if tp.startswith(path + "."):
                return tr
    return None


def _taint(node: ir.Node, env: dict[str, Trace], ctx: Ctx) -> Trace | None:
    """이 표현식이 오염됐으면 여기까지의 트레이스를, 아니면 None."""
    if node is None or isinstance(node, ir.Literal):
        return None

    if isinstance(node, (ir.Ident, ir.Member)):
        p = path_of(node)
        # 상수 키로 슬롯을 특정한 읽기(d["a"])는 그 슬롯만 본다. 그 외의 읽기는
        # 컨테이너를 통째로 보는 것이므로 안에 오염된 슬롯이 있으면 딸려 나온다.
        const_slot = (isinstance(node, ir.Member) and node.computed
                      and _const_key(node.index) is not None)
        if isinstance(node, ir.Member) and not node.computed and node.prop in _SIZE_PROPS:
            # x.length — 수치라 payload 를 sink 로 옮길 수 없다. env 조회보다 먼저
            # 봐야 한다: 'x' 가 오염이면 하위 경로 'x.length' 도 오염으로 잡히기 때문.
            # 호출 형태(x.length())는 라이브러리 요약이 이미 끊고 있고 이건 속성 형태다.
            return None
        if p:
            if _matches_source(p, ctx.rule):
                return [Step("source", node.loc, _snippet(node.loc, ctx.src))]
            hit = _env_lookup(p, env, slots=not const_slot)
            if hit is not None:
                return hit + [Step("propagation", node.loc, _snippet(node.loc, ctx.src))]
        if isinstance(node, ir.Member):
            if node.computed and _const_key(node.index) is not None:
                # 상수 키로 슬롯을 특정했고 그 슬롯이 깨끗한 것이 확정이다. 베이스로
                # 되돌아가면 다른 슬롯의 오염이 딸려 나와 키 단위 정밀도가 사라진다.
                return None
            if node.computed:
                # 인덱스를 특정할 수 없는 읽기 — 컨테이너의 어느 슬롯이든 나올 수 있다.
                base = path_of(node.obj)
                if base and (hit := _env_lookup(base, env, slots=True)) is not None:
                    return hit + [Step("propagation", node.loc, _snippet(node.loc, ctx.src))]
            elif _var_rooted(node.obj):
                # o.safe — 변수에 담긴 객체의 알려진 속성 하나만 읽는다. 위 조회에서
                # 안 걸렸다면 그 슬롯도, 그 슬롯을 품은 어떤 조상도 오염이 아니다
                # (_env_lookup 이 접두 일치로 조상까지 본다). 여기서 객체 전체로
                # 되돌아가면 o.cmd 의 오염이 o.safe 로 새어 나온다.
                return None
            return _taint(node.obj, env, ctx)
        return None

    if isinstance(node, ir.Call):
        cp = path_of(node.callee)
        if cp and _is_sanitizer(cp, ctx.rule, node, ctx):
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
            # obj.getData() — 객체가 오염이면 게터의 리턴도 오염이다.
            if summ.self_returns and isinstance(node.callee, ir.Member):
                if rt := _taint(node.callee.obj, env, ctx):
                    return rt + [step]
            # new Svc(오염) — 인자가 필드로 들어가면 만들어진 객체 자체가 오염이다.
            if summ.is_ctor and summ.taints_self:
                csh = 1 if summ.implicit_self else 0
                for i, a in enumerate(node.args):
                    if (i + csh) in summ.taints_self and (tr := _taint(a, env, ctx)):
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
        # (int)$x · (float)$x — 숫자로 바꾼 값은 payload 를 담을 수 없다. 규칙과 무관한
        # 자료형의 성질이라 sanitizers(규칙별 함수 목록)가 아니라 여기서 끊는다.
        if isinstance(node, ir.Opaque) and node.kind.endswith("cast_expression"):
            if _numeric_cast(node, ctx):
                return None
        if isinstance(node, ir.Binary) and (node.numeric or node.op in _BOOL_OPS):
            # 비교 결과는 불리언, 산술 결과는 수치다. 둘 다 공격 문자열을 담을 수 없다.
            # `$t = ($t == 'safe1') ? 'safe1' : 'safe2'` 를 오탐으로 만들던 경로.
            return None
        if isinstance(node, ir.Unary) and node.op in ("!", "not"):
            return None
        if isinstance(node, ir.Ternary) and len(node.children) == 3:
            # 조건식의 값은 then/else 중 하나다. 조건의 오염은 값으로 흐르지 않는다.
            for c in node.children[1:]:
                tr = _taint(c, env, ctx)
                if tr:
                    return tr + [Step("propagation", node.loc, _snippet(node.loc, ctx.src))]
            return None
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


def _iter_assigns(node: ir.Node):
    """표현식 트리 안의 모든 Assign 을 안쪽부터 훑는다."""
    if node is None:
        return
    if isinstance(node, ir.Assign):
        yield from _iter_assigns(node.value)
        yield node
    elif isinstance(node, ir.Call):
        for a in node.args:
            yield from _iter_assigns(a)
        yield from _iter_assigns(node.callee)
    elif isinstance(node, ir.Member):
        yield from _iter_assigns(node.obj)
        yield from _iter_assigns(node.index)
    elif isinstance(node, ir.FOLDED):
        for c in node.children:
            yield from _iter_assigns(c)


def _bind_inline(node: ir.Node, env: dict[str, Trace], ctx: Ctx) -> dict[str, Trace]:
    """조건식 안에서 이뤄진 대입을 환경에 반영한다.

    `if (($t = fgets($h)) === false)` / `while ((m = re.exec(s)))` 처럼 조건 자리에서
    변수를 채우는 형태는 흔한데, 표현식으로만 평가하면 $t 가 어디에도 묶이지 않아
    이후 본문이 통째로 미탐이었다. 대입문과 같은 규칙으로 묶는다.
    """
    for a in _iter_assigns(node):
        p = path_of(a.target)
        if not p or a.operator == "pair":     # 객체 리터럴의 키는 변수가 아니다
            continue
        tr = _taint(a.value, env, ctx)
        if tr:
            env = dict(env)
            env[p] = tr + [Step("propagation", a.loc, _snippet(a.loc, ctx.src))]
        elif a.operator == "=" and _precise_target(a.target) and p in env:
            env = dict(env)
            env.pop(p, None)
    return env


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
        if summ is not None and summ.self_sink_paths and isinstance(call.callee, ir.Member):
            # svc.run() — 인자가 없어도 객체 안의 필드가 sink 로 간다.
            rt = _taint(call.callee.obj, env, ctx)
            if rt:
                enter = Step("call", call.loc, _snippet(call.loc, ctx.src))
                for inner in summ.self_sink_paths:
                    _emit(ctx, rt + [enter] + inner)

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


def _out_params(node: ir.Node, env: dict[str, Trace], ctx: Ctx) -> dict[str, Trace]:
    """인자에 결과를 써 주는 호출을 반영한다. C 계열의 표준 형태다.

      outparam  fgets(buf, ...)              그 자체가 입력이다 → buf 가 오염
      outcopy   snprintf(cmd, n, "%s", x)    x 의 오염을 cmd 로 옮긴다

    리턴값만 보면 C 코드가 통째로 미탐이다. 어떤 호출의 몇 번째 인자가 출력인지는
    규칙이 선언한다 — 언어마다 API 가 다르기 때문이다.
    """
    pats = [s for s in ctx.rule.sources if s.kind in ("outparam", "outcopy")]
    if not pats:
        return env
    for call in _iter_calls(node):
        cp = path_of(call.callee)
        if not cp:
            continue
        base = cp.rpartition(".")[2]
        for s in pats:
            if base not in s.name and cp not in s.name:
                continue
            if s.arg >= len(call.args):
                continue
            p = _out_target(call.args[s.arg])
            if not p or p in env:
                continue
            if s.kind == "outparam":          # 그 자체가 입력이다(fgets · ShouldBindJSON)
                tr = [Step("source", call.loc, _snippet(call.loc, ctx.src))]
            else:                             # 다른 값을 그 자리로 옮긴다(snprintf · Decode)
                # 수신자도 본다 — json.NewDecoder(오염).Decode(&v) 는 오염이 수신자에 있다.
                recv = call.callee.obj if isinstance(call.callee, ir.Member) else None
                tr = next((t for a in ([recv] if recv is not None else [])
                           + [a for i, a in enumerate(call.args) if i != s.arg]
                           if (t := _taint(a, env, ctx))), None)
                if tr:
                    tr = tr + [Step("propagation", call.loc, _snippet(call.loc, ctx.src))]
            if tr:
                env = dict(env)
                env[p] = tr
    return env


def _out_target(node: ir.Node) -> str | None:
    """출력 인자가 가리키는 경로. `&q` 처럼 주소를 넘기는 형태를 한 겹 벗긴다."""
    p = path_of(node)
    if p is not None:
        return p
    kids = getattr(node, "children", None) or []
    return path_of(kids[0]) if len(kids) == 1 else None


def _apply_mutations(node: ir.Node, env: dict[str, Trace], ctx: Ctx) -> dict[str, Trace]:
    """coll.add(오염) / sb.append(오염) / map.put(키, 오염) → 수신자 경로를 오염시킨다."""
    env = _out_params(node, env, ctx)
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

        if meth not in _MUTATORS and recv not in env:
            # 사용자 정의 세터도 컨테이너 변경과 같다 — 요약이 "이 인자는 필드로
            # 들어간다"고 말하면 수신자를 오염으로 본다.
            summ = _user_function(cp, ctx) or _unique_function(cp, call.callee,
                                                               len(call.args), ctx)
            if summ is not None and summ.taints_self:
                sh = _self_shift(summ, call.callee)
                for i, a in enumerate(call.args):
                    if (i + sh) in summ.taints_self and (tr := _taint(a, env, ctx)):
                        env = dict(env)
                        env[recv] = tr + [Step("propagation", call.loc,
                                               _snippet(call.loc, ctx.src))]
                        break
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
        if cp is None and isinstance(call.callee, ir.Member):
            # /^[0-9]+$/.test(x) — 리시버가 리터럴이라 점 경로가 나오지 않는다.
            # 이름만으로도 검증 호출임을 알 수 있으면 인정한다.
            cp = call.callee.prop
        if not cp or not _is_sanitizer(cp, ctx.rule, call, ctx):
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
    out: set[str] = _lookup_guarded(test)
    if not ctx.rule.validators:
        return out
    text = _snippet(test.loc, ctx.src)
    if not any(tok in text for tok in ctx.rule.validators):
        return out
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


#: 거부하고 빠져나가는 호출. 예외를 던지는 것과 같은 자리다.
_EXIT_CALLS = frozenset({"panic", "exit", "Exit", "abort", "die", "halt",
                         "process.exit", "sys.exit", "os.Exit", "System.exit"})


def _lookup_guarded(test: ir.Node) -> set[str]:
    """조회표의 **키로** 쓰인 경로. 허용 목록 검사의 언어 무관 형태다.

        allowed := map[string]bool{"asc": true, "desc": true}
        if !allowed[data] { 거부; return }      // data 는 컴파일 시점 상수 집합 안의 값
        exec.Command("sh", "-c", "echo "+data)

    값이 **표의 키로 조회됐고** 그 분기가 돌아가 버렸다면, 이어지는 코드에서 그 값은
    미리 정해진 집합의 원소다. 컨테이너 자체를 읽는 형태(`data[i]`)와는 다르다 —
    그쪽은 첨자가 아니라 베이스가 오염 경로다.
    """
    out: set[str] = set()
    stack = [test]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if isinstance(n, ir.Member) and n.computed and n.index is not None:
            key, base = path_of(n.index), path_of(n.obj)
            if key and base and key != base and not key.startswith(base + "."):
                out.add(key)
        for attr in ("callee", "obj", "value", "target", "index"):
            if isinstance(c := getattr(n, attr, None), ir.Node):
                stack.append(c)
        for attr in ("args", "children"):
            stack.extend(c for c in (getattr(n, attr, None) or []) if isinstance(c, ir.Node))
    return out


#: nil 비교는 검증이 아니다 — 값이 있느냐를 물었을 뿐 무슨 값인지는 안 봤다.
_NULLS = frozenset({"nil", "null", "NULL", "None", "undefined"})


def _is_const(node: ir.Node) -> bool:
    """변수를 하나도 거치지 않는 식인가(리터럴 / 리터럴 조각으로 된 문자열).

    문자열 리터럴이 언어에 따라 Literal 이 아니라 조각을 가진 Opaque 로 오기 때문에
    `_const_key` 로는 Go 의 `"metadata"` 를 집지 못한다. 값을 꺼내는 게 아니라
    '상수인가'만 물으면 되므로 변수의 부재로 판단한다.
    """
    found = False
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, (ir.Ident, ir.Member, ir.Call)):
            return False
        if isinstance(n, ir.Literal):
            if (n.raw or "").strip() in _NULLS:
                return False
            found = True
        elif isinstance(n, ir.Opaque) and n.kind.endswith("string_literal"):
            found = True
        stack.extend(c for c in (getattr(n, "children", None) or [])
                     if isinstance(c, ir.Node))
    return found


def _rejected_paths(test: ir.Node) -> set[str]:
    """거부-후-return 분기의 조건이 **검사한** 경로들.

    `_validated_paths` 는 규칙의 validators 토큰(Contains·MatchString·Atoi …)에
    걸린 것만 인정한다. 실제 거부 코드는 그 목록에 없는 형태가 더 많다.

        if host == "metadata" || host == "metadata.google.internal" { 거부 }
        if !allowed[parsedURL.Hostname()] { 거부 }
        if ip.IsPrivate() || ip.IsLoopback() { 거부 }

    셋 다 "값을 보고 아니면 돌려보낸다"는 같은 일을 한다. 무엇을 검사로 인정할지가
    이 함수의 전부다 — 넓히면 오탐이 줄고 재현율이 깎인다. `len(data) > 100` 은
    검사가 아니다(길이를 봤을 뿐 값은 그대로다). 그 경계가 테스트에 박혀 있다.

    호출부는 `_always_exits(then)` 인 분기에서만 부르므로 '거부한다'는 이미 참이다.
    """
    out: set[str] = _lookup_guarded(test)
    stack = [test]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if isinstance(n, ir.Binary) and n.op in ("==", "!=") and len(n.children) == 2:
            # host == "metadata" — 값을 정해진 이름과 맞춰 본다.
            a, b = n.children
            for x, y in ((a, b), (b, a)):
                if _is_const(y) and _var_rooted(x) and (p := path_of(x)):
                    out.add(p)
        elif (isinstance(n, ir.Call) and not n.args
                and isinstance(n.callee, ir.Member) and _var_rooted(n.callee.obj)):
            # ip.IsPrivate() / ip.IsLoopback() — 값 자체에 성질을 물었다.
            # 인자가 있으면 제외한다: len(data) > 100 처럼 값을 인자로 넘겨 **다른 것**을
            # 계산한 형태는 값을 본 게 아니다. 그 경계가 재현율을 지킨다.
            if p := path_of(n.callee.obj):
                out.add(p)
        for attr in ("callee", "obj", "value", "target", "index"):
            if isinstance(c := getattr(n, attr, None), ir.Node):
                stack.append(c)
        for attr in ("args", "children"):
            stack.extend(c for c in (getattr(n, attr, None) or []) if isinstance(c, ir.Node))
    return out


def _derived_origins(env: dict[str, Trace], guarded: set[str]) -> set[str]:
    """guarded 경로가 파생돼 나온 **조상** 경로들.

        data      ← 소스
        parsedURL ← url.Parse(data)
        host      ← parsedURL.Hostname()

    `host` 를 검증했으면 `parsedURL` 과 `data` 도 같은 값의 다른 모습이다.
    별도의 자료구조는 필요 없다 — env 의 Trace 가 이미 유래를 들고 있다.
    `host` 의 트레이스는 `data` 의 트레이스로 시작한다. 형제(`other := data + "x"`)는
    갈라진 지점이 달라 그렇지 않다. 조상만 지우고 형제는 남기는 것이 계약이다.
    """
    out: set[str] = set()
    for g in guarded:
        # 검증된 경로가 env 에 그대로 없을 수 있다 — `allowed[parsedURL.Hostname()]`
        # 의 키는 `parsedURL.Hostname` 이지만 오염을 들고 있는 것은 `parsedURL` 이다.
        tr = None
        while g and (tr := env.get(g)) is None:
            g = g.rpartition(".")[0]
        if not tr:
            continue
        for k, t in env.items():
            if k != g and len(t) < len(tr) and tr[:len(t)] == t:
                out.add(k)
    return out


def _always_exits(stmts: list[ir.Node]) -> bool:
    """이 블록이 끝까지 가지 않고 반드시 빠져나가는가.

    return 만 보면 예외로 거부하는 코드를 통째로 놓친다. NestJS 는 `throw new
    BadRequestException(...)`, 파이썬은 raise, Go 는 panic 으로 거부한다 — 같은
    코퍼스의 express 판(return)과 nest 판(throw)이 점수가 2.7배 갈렸다.
    """
    for s in stmts:
        if isinstance(s, ir.Return):
            return True
        if isinstance(s, ir.Opaque) and ("throw" in s.kind or "raise" in s.kind):
            return True
        if isinstance(s, ir.Call):
            cp = path_of(s.callee)
            if cp and (cp in _EXIT_CALLS or cp.rpartition(".")[2] in _EXIT_CALLS):
                return True
    return False


def _drop_guarded(env: dict[str, Trace], guarded: set[str]) -> dict[str, Trace]:
    """검증된 경로와 그 하위 경로를 오염 상태에서 뺀다."""
    if not guarded:
        return env
    return {k: v for k, v in env.items()
            if not any(k == g or k.startswith(g + ".") for g in guarded)}


def _run_nested(node: ir.Node, ctx: Ctx, env: dict[str, Trace] | None = None) -> None:
    for fn in _iter_functions(node):
        # 클로저는 바깥 스코프를 그대로 붙잡는다. 빈 환경으로 돌리면 `v := 오염;
        # go func(){ 위험(v) }()` 같은 형태가 통째로 미탐이다 — Go 의 고루틴·defer,
        # JS 의 콜백이 전부 이 모양이다. 파라미터로 받는 값은 seed 가 따로 덮는다.
        captured = {k: v for k, v in (env or {}).items()
                    if not any(p.name == k.split(".")[0] for p in fn.params)}
        _run_function(fn, ctx, seed={**captured, **(_callback_seed(fn, node, env, ctx) or {})})


#: 콜백에 원소를 넘겨주는 메서드. 수신자가 오염이면 콜백의 첫 인자도 오염이다.
_ITER_METHODS = frozenset({
    "forEach", "map", "filter", "flatMap", "find", "findIndex", "some", "every",
    "then", "catch", "finally", "reduce", "sort", "each", "eachSeries", "eachLimit",
    # 코틀린 스코프 함수 — 수신자를 그대로 람다에 넘긴다.
    "let", "also", "apply", "run", "takeIf", "takeUnless", "onEach", "mapNotNull",
    # 스위프트
    "compactMap", "flatMap", "first", "contains"})


def _callback_seed(fn: ir.Function, node: ir.Node, env: dict[str, Trace] | None,
                   ctx: Ctx) -> dict[str, Trace] | None:
    """`오염.map(function (v) { ... })` 의 v 를 오염으로 시작시킨다.

    콜백을 빈 환경으로 돌리면 배열·프로미스를 거친 흐름이 통째로 미탐이다. 원소를
    하나하나 구분하지 않는 과대근사로, 컨테이너를 통째로 오염으로 보는 모델과 같다.
    """
    if env is None or not fn.params:
        return None
    for call in _iter_calls(node):
        if not any(a is fn for a in call.args):
            continue
        cp = path_of(call.callee)
        meth = cp.rpartition(".")[2] if cp and "." in cp else (
            call.callee.prop if isinstance(call.callee, ir.Member) else None)
        if meth not in _ITER_METHODS:
            continue
        src_node = call.callee.obj if isinstance(call.callee, ir.Member) else None
        tr = _taint(src_node, env, ctx) if src_node is not None else None
        if tr:
            return {fn.params[0].name: tr + [
                Step("propagation", fn.loc, _snippet(fn.loc, ctx.src))]}
    return None


# ---------- 문 실행 ----------

def _precise_target(node: ir.Node) -> bool:
    """대입 대상이 그 경로 하나만 가리키는지.

    a[i] 는 인덱스를 특정할 수 없어 path_of 가 베이스 'a' 로 뭉갠다. 그 자리에 안전한
    값을 넣었다고 'a' 전체의 오염을 지우면, 다른 슬롯에 들어 있던 오염까지 사라진다
    (실측: m["b"]=오염 다음 줄의 m["c"]="안전" 하나로 미탐이 났다).
    """
    while isinstance(node, ir.Member):
        if node.computed and _const_key(node.index) is None:
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
            _run_nested(s.value, ctx, env)
            env = _apply_mutations(s.value, env, ctx)
            tr = _taint(s.value, env, ctx)
            p = path_of(s.target)
            if p and isinstance(s.value, ir.Opaque) and s.value.kind == "object_literal":
                # const o = { a: 오염, b: '안전' } — 슬롯별로 담아 o.b 읽기를 지킨다.
                env = dict(env)
                env.pop(p, None)
                for pair in s.value.children:
                    key = path_of(pair.target) if isinstance(pair, ir.Assign) else None
                    ptr = _taint(pair.value, env, ctx) if key else None
                    slot = f"{p}.{key}"
                    if ptr:
                        env[slot] = ptr + [Step("propagation", s.loc,
                                                _snippet(s.loc, ctx.src))]
                    else:
                        env.pop(slot, None)
                continue
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
            _run_nested(s.value, ctx, env)
            rt = _taint(s.value, env, ctx)
            if rt:
                ctx.return_traces.append(rt)  # 요약 계산용: 리턴값이 오염됨
                if ctx.return_is_sink:
                    _emit(ctx, rt + [Step("sink", s.loc, _snippet(s.loc, ctx.src))])

        elif isinstance(s, ir.If):
            _check_sinks(s.test, env, ctx)
            env = _bind_inline(s.test, env, ctx)
            # 조건이 검증한 경로는 참 분기에서만 오염을 뺀다(경로 민감도 최소판).
            guarded = _guarded_paths(s.test, ctx)
            then_env = _run(s.then, _drop_guarded(dict(env), guarded), ctx)
            else_env = _run(s.orelse, dict(env), ctx)
            if _always_exits(s.then):
                # 참 분기가 돌아가 버리면 그 안의 상태는 이어지지 않는다. 그리고 그
                # 분기가 "형태가 잘못됐으면 거부"였다면, 이어지는 코드에서는 검증된 값이다.
                clean = _validated_paths(s.test, ctx) | _rejected_paths(s.test)
                env = _drop_guarded(else_env, clean | _derived_origins(else_env, clean))
            else:
                env = _merge(then_env, else_env)

        elif isinstance(s, ir.Loop):
            _check_sinks(s.test, env, ctx)
            env = _run_loop(s, _bind_inline(s.test, env, ctx), ctx)

        else:
            _check_sinks(s, env, ctx)
            _run_nested(s, ctx, env)
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


def _run_function(fn: ir.Function, ctx: Ctx,
                  seed: dict[str, Trace] | None = None) -> None:
    """함수 본문을 분석한다(일반 파라미터 오염은 요약이 담당).

    seed 는 콜백처럼 호출부가 값을 직접 넘겨주는 경우의 시작 오염이다.
    """
    prev = ctx.return_is_sink
    ctx.return_is_sink = _returns_are_sink(fn, ctx.rule)
    try:
        env = _annotated_env(fn, ctx)
        if seed:
            env = {**env, **seed}
        _run(fn.body, env, ctx)
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
    result.is_ctor = bool(info.fn.is_ctor)

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
        out_env = _run(info.fn.body, env, ctx)

        if any(tr and tr[0].kind == "param" for tr in ctx.return_traces):
            result.returns_tainted.add(i)

        paths = [f.steps for f in collected if f.steps and f.steps[0].kind == "param"]
        if paths:
            result.sink_paths[i] = paths

        # this.cmd = cmd — 이 파라미터가 객체 안에 남는다. 생성자·세터가 이 모양이다.
        if any(tr and tr[0].kind == "param" and _is_field(k)
               for k, tr in out_env.items()):
            result.taints_self.add(i)

    # (3) 수신자가 오염일 때. 호출부에서 obj.m() 의 인자는 비어 있으므로 파라미터
    #     전파로는 절대 안 잡힌다 — 객체를 통째로 오염으로 두고 한 번 더 돌린다.
    #     수신자를 언급조차 않는 함수(대부분이 그렇다)는 결과가 뻔하므로 건너뛴다 —
    #     이 검사가 없으면 함수마다 실행이 한 번씩 더 늘어 요약 계산이 배로 느려진다.
    if not _mentions_receiver(info):
        return result
    collected = []
    ctx = Ctx(rule=rule, src=info.src, out=collected, summaries=summaries, file=info.file)
    step = Step("param", info.fn.loc, f"{info.name}(this)")
    _run(info.fn.body, {r: [step] for r in _RECEIVERS}, ctx)
    result.self_returns = any(tr and tr[0].kind == "param" for tr in ctx.return_traces)
    result.self_sink_paths = [f.steps for f in collected
                              if f.steps and f.steps[0].kind == "param"]
    return result


def _mentions_receiver(info: FuncInfo) -> bool:
    """함수가 this/self 를 한 번이라도 쓰는가.

    안 쓰는 함수(대부분이 그렇다)는 수신자를 오염시켜 돌려 봐야 결과가 같다. 이
    검사가 없으면 함수마다 실행이 한 번 더 늘어 요약 계산이 배로 느려진다. IR 을
    보는 이유는 코틀린·스위프트가 필드를 `this.` 없이 쓰기 때문이다 — 원문에는
    이름만 있고, `this.` 는 정규화기가 붙인다.
    """
    cached = getattr(info, "_uses_receiver", None)
    if cached is None:
        cached = _walk_uses_receiver(info.fn.body)
        info._uses_receiver = cached
    return cached


def _walk_uses_receiver(nodes) -> bool:
    stack = list(nodes)
    while stack:
        n = stack.pop()
        if isinstance(n, ir.Ident):
            if n.name in _RECEIVERS:
                return True
            continue
        for attr in ("target", "value", "obj", "callee", "test", "index"):
            if isinstance(c := getattr(n, attr, None), ir.Node):
                stack.append(c)
        for attr in ("body", "then", "orelse", "args", "children"):
            stack.extend(c for c in (getattr(n, attr, None) or []) if isinstance(c, ir.Node))
    return False


def _is_field(path: str) -> bool:
    """this.cmd / self.cmd / $this->cmd 처럼 객체 안에 남는 경로인가."""
    return any(path.startswith(r + ".") for r in _RECEIVERS)


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

    # 같은 이름의 정의가 여럿이어도 요약이 전부 같으면 수신자를 몰라도 결과는 하나다.
    # 그때만 유일 이름으로 승격한다 — 서로 다르면 그대로 두어 해석하지 않는다.
    # (실측: 파이썬 코퍼스의 doSomething 은 정의가 둘인데 둘 다 인자를 그대로 돌려준다.)
    for name in {k.rsplit("#alt", 1)[0] for k in summaries if "#alt" in k}:
        if unique_name(name) in summaries:
            continue
        found = [summaries[k] for i in range(64)
                 if (k := alt_name(name, i)) in summaries]
        if len(found) > 1 and all(f == found[0] for f in found[1:]):
            summaries[unique_name(name)] = found[0]
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
