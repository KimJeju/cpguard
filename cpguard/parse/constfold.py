"""상수 전파 — 컴파일 시점에 결과가 정해지는 분기를 접는다.

왜 필요한가
-----------
taint 엔진은 경로 민감도가 없다. 분기 조건의 참거짓을 해석하지 않고 양쪽을 모두
가능하다고 보는데(건전한 과대근사), 그래서 아래 같은 코드를 오탐으로 낸다.

    int num = 86;
    if ((7 * 42) - num > 200) bar = "안전한 상수";
    else                      bar = param;      // 실행되지 않는 가지
    exec(bar);

OWASP Benchmark 의 안전 케이스 753건 중 347건(46%)이 정확히 이 형태다. 조건이
상수로 접히면 죽은 가지를 지울 수 있고, 그만큼 오탐이 사라진다.

무엇을 접는가 (보수적으로)
--------------------------
- 한 스코프(함수 본문 / 모듈 최상위) 안에서 **정확히 한 번만 대입되고 그 값이
  상수인 이름**만 상수로 본다. 두 번 이상 대입되면 어느 값인지 알 수 없으므로 포기한다.
- 파라미터는 호출자가 정하므로 상수가 아니다.
- 선언보다 앞선 사용을 상수로 접지 않도록 전위 순회 순서대로 표를 채운다.
- 나눗셈 0, 타입이 안 맞는 연산 등 조금이라도 애매하면 접지 않는다(모르면 그대로 둔다).

접기 자체는 IR 을 제자리에서 고친다. If 는 죽은 가지를 비우고, Ternary 는 살아남은
가지 하나만 남긴다(엔진은 Ternary 의 children 합집합으로 오염을 전파하므로,
children 이 하나면 그 가지만 전파된다).
"""
from __future__ import annotations

import operator as _op
from collections import Counter

from .. import ir

_UNK = object()   # "상수가 아님/모르겠음" 표식 (None 은 null 리터럴의 값이라 못 쓴다)

_BIN = {
    "+": _op.add, "-": _op.sub, "*": _op.mul, "%": _op.mod,
    "<": _op.lt, ">": _op.gt, "<=": _op.le, ">=": _op.ge,
    "==": _op.eq, "!=": _op.ne,
    "&": _op.and_, "|": _op.or_, "^": _op.xor, "<<": _op.lshift, ">>": _op.rshift,
    "&&": lambda a, b: bool(a) and bool(b), "||": lambda a, b: bool(a) or bool(b),
    "and": lambda a, b: bool(a) and bool(b), "or": lambda a, b: bool(a) or bool(b),
}
_UN = {"!": lambda v: not bool(v), "not": lambda v: not bool(v),
       "-": _op.neg, "+": _op.pos, "~": _op.invert, "bang": lambda v: not bool(v)}

_INT_SUFFIX = "lLuUfFdD"


def _literal_value(node: ir.Literal):
    """리터럴 원문에서 파이썬 값. 확신이 없으면 _UNK."""
    if node.value is not None:
        return node.value
    raw = (node.raw or "").strip()
    if not raw:
        return _UNK
    low = raw.lower()
    if low in ("true",):
        return True
    if low in ("false",):
        return False
    if low in ("null", "nil", "none"):
        return None
    if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
        return raw[1:-1]
    num = raw.rstrip(_INT_SUFFIX).replace("_", "")
    try:
        if num[:2].lower() in ("0x", "0b", "0o"):
            return int(num, 0)
        if "." in num or "e" in num.lower():
            return float(num)
        return int(num)
    except ValueError:
        return _UNK


def _eval(node: ir.Node, consts: dict[str, object]):
    if isinstance(node, ir.Literal):
        return _literal_value(node)

    if isinstance(node, ir.Ident):
        return consts.get(node.name, _UNK)

    if isinstance(node, ir.Binary):
        fn = _BIN.get(node.op)
        if fn is None or len(node.children) != 2:
            return _UNK
        a = _eval(node.children[0], consts)
        b = _eval(node.children[1], consts)
        if a is _UNK or b is _UNK:
            return _UNK
        try:
            return fn(a, b)
        except Exception:
            return _UNK          # 0 나누기·타입 불일치 등 → 모르는 것으로

    if isinstance(node, ir.Unary):
        fn = _UN.get(node.op)
        if fn is None or len(node.children) != 1:
            return _UNK
        v = _eval(node.children[0], consts)
        if v is _UNK:
            return _UNK
        try:
            return fn(v)
        except Exception:
            return _UNK

    if isinstance(node, ir.Member) and node.computed and node.index is not None:
        # "ABC"[1] — 리터럴 문자열/리스트를 상수 인덱스로 읽는 것은 컴파일 시점에 정해진다.
        base = _eval(node.obj, consts)
        idx = _eval(node.index, consts)
        if base is _UNK or idx is _UNK or not isinstance(idx, int):
            return _UNK
        try:
            return base[idx]
        except Exception:
            return _UNK

    if isinstance(node, ir.Call):
        # "ABC".charAt(1) — 자바에서 같은 자리를 차지하는 형태.
        callee = node.callee
        if (isinstance(callee, ir.Member) and callee.prop in ("charAt", "substring")
                and node.args):
            base = _eval(callee.obj, consts)
            args = [_eval(a, consts) for a in node.args]
            if base is _UNK or any(a is _UNK for a in args) or not isinstance(base, str):
                return _UNK
            try:
                if callee.prop == "charAt":
                    return base[args[0]]
                return base[args[0]:args[1]] if len(args) > 1 else base[args[0]:]
            except Exception:
                return _UNK
        return _UNK

    if isinstance(node, ir.Opaque):
        # 자바 등에서 문자열 리터럴은 조각을 자식으로 가진 래퍼로 온다. 조각의 원문이
        # 곧 값이다(따옴표가 벗겨진 채로 오므로 리터럴 파서로는 숫자로 오인한다).
        # 파이썬의 보간 f-string 은 kind 가 'string' 이라 여기 걸리지 않는다 — 접으면 안 된다.
        if node.kind in ("string_literal", "raw_string_literal", "interpreted_string_literal"):
            if all(isinstance(c, ir.Literal) for c in node.children):
                return "".join(str(c.raw or "") for c in node.children)
            return _UNK
        # 괄호처럼 자식 하나만 감싼 래퍼는 그 자식이 값이다. 그 외는 모른다.
        kids = [c for c in node.children if not isinstance(c, ir.Literal) or (c.raw or "").strip()]
        if len(node.children) == 1:
            return _eval(node.children[0], consts)
        if node.kind in ("parenthesized_expression", "parenthesized_statements",
                         "tuple_expression") and kids:
            return _eval(kids[0], consts)
        return _UNK

    if isinstance(node, ir.Ternary) and len(node.children) == 1:
        return _eval(node.children[0], consts)

    return _UNK


def _truth(v):
    """분기 판정에 쓸 수 있는 값이면 True/False, 아니면 None(=판정 불가)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):        # C 계열의 if (0) / if (1)
        return v != 0
    return None


# ---------- IR 순회 ----------

def _kids(node: ir.Node):
    """이 노드가 직접 품은 하위 노드들(문·식 구분 없이)."""
    if node is None:
        return
    for attr in ("body", "then", "orelse", "children", "args", "params"):
        v = getattr(node, attr, None)
        if isinstance(v, list):
            yield from (x for x in v if isinstance(x, ir.Node))
    for attr in ("value", "target", "callee", "obj", "test"):
        v = getattr(node, attr, None)
        if isinstance(v, ir.Node):
            yield v


def _walk_scope(nodes):
    """스코프 안 전위 순회. 중첩 함수는 별도 스코프이므로 들어가지 않는다."""
    for n in nodes:
        if isinstance(n, ir.Function):
            continue
        yield n
        yield from _walk_scope(list(_kids(n)))


def _simple_name(node: ir.Node) -> str | None:
    return node.name if isinstance(node, ir.Ident) else None


def _fold_scope(body: list[ir.Node], params: list[str]) -> None:
    # (1) 이름별 대입 횟수. 두 번 이상이면 값을 특정할 수 없다.
    counts = Counter({p: 2 for p in params})         # 파라미터는 호출자가 정한다 → 상수 아님
    for n in _walk_scope(body):
        if isinstance(n, ir.Assign):
            name = _simple_name(n.target)
            if name:
                counts[name] += 1

    # (2) 전위 순회하며 상수표를 채우고, 그 시점 표로 분기를 접는다.
    consts: dict[str, object] = {}
    for n in _walk_scope(body):
        if isinstance(n, ir.Assign):
            name = _simple_name(n.target)
            if name and counts.get(name) == 1:
                v = _eval(n.value, consts)
                if v is not _UNK:
                    consts[name] = v
            continue

        if isinstance(n, ir.If):
            t = _truth(_eval(n.test, consts))
            if t is True:
                n.orelse = []
            elif t is False:
                n.then = []
            continue

        if isinstance(n, ir.Ternary) and len(n.children) == 3:
            t = _truth(_eval(n.children[0], consts))
            if t is not None:
                n.children = [n.children[1] if t else n.children[2]]


def _functions(nodes):
    for n in nodes:
        if isinstance(n, ir.Function):
            yield n
            yield from _functions(list(_kids(n)))
        else:
            yield from _functions(list(_kids(n)))


def fold(module: ir.Module) -> ir.Module:
    """모듈의 모든 스코프에서 상수 분기를 접는다. IR 을 제자리에서 고치고 그대로 돌려준다."""
    _fold_scope(module.body, [])
    for fn in _functions(module.body):
        _fold_scope(fn.body, [p.name for p in fn.params])
    return module
