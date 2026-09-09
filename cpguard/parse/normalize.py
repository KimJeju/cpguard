"""CST -> IR 정규화.

tree-sitter가 만든 언어별 CST를 ir.py의 언어중립 IR로 변환한다.
이 모듈이 "언어 의존성을 흡수하는 방화벽"이다 — 이 위(CPG·taint)는 JS 문법을 모른다.
나중에 Java를 붙일 때(SP2)도 이 파일에 대응하는 normalize_java.py만 새로 쓰면 되고,
CPG·taint 엔진은 그대로 재사용한다.

--------------------------------------------------------------------------
tree-sitter JavaScript 노드 타입 → IR 매핑
--------------------------------------------------------------------------
  program                          → ir.Module(body=[...])
  function_declaration             → ir.Function
      field 'name' / 'parameters' / 'body'
  arrow_function / function_expression → ir.Function(name=None)
      화살표의 축약 본문 (x => x+1) 은 암묵적 return 으로 펼친다
  statement_block                  → 문 리스트로 평탄화
  expression_statement             → 안의 표현식 하나를 문으로
  lexical_declaration / variable_declaration
      → 안의 variable_declarator 각각 → ir.Assign(operator='declare')
        (선언 하나에 declarator 여러 개일 수 있어 list 반환 → _block에서 평탄화)
  assignment_expression            → ir.Assign(operator=원본 연산자)
  member_expression                → ir.Member(obj=재귀, prop=문자열)
  subscript_expression a[b]        → ir.Member(computed=True, prop="")
  call_expression                  → ir.Call(callee=재귀, args=[재귀...])
  identifier / property_identifier → ir.Ident
  string/number/true/false/null    → ir.Literal
  return_statement                 → ir.Return
  if_statement                     → ir.If      (CFG 구축은 M2에서 사용)
  while/for/do                     → ir.Loop    (동상)
  그 외 모르는 노드                 → ir.Opaque(kind, children)  ← 예외 대신 접는다

원칙: 모르는 문법을 만나도 죽지 않는다. Opaque로 접어서 taint 합집합 전파만 유지.
"""
from __future__ import annotations

from tree_sitter import Node as TSNode, Tree

from .. import ir


# ---------- 위치/텍스트 헬퍼 ----------

def loc_of(node: TSNode, file: str) -> ir.Loc:
    sr, sc = node.start_point
    er, ec = node.end_point
    return ir.Loc(
        file=file,
        start_line=sr + 1, start_col=sc,
        end_line=er + 1, end_col=ec,
        start_byte=node.start_byte, end_byte=node.end_byte,
    )


def text_of(node: TSNode) -> str:
    return node.text.decode("utf-8")


def child_by_field(node: TSNode, field: str) -> TSNode | None:
    return node.child_by_field_name(field)


# ---------- 진입점 ----------

def normalize(tree: Tree, file: str = "<memory>", language: str = "javascript") -> ir.Module:
    """CST -> ir.Module. 언어에 맞는 정규화기로 보낸다.

    분석 코어는 이 함수 위쪽만 보므로, 언어가 늘어도 여기서만 갈래가 생긴다.
    마지막에 상수 전파를 한 번 돌려 컴파일 시점에 죽는 분기를 접는다(오탐 감소).
    """
    from .constfold import fold

    if language == "php":
        from .normalize_php import normalize_php
        return fold(normalize_php(tree, file))
    if language == "python":
        from .normalize_py import normalize_py
        return fold(normalize_py(tree, file))
    if language in ("java", "kotlin", "go", "ruby", "cpp", "c", "swift", "csharp"):
        from .normalize_cfam import normalize_cfam
        return fold(normalize_cfam(tree, file, language))
    root = tree.root_node
    return fold(ir.Module(loc=loc_of(root, file), body=_block(root.named_children, file)))


def _block(nodes, file: str) -> list[ir.Node]:
    """문 노드들을 IR로 변환해 평탄한 리스트로 만든다.

    _decl 은 `const a=1, b=2;` 처럼 여러 Assign 을 낼 수 있으므로 여기서 평탄화한다.
    """
    out: list[ir.Node] = []
    for n in nodes:
        r = _stmt(n, file)
        if r is None:
            continue
        if isinstance(r, list):
            out.extend(r)
        else:
            out.append(r)
    return out


# ---------- 문(statement) ----------

def _stmt(node: TSNode, file: str):
    """문 레벨 디스패치. ir.Node 또는 list[ir.Node] 반환."""
    t = node.type

    if t == "expression_statement":
        kids = node.named_children
        return _expr(kids[0], file) if kids else None

    if t in ("lexical_declaration", "variable_declaration"):
        return _decl(node, file)

    if t in ("function_declaration", "generator_function_declaration"):
        return _function(node, file)

    if t == "return_statement":
        return _return(node, file)

    if t == "if_statement":
        return _if(node, file)

    if t in ("while_statement", "for_statement", "for_in_statement", "do_statement"):
        return _loop(node, file)

    if t == "switch_statement":
        return _switch(node, file)

    if t == "statement_block":
        return _block(node.named_children, file)

    # 문인지 표현식인지 애매하면 표현식으로 시도 (최종적으로 Opaque 로 접힘)
    return _expr(node, file)


def _decl(node: TSNode, file: str) -> list[ir.Node]:
    """const/let/var 선언 → ir.Assign(operator='declare') 리스트.

    declarator 의 name 이 구조분해(object_pattern 등)면 target 은 Opaque 가 된다.
    (구조분해 taint 는 후속 과제 — 지금은 죽지 않고 넘어가는 것이 목표)
    """
    out: list[ir.Node] = []
    for d in node.named_children:
        if d.type != "variable_declarator":
            continue
        name_node = child_by_field(d, "name")
        value_node = child_by_field(d, "value")
        if name_node is None:
            continue
        target = _expr(name_node, file)
        if value_node is not None:
            value = _expr(value_node, file)
        else:
            # 초기화 없는 선언(let x;) — undefined 리터럴로 둔다
            value = ir.Literal(loc=loc_of(d, file), value=None, raw="undefined")
        out.append(ir.Assign(loc=loc_of(d, file), target=target, value=value, operator="declare"))
    return out


def _function(node: TSNode, file: str) -> ir.Function:
    """함수 선언/표현식/화살표 → ir.Function."""
    name_node = child_by_field(node, "name")
    name = text_of(name_node) if name_node is not None else None

    params: list[ir.Param] = []
    params_node = child_by_field(node, "parameters")
    if params_node is not None:
        for p in params_node.named_children:
            # identifier 가 보통이지만 기본값·rest·패턴 파라미터도 이름 텍스트로 받아둔다
            params.append(ir.Param(loc=loc_of(p, file), name=text_of(p)))
    else:
        # 화살표 단일 파라미터: x => ...  (parameters 필드 없이 identifier 하나)
        single = child_by_field(node, "parameter")
        if single is not None:
            params.append(ir.Param(loc=loc_of(single, file), name=text_of(single)))

    body_node = child_by_field(node, "body")
    if body_node is None:
        body: list[ir.Node] = []
    elif body_node.type == "statement_block":
        body = _block(body_node.named_children, file)
    else:
        # 화살표 축약 본문: x => x + 1  →  암묵적 return 으로 펼친다
        body = [ir.Return(loc=loc_of(body_node, file), value=_expr(body_node, file))]

    return ir.Function(loc=loc_of(node, file), name=name, params=params, body=body)


def _return(node: TSNode, file: str) -> ir.Return:
    kids = node.named_children
    value = _expr(kids[0], file) if kids else None
    return ir.Return(loc=loc_of(node, file), value=value)


def _if(node: TSNode, file: str) -> ir.If:
    """조건문 → ir.If. 분기 조건은 taint 전파 대상이 아니지만 CFG(M2)에 필요."""
    test_node = child_by_field(node, "condition")
    test = _expr(test_node, file) if test_node is not None else ir.Opaque(
        loc=loc_of(node, file), kind="missing_condition", children=[]
    )
    cons = child_by_field(node, "consequence")
    alt = child_by_field(node, "alternative")
    return ir.If(
        loc=loc_of(node, file),
        test=test,
        then=_branch(cons, file),
        orelse=_branch(alt, file),
    )


def _loop(node: TSNode, file: str) -> ir.Loop:
    """while/for/do → ir.Loop (조건 유무는 문법마다 다름)."""
    test_node = child_by_field(node, "condition")
    body = _branch(child_by_field(node, "body"), file)
    # for (const x of 오염) — 반복 변수를 대상에 묶지 않으면 본문이 통째로 미탐이다.
    # 원소를 구분하지 않는 과대근사로, 컨테이너를 통째로 오염으로 보는 모델과 같은 기준.
    tgt, src = child_by_field(node, "left"), child_by_field(node, "right")
    if tgt is not None and src is not None:
        body.insert(0, ir.Assign(loc=loc_of(tgt, file), target=_expr(tgt, file),
                                 value=_expr(src, file)))
    test = _expr(test_node, file) if test_node is not None else None
    return ir.Loop(loc=loc_of(node, file), test=test, body=body)


def _switch(node: TSNode, file: str) -> list[ir.Node]:
    """switch → if/else 사슬.

    case 본문을 순서대로 이어 붙이면 서로 배타적인 분기가 순차 실행처럼 보여,
    뒤 분기의 안전한 대입이 앞 분기에서 담긴 오염을 지운다. 조건을 `대상 == 라벨`
    로 만들어 두면 선택자가 상수일 때 constfold 가 죽은 가지도 지운다.
    """
    subj = child_by_field(node, "value")
    body = child_by_field(node, "body")
    groups = [c for c in (body.named_children if body is not None else [])
              if c.type in ("switch_case", "switch_default")]
    if not groups:
        return _branch(body, file)

    default: list[ir.Node] = []
    cases: list[tuple[ir.Node, list[ir.Node]]] = []
    pending: list[TSNode] = []       # 라벨만 있고 본문이 없는 그룹(fall-through)
    for g in groups:
        val = child_by_field(g, "value")
        stmts = _block([c for c in g.named_children
                        if val is None or c.start_byte != val.start_byte], file)
        if not stmts:
            if val is not None:
                pending.append(val)
            continue
        if g.type == "switch_default":
            default = stmts
            pending = []
            continue
        cases.append((_case_test(subj, pending + [val] if val is not None else pending,
                                 node, file), stmts))
        pending = []

    chain: list[ir.Node] = default
    for test, stmts in reversed(cases):
        chain = [ir.If(loc=loc_of(node, file), test=test, then=stmts, orelse=chain)]
    return chain


def _case_test(subj: TSNode | None, vals: list[TSNode], node: TSNode, file: str) -> ir.Node:
    """`대상 == 라벨1 || 대상 == 라벨2 ...`. 대상이 없으면 접을 수 없는 값을 둔다."""
    if subj is None or not vals:
        return ir.Opaque(loc=loc_of(node, file), kind="switch_case_test", children=[])
    out: ir.Node | None = None
    for v in vals:
        cmp_ = ir.Binary(loc=loc_of(v, file), op="==",
                         children=[_expr(subj, file), _expr(v, file)])
        out = cmp_ if out is None else ir.Binary(
            loc=loc_of(v, file), op="||", children=[out, cmp_])
    return out


def _branch(node: TSNode | None, file: str) -> list[ir.Node]:
    """if/loop 의 본문 자리 — 블록이면 펼치고, 단일 문이면 리스트로 감싼다."""
    if node is None:
        return []
    if node.type == "statement_block":
        return _block(node.named_children, file)
    if node.type == "else_clause":
        kids = node.named_children
        return _branch(kids[0], file) if kids else []
    r = _stmt(node, file)
    if r is None:
        return []
    return r if isinstance(r, list) else [r]


# ---------- 표현식 ----------

def _expr(node: TSNode, file: str) -> ir.Node:
    """표현식 레벨 디스패치."""
    t = node.type

    if t in ("identifier", "property_identifier", "shorthand_property_identifier"):
        return ir.Ident(loc=loc_of(node, file), name=text_of(node))

    if t == "member_expression":
        # a.b : object 는 재귀, property 는 문자열로 흡수
        obj = _expr(child_by_field(node, "object"), file)
        prop_node = child_by_field(node, "property")
        prop = text_of(prop_node) if prop_node is not None else ""
        return ir.Member(loc=loc_of(node, file), obj=obj, prop=prop)

    if t == "subscript_expression":
        # a[expr] : prop 을 특정할 수 없어 computed. 인덱스가 상수면 엔진이 슬롯을
        # 구분할 수 있으므로 버리지 않고 실어 보낸다.
        obj = _expr(child_by_field(node, "object"), file)
        idx = child_by_field(node, "index")
        return ir.Member(loc=loc_of(node, file), obj=obj, prop="", computed=True,
                         index=_expr(idx, file) if idx is not None else None)

    if t == "call_expression":
        # f(a, b) : function=callee(재귀), arguments 의 named children=args(각각 재귀)
        callee = _expr(child_by_field(node, "function"), file)
        arg_list = child_by_field(node, "arguments")
        args = [_expr(a, file) for a in arg_list.named_children] if arg_list is not None else []
        return ir.Call(loc=loc_of(node, file), callee=callee, args=args)

    if t in ("assignment_expression", "augmented_assignment_expression"):
        left = child_by_field(node, "left")
        right = child_by_field(node, "right")
        op_node = child_by_field(node, "operator")
        return ir.Assign(
            loc=loc_of(node, file),
            target=_expr(left, file),
            value=_expr(right, file),
            operator=text_of(op_node) if op_node is not None else "=",
        )

    if t in ("arrow_function", "function_expression", "generator_function"):
        return _function(node, file)

    if t == "template_string" and any(c.type == "template_substitution"
                                     for c in node.named_children):
        # `x${p}` — 보간이 든 템플릿은 상수가 아니다. 리터럴로 접으면 안에 담긴
        # 오염이 밖으로 나오지 못한다(파이썬 f-string 과 같은 계열의 미탐).
        return _opaque(node, file)

    if t in ("string", "template_string", "number", "true", "false", "null", "undefined", "regex"):
        return ir.Literal(loc=loc_of(node, file), value=None, raw=text_of(node))

    if t == "binary_expression":
        left, right = child_by_field(node, "left"), child_by_field(node, "right")
        op = child_by_field(node, "operator")
        if left is not None and right is not None:
            return ir.Binary(loc=loc_of(node, file),
                             op=text_of(op) if op is not None else "",
                             children=[_expr(left, file), _expr(right, file)])

    if t == "unary_expression":
        arg = child_by_field(node, "argument")
        op = child_by_field(node, "operator")
        if arg is not None:
            return ir.Unary(loc=loc_of(node, file),
                            op=text_of(op) if op is not None else "!",
                            children=[_expr(arg, file)])

    if t == "ternary_expression":
        cond = child_by_field(node, "condition")
        con = child_by_field(node, "consequence")
        alt = child_by_field(node, "alternative")
        if cond is not None and con is not None and alt is not None:
            return ir.Ternary(loc=loc_of(node, file),
                              children=[_expr(cond, file), _expr(con, file),
                                        _expr(alt, file)])

    if t == "parenthesized_expression":
        kids = node.named_children
        return _expr(kids[0], file) if kids else _opaque(node, file)

    # 모르는 노드 → Opaque (자식 표현식들을 담아 taint 합집합 전파만 가능하게)
    return _opaque(node, file)


def _opaque(node: TSNode, file: str) -> ir.Opaque:
    return ir.Opaque(
        loc=loc_of(node, file),
        kind=node.type,
        children=[_expr(c, file) for c in node.named_children],
    )
