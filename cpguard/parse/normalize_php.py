"""PHP CST -> IR 정규화.

JS/TS 용 normalize.py 와 같은 IR 을 만든다. CPG·taint 엔진은 이 파일의 존재를 모르며,
언어가 늘어나도 코어는 그대로다 — 언어중립 IR 설계가 실제로 값을 하는 지점이다.

PHP 특유 처리
  - 변수는 `$x` 형태(variable_name)이며 이름에 $ 를 포함한 채로 둔다.
    오염 시작점이 `$_GET` / `$_POST` 같은 슈퍼글로벌이라 이름이 그대로여야 매칭된다.
  - echo / print / include / require / 백틱은 문법상 호출이 아니지만,
    위험 지점 판정을 호출 하나로 통일하기 위해 Call 노드로 정규화한다.
  - arguments 의 자식은 argument 래퍼이므로 한 겹 벗긴다.
"""
from __future__ import annotations

from tree_sitter import Node as TSNode, Tree

from .. import ir
from .normalize import child_by_field, loc_of, text_of

# 문법상 호출이 아니지만 위험 지점이 될 수 있어 Call 로 정규화하는 구문
_AS_CALL = {
    "echo_statement": "echo",
    "print_intrinsic": "print",
    "include_expression": "include",
    "include_once_expression": "include_once",
    "require_expression": "require",
    "require_once_expression": "require_once",
    "exit_statement": "exit",
    "shell_command_expression": "shell_exec",   # `cmd` 백틱
    "unset_statement": "unset",
}

_LITERALS = {
    "string", "integer", "float", "boolean", "null",
    "heredoc", "nowdoc", "shell_command_expression_literal",
}


def normalize_php(tree: Tree, file: str = "<memory>") -> ir.Module:
    root = tree.root_node
    return ir.Module(loc=loc_of(root, file), body=_block(root.named_children, file))


def _block(nodes, file: str) -> list[ir.Node]:
    out: list[ir.Node] = []
    for n in nodes:
        if n.type in ("php_tag", "text_interpolation", "comment"):
            continue
        r = _stmt(n, file)
        if r is None:
            continue
        if isinstance(r, list):
            out.extend(r)
        else:
            out.append(r)
    return out


# ---------- 문 ----------

def _stmt(node: TSNode, file: str):
    t = node.type

    if t == "expression_statement":
        kids = [c for c in node.named_children if c.type != "comment"]
        return _expr(kids[0], file) if kids else None

    if t in ("function_definition", "method_declaration", "function_static_declaration"):
        return _function(node, file)

    if t in ("class_declaration", "interface_declaration", "trait_declaration",
             "namespace_definition"):
        # 선언 자체는 taint 대상이 아니고, 안의 메서드만 꺼내 분석한다
        body = child_by_field(node, "body")
        return _block(body.named_children, file) if body is not None else None

    if t == "compound_statement":
        return _block(node.named_children, file)

    if t == "return_statement":
        kids = [c for c in node.named_children if c.type != "comment"]
        value = _expr(kids[0], file) if kids else None
        return ir.Return(loc=loc_of(node, file), value=value)

    if t == "if_statement":
        return _if(node, file)

    if t in ("while_statement", "for_statement", "foreach_statement",
             "do_statement"):
        return _loop(node, file)

    if t == "switch_statement":
        return _switch(node, file)

    if t in ("try_statement", "catch_clause", "finally_clause"):
        body = child_by_field(node, "body") or node
        return _block([c for c in body.named_children], file)

    return _expr(node, file)


def _function(node: TSNode, file: str) -> ir.Function:
    name_node = child_by_field(node, "name")
    name = text_of(name_node) if name_node is not None else None

    params: list[ir.Param] = []
    params_node = child_by_field(node, "parameters")
    if params_node is not None:
        for p in params_node.named_children:
            var = child_by_field(p, "name")
            # simple_parameter 의 이름은 variable_name($x) 이다
            if var is None:
                var = next((c for c in p.named_children if c.type == "variable_name"), None)
            if var is not None:
                params.append(ir.Param(loc=loc_of(var, file), name=text_of(var)))

    body_node = child_by_field(node, "body")
    body = _block(body_node.named_children, file) if body_node is not None else []
    return ir.Function(loc=loc_of(node, file), name=name, params=params, body=body)


def _branch(node: TSNode | None, file: str) -> list[ir.Node]:
    if node is None:
        return []

    if node.type in ("compound_statement", "else_clause", "else_if_clause"):
        inner = child_by_field(node, "body")
        target = inner if inner is not None else node
        return _block(target.named_children, file)

    if node.type in ("case_statement", "default_statement"):
        return _block(node.named_children, file)

    r = _stmt(node, file)
    if r is None:
        return []
    return r if isinstance(r, list) else [r]


def _switch(node: TSNode, file: str) -> list[ir.Node]:
    """switch → if/else 사슬.

    case 본문을 순서대로 이어 붙이면 서로 배타적인 분기가 순차 실행처럼 보여, 뒤
    분기의 안전한 대입이 앞 분기에서 담긴 오염을 지운다. 조건을 `대상 == 라벨` 로
    두면 선택자가 상수일 때 constfold 가 죽은 가지도 지운다.
    """
    subj = child_by_field(node, "condition")
    body = child_by_field(node, "body")
    groups = [c for c in (body.named_children if body is not None else [])
              if c.type in ("case_statement", "default_statement")]
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
        if g.type == "default_statement":
            default, pending = stmts, []
            continue
        vals = pending + [val] if val is not None else pending
        cases.append((_case_test(subj, vals, node, file), stmts))
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


def _if(node: TSNode, file: str) -> ir.If:
    cond = child_by_field(node, "condition")
    test = _expr(cond, file) if cond is not None else ir.Opaque(
        loc=loc_of(node, file), kind="missing_condition", children=[])
    return ir.If(
        loc=loc_of(node, file), test=test,
        then=_branch(child_by_field(node, "body"), file),
        orelse=_branch(child_by_field(node, "alternative"), file),
    )


def _loop(node: TSNode, file: str) -> ir.Loop:
    cond = child_by_field(node, "condition")
    body_node = child_by_field(node, "body")
    body = _branch(body_node, file)
    if node.type == "foreach_statement":
        # foreach ($오염 as $x) — 반복 변수를 대상에 묶지 않으면 본문이 통째로
        # 미탐이다. 원소를 구분하지 않는 과대근사(컨테이너 모델과 같은 기준).
        kids = [c for c in node.named_children
                if c.type != "comment"
                and (body_node is None or c.start_byte != body_node.start_byte)]
        if len(kids) >= 2:
            tgt = kids[1]
            if tgt.type == "pair":          # `$k => $v` 는 값 쪽이 원소다
                pk = [c for c in tgt.named_children if c.type != "comment"]
                tgt = pk[-1] if pk else tgt
            body.insert(0, ir.Assign(loc=loc_of(tgt, file), target=_expr(tgt, file),
                                     value=_expr(kids[0], file)))
    return ir.Loop(
        loc=loc_of(node, file),
        test=_expr(cond, file) if cond is not None else None,
        body=body,
    )


# ---------- 표현식 ----------

def _args(node: TSNode | None, file: str) -> list[ir.Node]:
    """arguments 노드에서 argument 래퍼를 벗겨 실제 표현식만 뽑는다."""
    if node is None:
        return []
    out: list[ir.Node] = []
    for a in node.named_children:
        if a.type == "argument":
            kids = [c for c in a.named_children if c.type != "comment"]
            if kids:
                out.append(_expr(kids[0], file))
        elif a.type != "comment":
            out.append(_expr(a, file))
    return out


def _expr(node: TSNode, file: str) -> ir.Node:
    t = node.type

    if t in ("variable_name", "name", "qualified_name"):
        return ir.Ident(loc=loc_of(node, file), name=text_of(node))

    if t == "subscript_expression":
        # $a['키'] : prop 은 특정 못 하지만 인덱스가 상수면 엔진이 슬롯을 구분한다.
        kids = [c for c in node.named_children if c.type != "comment"]
        obj_node = child_by_field(node, "object") or (kids[0] if kids else None)
        idx = child_by_field(node, "index")
        if idx is None and obj_node is not None:
            idx = next((c for c in kids if c.start_byte != obj_node.start_byte), None)
        return ir.Member(
            loc=loc_of(node, file),
            obj=_expr(obj_node, file) if obj_node is not None else _opaque(node, file),
            prop="", computed=True,
            index=_expr(idx, file) if idx is not None else None)

    if t in ("member_access_expression", "nullsafe_member_access_expression",
             "scoped_property_access_expression"):
        obj_node = child_by_field(node, "object") or child_by_field(node, "scope")
        prop_node = child_by_field(node, "name")
        obj = _expr(obj_node, file) if obj_node is not None else ir.Opaque(
            loc=loc_of(node, file), kind=t, children=[])
        prop = text_of(prop_node) if prop_node is not None else ""
        return ir.Member(loc=loc_of(node, file), obj=obj, prop=prop)

    if t in ("function_call_expression", "member_call_expression",
             "nullsafe_member_call_expression", "scoped_call_expression",
             "object_creation_expression"):
        fn_node = child_by_field(node, "function")
        if fn_node is None:
            # 메서드 호출: object + name 을 멤버 접근으로 합성
            obj_node = child_by_field(node, "object") or child_by_field(node, "scope")
            name_node = child_by_field(node, "name")
            if obj_node is not None and name_node is not None:
                callee = ir.Member(loc=loc_of(node, file), obj=_expr(obj_node, file),
                                   prop=text_of(name_node))
            elif name_node is not None:
                callee = _expr(name_node, file)
            else:
                callee = ir.Opaque(loc=loc_of(node, file), kind=t, children=[])
        else:
            callee = _expr(fn_node, file)
        return ir.Call(loc=loc_of(node, file), callee=callee,
                       args=_args(child_by_field(node, "arguments"), file))

    if t in _AS_CALL:
        # echo / include / 백틱 등을 호출로 정규화해 위험 지점 판정을 통일한다
        args = [_expr(c, file) for c in node.named_children if c.type != "comment"]
        return ir.Call(
            loc=loc_of(node, file),
            callee=ir.Ident(loc=loc_of(node, file), name=_AS_CALL[t]),
            args=args,
        )

    if t == "assignment_expression" or t == "augmented_assignment_expression":
        left = child_by_field(node, "left")
        right = child_by_field(node, "right")
        op_node = child_by_field(node, "operator")
        return ir.Assign(
            loc=loc_of(node, file),
            target=_expr(left, file) if left is not None else ir.Opaque(
                loc=loc_of(node, file), kind="missing_target", children=[]),
            value=_expr(right, file) if right is not None else ir.Literal(
                loc=loc_of(node, file), value=None, raw="null"),
            operator=text_of(op_node) if op_node is not None else "=",
        )

    if t in ("anonymous_function_creation_expression", "arrow_function",
             "anonymous_function"):
        return _function(node, file)

    if t == "encapsed_string" and not any(
            c.type != "string_content" for c in node.named_children):
        # 보간이 없는 "..." 는 상수다. Opaque 로 두면 첨자 키도 분기 조건도 접히지
        # 않는다. 보간이 든 경우는 아래 Opaque 로 떨어져 오염이 합집합 전파된다.
        return ir.Literal(loc=loc_of(node, file), value=None, raw=text_of(node))

    if t in _LITERALS:
        return ir.Literal(loc=loc_of(node, file), value=None, raw=text_of(node))

    # 상수 전파가 죽은 가지를 지우려면 연산자와 조건식이 IR 에 남아 있어야 한다.
    if t == "binary_expression":
        left, right = child_by_field(node, "left"), child_by_field(node, "right")
        op = child_by_field(node, "operator")
        if left is not None and right is not None:
            return ir.Binary(loc=loc_of(node, file),
                             op=text_of(op) if op is not None else "",
                             children=[_expr(left, file), _expr(right, file)])

    if t == "unary_op_expression":
        kids = [c for c in node.named_children if c.type != "comment"]
        op = child_by_field(node, "operator")
        if kids:
            return ir.Unary(loc=loc_of(node, file),
                            op=text_of(op) if op is not None else "!",
                            children=[_expr(kids[-1], file)])

    if t == "conditional_expression":
        cond = child_by_field(node, "condition")
        con = child_by_field(node, "body")
        alt = child_by_field(node, "alternative")
        if cond is not None and alt is not None:
            return ir.Ternary(
                loc=loc_of(node, file),
                children=[_expr(cond, file),
                          _expr(con, file) if con is not None else _expr(cond, file),
                          _expr(alt, file)])

    if t == "parenthesized_expression":
        kids = [c for c in node.named_children if c.type != "comment"]
        return _expr(kids[0], file) if kids else _opaque(node, file)

    # 문자열 결합(binary_expression), 보간 문자열(encapsed_string) 등은
    # Opaque 로 접어 자식들의 오염을 합집합으로 전파한다.
    return _opaque(node, file)


def _opaque(node: TSNode, file: str) -> ir.Opaque:
    return ir.Opaque(
        loc=loc_of(node, file), kind=node.type,
        children=[_expr(c, file) for c in node.named_children if c.type != "comment"],
    )
