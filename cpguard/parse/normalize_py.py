"""Python CST -> IR 정규화.

JS/PHP 와 같은 IR 을 만든다. 세 번째 언어를 붙이면서도 CPG·taint 엔진은 손대지 않는다.

Python 특유 처리
  - 할당은 expression_statement 안의 `assignment` 노드다(문이 아니라 식).
  - 데코레이터가 붙은 함수는 decorated_definition 으로 한 겹 감싸인다.
  - with / try / async 블록은 본문을 펼쳐 흐름을 잇는다.
  - f-string(보간)은 Opaque 로 접어 자식 오염을 합집합 전파한다.
"""
from __future__ import annotations

from tree_sitter import Node as TSNode, Tree

from .. import ir
from .normalize import child_by_field, loc_of, text_of

_LITERALS = {
    "string", "concatenated_string", "integer", "float", "true", "false", "none",
}

_BLOCKISH = {
    "block", "module",
}


def normalize_py(tree: Tree, file: str = "<memory>") -> ir.Module:
    root = tree.root_node
    return ir.Module(loc=loc_of(root, file), body=_block(root.named_children, file))


def _block(nodes, file: str) -> list[ir.Node]:
    out: list[ir.Node] = []
    for n in nodes:
        if n.type == "comment":
            continue
        r = _stmt(n, file)
        if r is None:
            continue
        if isinstance(r, list):
            out.extend(r)
        else:
            out.append(r)
    return out


def _body_of(node: TSNode, file: str) -> list[ir.Node]:
    body = child_by_field(node, "body")
    if body is None:
        return []
    if body.type in _BLOCKISH:
        return _block(body.named_children, file)
    r = _stmt(body, file)
    if r is None:
        return []
    return r if isinstance(r, list) else [r]


# ---------- 문 ----------

def _stmt(node: TSNode, file: str):
    t = node.type

    if t == "expression_statement":
        kids = [c for c in node.named_children if c.type != "comment"]
        if not kids:
            return None
        return [_expr(k, file) for k in kids] if len(kids) > 1 else _expr(kids[0], file)

    if t == "decorated_definition":
        inner = child_by_field(node, "definition")
        return _stmt(inner, file) if inner is not None else None

    if t == "function_definition":
        return _function(node, file)

    if t == "class_definition":
        # 클래스 자체는 오염 대상이 아니고, 안의 메서드만 꺼내 분석한다
        return _body_of(node, file)

    if t == "return_statement":
        kids = [c for c in node.named_children if c.type != "comment"]
        return ir.Return(loc=loc_of(node, file),
                         value=_expr(kids[0], file) if kids else None)

    if t == "if_statement":
        return _if(node, file)

    if t in ("while_statement", "for_statement"):
        return _loop(node, file)

    if t in ("with_statement", "try_statement", "async_statement"):
        # 블록 구조는 흐름만 이어주면 되므로 본문을 펼친다
        out: list[ir.Node] = _body_of(node, file)
        for c in node.named_children:
            if c.type in ("except_clause", "else_clause", "finally_clause"):
                out.extend(_block(c.named_children, file))
        return out

    if t == "block":
        return _block(node.named_children, file)

    return _expr(node, file)


def _function(node: TSNode, file: str) -> ir.Function:
    name_node = child_by_field(node, "name")
    params: list[ir.Param] = []
    params_node = child_by_field(node, "parameters")
    if params_node is not None:
        for p in params_node.named_children:
            if p.type == "comment":
                continue
            # identifier / default_parameter / typed_parameter 모두 이름만 뽑는다
            target = p if p.type == "identifier" else child_by_field(p, "name")
            if target is None:
                target = next((c for c in p.named_children
                               if c.type == "identifier"), None)
            if target is not None:
                params.append(ir.Param(loc=loc_of(target, file), name=text_of(target)))
    return ir.Function(
        loc=loc_of(node, file),
        name=text_of(name_node) if name_node is not None else None,
        params=params,
        body=_body_of(node, file),
    )


def _branch(node: TSNode | None, file: str) -> list[ir.Node]:
    if node is None:
        return []
    if node.type in _BLOCKISH:
        return _block(node.named_children, file)
    if node.type in ("else_clause", "elif_clause"):
        return _body_of(node, file) or _block(node.named_children, file)
    r = _stmt(node, file)
    if r is None:
        return []
    return r if isinstance(r, list) else [r]


def _if(node: TSNode, file: str) -> ir.If:
    cond = child_by_field(node, "condition")
    test = _expr(cond, file) if cond is not None else ir.Opaque(
        loc=loc_of(node, file), kind="missing_condition", children=[])
    orelse: list[ir.Node] = []
    for c in node.named_children:
        if c.type in ("else_clause", "elif_clause"):
            orelse.extend(_branch(c, file))
    # tree-sitter-python 의 if_statement 는 본문 필드가 body 가 아니라 consequence 다.
    # 이걸 body 로 읽으면 then 블록이 통째로 비어 분기 안의 오염을 놓친다.
    return ir.If(loc=loc_of(node, file), test=test,
                 then=_branch(child_by_field(node, "consequence"), file),
                 orelse=orelse)


def _loop(node: TSNode, file: str) -> ir.Loop:
    cond = child_by_field(node, "condition") or child_by_field(node, "right")
    return ir.Loop(loc=loc_of(node, file),
                   test=_expr(cond, file) if cond is not None else None,
                   body=_body_of(node, file))


# ---------- 표현식 ----------

def _expr(node: TSNode, file: str) -> ir.Node:
    t = node.type

    if t == "identifier":
        return ir.Ident(loc=loc_of(node, file), name=text_of(node))

    if t == "attribute":
        obj = child_by_field(node, "object")
        attr = child_by_field(node, "attribute")
        return ir.Member(
            loc=loc_of(node, file),
            obj=_expr(obj, file) if obj is not None else _opaque(node, file),
            prop=text_of(attr) if attr is not None else "",
        )

    if t == "subscript":
        val = child_by_field(node, "value")
        return ir.Member(loc=loc_of(node, file),
                         obj=_expr(val, file) if val is not None else _opaque(node, file),
                         prop="", computed=True)

    if t == "call":
        fn = child_by_field(node, "function")
        args_node = child_by_field(node, "arguments")
        args: list[ir.Node] = []
        if args_node is not None:
            for a in args_node.named_children:
                if a.type == "comment":
                    continue
                # 키워드 인자(shell=True 등)는 값만 취한다
                if a.type == "keyword_argument":
                    v = child_by_field(a, "value")
                    args.append(_expr(v, file) if v is not None else _opaque(a, file))
                else:
                    args.append(_expr(a, file))
        return ir.Call(
            loc=loc_of(node, file),
            callee=_expr(fn, file) if fn is not None else _opaque(node, file),
            args=args,
        )

    if t in ("assignment", "augmented_assignment"):
        left = child_by_field(node, "left")
        right = child_by_field(node, "right")
        op = child_by_field(node, "operator")
        return ir.Assign(
            loc=loc_of(node, file),
            target=_expr(left, file) if left is not None else _opaque(node, file),
            value=_expr(right, file) if right is not None else ir.Literal(
                loc=loc_of(node, file), value=None, raw="None"),
            operator=text_of(op) if op is not None else "=",
        )

    if t in ("lambda",):
        body = child_by_field(node, "body")
        return ir.Function(
            loc=loc_of(node, file), name=None, params=[],
            body=[ir.Return(loc=loc_of(node, file), value=_expr(body, file))]
            if body is not None else [],
        )

    if t in _LITERALS:
        return ir.Literal(loc=loc_of(node, file), value=None, raw=text_of(node))

    if t == "parenthesized_expression":
        kids = [c for c in node.named_children if c.type != "comment"]
        return _expr(kids[0], file) if kids else _opaque(node, file)

    # f-string 보간, 이항연산, 컴프리헨션 등은 Opaque 로 접어 오염을 합집합 전파
    return _opaque(node, file)


def _opaque(node: TSNode, file: str) -> ir.Opaque:
    return ir.Opaque(
        loc=loc_of(node, file), kind=node.type,
        children=[_expr(c, file) for c in node.named_children if c.type != "comment"],
    )
