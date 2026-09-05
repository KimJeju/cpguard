"""C-계열·기타 언어 CST -> IR 정규화 (Java · Kotlin · Go · C/C++ · Swift · C# · Ruby).

언어마다 정규화기를 복붙하지 않고, "이 언어에서 호출/멤버/할당/함수/반환/분기/반복이
어떤 노드·필드 이름인가" 만 표(LANG)로 두고 하나의 워커가 돈다. IR·CPG·taint 엔진은
그대로다(ir.py 의 설계 경계).

필드 이름은 tree-sitter 문법을 실제로 파싱해 확인한 값이다(CST 프로브). Kotlin·Swift 는
필드가 거의 없어 위치(named_children 순서) 기반으로 읽는다. 모르는 노드는 Opaque 로
접어 자식 오염을 합집합 전파한다 — 놓치는 쪽(FN)보다 과대근사(FP)를 택한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Node as TSNode, Tree

from .. import ir
from .normalize import child_by_field, loc_of, text_of


@dataclass
class Spec:
    """언어별 노드/필드 이름표."""
    call: str                      # 호출 노드
    call_fn: str | None            # 호출 대상 필드(없으면 첫 named child)
    call_args: str | None          # 인자 컨테이너 필드(없으면 인자 컨테이너 타입으로 찾음)
    args_types: tuple[str, ...]    # 인자 컨테이너 노드 타입들
    member: str                    # 멤버 접근 노드
    member_obj: str | None         # 객체 필드(없으면 첫 named child)
    member_prop: str | None        # 속성 필드(없으면 마지막 named child; suffix 래퍼면 그 안)
    subscript: tuple[str, ...]     # a[i] 노드들 (computed member)
    subscript_obj: str | None
    assign: tuple[str, ...]        # 할당 노드
    assign_left: str | None
    assign_right: str | None
    decl: tuple[str, ...]          # 선언 초기화 노드(변수 선언)
    decl_name: str | None          # 선언의 이름 필드(없으면 첫 identifier)
    decl_value: str | None         # 선언의 값 필드(없으면 마지막 named child)
    func: tuple[str, ...]          # 함수/메서드 정의 노드
    func_name: str | None
    func_params: str | None        # 파라미터 컨테이너 필드(없으면 타입으로 찾음)
    params_types: tuple[str, ...]  # 파라미터 컨테이너 노드 타입
    param_name: str | None         # 파라미터 노드의 이름 필드(없으면 첫 identifier)
    func_body: str | None
    ret: tuple[str, ...]           # 반환 노드
    if_: str
    if_cond: str | None
    if_then: str | None
    if_else: str | None
    loops: tuple[str, ...]
    block: tuple[str, ...]         # 본문 컨테이너(펼침)
    idents: tuple[str, ...]        # 식별자 노드 타입
    literals: tuple[str, ...]
    descend: tuple[str, ...] = field(default_factory=tuple)   # 클래스 등: 본문만 꺼내 분석
    wrap: tuple[str, ...] = ("expression_statement",)         # 식을 감싼 문 노드(펼침)
    unwrap_decl: tuple[str, ...] = field(default_factory=tuple)  # C 의 pointer_declarator 등


_ID = ("identifier",)
_LIT_COMMON = ("string", "string_literal", "number", "number_literal", "integer", "float",
               "true", "false", "null", "nil", "none", "character_literal", "char_literal",
               "decimal_integer_literal", "hex_integer_literal", "string_fragment",
               "interpreted_string_literal", "raw_string_literal", "rune_literal",
               "int_literal", "float_literal", "line_string_literal", "boolean_literal",
               "null_literal", "real_literal", "integer_literal", "simple_symbol", "constant")

LANG: dict[str, Spec] = {
    "java": Spec(
        call="method_invocation", call_fn=None, call_args="arguments", args_types=("argument_list",),
        member="field_access", member_obj="object", member_prop="field",
        subscript=("array_access",), subscript_obj="array",
        assign=("assignment_expression",), assign_left="left", assign_right="right",
        decl=("variable_declarator",), decl_name="name", decl_value="value",
        func=("method_declaration", "constructor_declaration", "lambda_expression"),
        func_name="name", func_params="parameters", params_types=("formal_parameters", "inferred_parameters"),
        param_name="name", func_body="body",
        ret=("return_statement",),
        if_="if_statement", if_cond="condition", if_then="consequence", if_else="alternative",
        loops=("while_statement", "for_statement", "enhanced_for_statement", "do_statement"),
        block=("block", "program", "class_body", "local_variable_declaration", "constructor_body"),
        idents=_ID, literals=_LIT_COMMON,
        descend=("class_declaration", "interface_declaration", "enum_declaration"),
    ),
    "csharp": Spec(
        call="invocation_expression", call_fn="function", call_args="arguments", args_types=("argument_list",),
        member="member_access_expression", member_obj="expression", member_prop="name",
        subscript=("element_access_expression",), subscript_obj="expression",
        assign=("assignment_expression",), assign_left="left", assign_right="right",
        decl=("variable_declarator",), decl_name="name", decl_value=None,
        func=("method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression"),
        func_name="name", func_params="parameters", params_types=("parameter_list",),
        param_name="name", func_body="body",
        ret=("return_statement",),
        if_="if_statement", if_cond="condition", if_then="consequence", if_else="alternative",
        loops=("while_statement", "for_statement", "foreach_statement", "do_statement"),
        block=("block", "compilation_unit", "declaration_list", "local_declaration_statement",
               "variable_declaration", "namespace_declaration", "file_scoped_namespace_declaration"),
        idents=_ID, literals=_LIT_COMMON + ("verbatim_string_literal", "interpolated_string_expression"),
        descend=("class_declaration", "struct_declaration", "interface_declaration", "record_declaration"),
    ),
    "go": Spec(
        call="call_expression", call_fn="function", call_args="arguments", args_types=("argument_list",),
        member="selector_expression", member_obj="operand", member_prop="field",
        subscript=("index_expression",), subscript_obj="operand",
        assign=("assignment_statement", "short_var_declaration"), assign_left="left", assign_right="right",
        decl=("var_spec", "const_spec"), decl_name="name", decl_value="value",
        func=("function_declaration", "method_declaration", "func_literal"),
        func_name="name", func_params="parameters", params_types=("parameter_list",),
        param_name="name", func_body="body",
        ret=("return_statement",),
        if_="if_statement", if_cond="condition", if_then="consequence", if_else="alternative",
        loops=("for_statement",),
        block=("block", "statement_list", "source_file", "var_declaration", "const_declaration",
               "expression_list"),
        idents=_ID + ("field_identifier", "package_identifier"), literals=_LIT_COMMON,
    ),
    "cpp": Spec(
        call="call_expression", call_fn="function", call_args="arguments", args_types=("argument_list",),
        member="field_expression", member_obj="argument", member_prop="field",
        subscript=("subscript_expression",), subscript_obj="argument",
        assign=("assignment_expression",), assign_left="left", assign_right="right",
        decl=("init_declarator",), decl_name="declarator", decl_value="value",
        func=("function_definition", "lambda_expression"),
        func_name="declarator", func_params="parameters", params_types=("parameter_list",),
        param_name="declarator", func_body="body",
        ret=("return_statement",),
        if_="if_statement", if_cond="condition", if_then="consequence", if_else="alternative",
        loops=("while_statement", "for_statement", "do_statement", "for_range_loop"),
        block=("compound_statement", "translation_unit", "declaration", "condition_clause",
               "namespace_definition", "declaration_list"),
        idents=_ID + ("field_identifier", "qualified_identifier", "namespace_identifier"),
        literals=_LIT_COMMON + ("concatenated_string", "user_defined_literal"),
        descend=("class_specifier", "struct_specifier"),
        unwrap_decl=("pointer_declarator", "reference_declarator", "function_declarator",
                     "array_declarator", "parenthesized_declarator"),
    ),
    "kotlin": Spec(
        call="call_expression", call_fn=None, call_args=None, args_types=("value_arguments", "call_suffix"),
        member="navigation_expression", member_obj=None, member_prop=None,
        subscript=("indexing_expression",), subscript_obj=None,
        assign=("assignment",), assign_left=None, assign_right=None,
        decl=("property_declaration",), decl_name=None, decl_value=None,
        func=("function_declaration", "lambda_literal", "anonymous_function"),
        func_name="name", func_params=None, params_types=("function_value_parameters", "lambda_parameters"),
        param_name=None, func_body=None,
        ret=("return_expression", "jump_expression"),
        if_="if_expression", if_cond=None, if_then=None, if_else=None,
        loops=("for_statement", "while_statement", "do_while_statement"),
        block=("block", "source_file", "statements", "function_body", "control_structure_body",
               "class_body", "variable_declaration", "value_argument"),
        idents=_ID + ("simple_identifier",), literals=_LIT_COMMON + ("string_literal", "character_literal"),
        descend=("class_declaration", "object_declaration", "companion_object"),
    ),
    "swift": Spec(
        call="call_expression", call_fn=None, call_args=None, args_types=("call_suffix", "value_arguments"),
        member="navigation_expression", member_obj="target", member_prop="suffix",
        subscript=("subscript_expression",), subscript_obj=None,
        assign=("assignment",), assign_left="target", assign_right="result",
        decl=("property_declaration",), decl_name="name", decl_value="value",
        func=("function_declaration", "lambda_literal", "init_declaration"),
        func_name="name", func_params=None, params_types=(),
        param_name="name", func_body="body",
        ret=("control_transfer_statement",),
        if_="if_statement", if_cond=None, if_then=None, if_else=None,
        loops=("for_statement", "while_statement", "repeat_while_statement"),
        block=("function_body", "statements", "source_file", "class_body", "pattern"),
        idents=_ID + ("simple_identifier",), literals=_LIT_COMMON + ("line_string_literal", "multi_line_string_literal"),
        descend=("class_declaration", "protocol_declaration"),
    ),
    "ruby": Spec(
        call="call", call_fn=None, call_args="arguments", args_types=("argument_list",),
        member="call", member_obj="receiver", member_prop="method",   # receiver.method 없는 인자면 멤버로 취급
        subscript=("element_reference",), subscript_obj="object",
        assign=("assignment", "operator_assignment"), assign_left="left", assign_right="right",
        decl=(), decl_name=None, decl_value=None,
        func=("method", "singleton_method", "lambda", "block", "do_block"),
        func_name="name", func_params="parameters", params_types=("method_parameters", "block_parameters", "lambda_parameters"),
        param_name=None, func_body="body",
        ret=("return",),
        if_="if", if_cond="condition", if_then="consequence", if_else="alternative",
        loops=("while", "until", "for"),
        block=("program", "body_statement", "then", "else", "begin", "do"),
        idents=_ID + ("constant", "instance_variable", "global_variable", "class_variable"),
        literals=_LIT_COMMON + ("string", "symbol", "simple_symbol", "hash_key_symbol"),
        descend=("class", "module"),
    ),
}
LANG["c"] = LANG["cpp"]


def normalize_cfam(tree: Tree, file: str = "<memory>", language: str = "java") -> ir.Module:
    spec = LANG[language]
    root = tree.root_node
    w = _Worker(spec, file)
    return ir.Module(loc=loc_of(root, file), body=w.block(root.named_children))


class _Worker:
    def __init__(self, spec: Spec, file: str):
        self.s = spec
        self.file = file

    # ---------- 유틸 ----------

    def _named(self, node: TSNode) -> list[TSNode]:
        return [c for c in node.named_children if c.type not in ("comment", "line_comment", "block_comment")]

    def _fld(self, node: TSNode, name: str | None) -> TSNode | None:
        return child_by_field(node, name) if name else None

    def _first_ident(self, node: TSNode | None) -> TSNode | None:
        """노드 안에서 첫 식별자(깊이 우선). 파라미터/선언 이름 뽑기용."""
        if node is None:
            return None
        if node.type in self.s.idents:
            return node
        for c in self._named(node):
            r = self._first_ident(c)
            if r is not None:
                return r
        return None

    def _unwrap(self, node: TSNode | None) -> TSNode | None:
        """C 의 pointer_declarator → identifier 처럼 래퍼를 벗긴다."""
        while node is not None and node.type in self.s.unwrap_decl:
            inner = child_by_field(node, "declarator")
            if inner is None:
                kids = self._named(node)
                inner = kids[0] if kids else None
            node = inner
        return node

    def _opaque(self, node: TSNode) -> ir.Opaque:
        return ir.Opaque(loc=loc_of(node, self.file), kind=node.type,
                         children=[self.expr(c) for c in self._named(node)])

    # ---------- 블록/문 ----------

    @staticmethod
    def _flat(r) -> list[ir.Node]:
        """stmt() 가 돌려준 (중첩)리스트를 재귀 평탄화. 래퍼 문(expression_statement →
        statement_list → …)이 겹치면 리스트 안에 리스트가 생겨 엔진이 문장을 못 본다."""
        if r is None:
            return []
        if isinstance(r, list):
            out: list[ir.Node] = []
            for x in r:
                out.extend(_Worker._flat(x))
            return out
        return [r]

    def block(self, nodes) -> list[ir.Node]:
        out: list[ir.Node] = []
        for n in nodes:
            if n.type in ("comment", "line_comment", "block_comment"):
                continue
            out.extend(self._flat(self.stmt(n)))
        return out

    def _body(self, node: TSNode | None) -> list[ir.Node]:
        if node is None:
            return []
        if node.type in self.s.block:
            return self.block(self._named(node))
        return self._flat(self.stmt(node))

    def stmt(self, node: TSNode):
        s = self.s
        t = node.type

        if t in s.wrap or t in s.block:
            kids = self._named(node)
            if not kids:
                return None
            return [self.expr(k) if t in s.wrap else self._stmt_or_expr(k) for k in kids]

        if t in s.descend:
            # 클래스/구조체: 본문만 꺼내 메서드를 분석
            body = child_by_field(node, "body")
            return self.block(self._named(body)) if body is not None else self.block(self._named(node))

        if t in s.func:
            return self.function(node)

        if t in s.ret:
            kids = self._named(node)
            # Swift control_transfer_statement 는 break/continue 도 포함 — 값 있으면 return 취급
            return ir.Return(loc=loc_of(node, self.file), value=self.expr(kids[0]) if kids else None)

        if t == s.if_:
            return self._if(node)

        if t in s.loops:
            return self._loop(node)

        if t in s.decl:
            return self._decl(node)

        return self.expr(node)

    def _stmt_or_expr(self, node: TSNode):
        r = self.stmt(node)
        return r if r is not None else self._opaque(node)

    # ---------- 함수 ----------

    def function(self, node: TSNode) -> ir.Function:
        s = self.s
        name_node = self._unwrap(self._fld(node, s.func_name)) if s.func_name else None
        if name_node is not None and name_node.type not in s.idents:
            name_node = self._first_ident(name_node)
        # 파라미터 컨테이너: 필드 우선, 없으면 타입으로 탐색
        pnode = self._fld(node, s.func_params) if s.func_params else None
        if pnode is None:
            pnode = next((c for c in self._named(node) if c.type in s.params_types), None)
        params: list[ir.Param] = []
        if pnode is not None:
            for p in self._named(pnode):
                if s.param_name:
                    tgt = self._unwrap(self._fld(p, s.param_name))
                    if tgt is not None and tgt.type not in s.idents:
                        tgt = self._first_ident(tgt)
                else:
                    tgt = None
                if tgt is None:
                    tgt = self._first_ident(p)
                if tgt is not None:
                    params.append(ir.Param(loc=loc_of(tgt, self.file), name=text_of(tgt)))
        # Swift 는 parameter 가 함수 노드의 직계 자식(컨테이너 없음)
        if not params and not s.params_types:
            for p in self._named(node):
                if p.type == "parameter":
                    tgt = self._fld(p, "name") or self._first_ident(p)
                    if tgt is not None:
                        params.append(ir.Param(loc=loc_of(tgt, self.file), name=text_of(tgt)))
        bnode = self._fld(node, s.func_body) if s.func_body else None
        if bnode is None:
            bnode = next((c for c in reversed(self._named(node)) if c.type in s.block), None)
        return ir.Function(loc=loc_of(node, self.file),
                           name=text_of(name_node) if name_node is not None else None,
                           params=params, body=self._body(bnode))

    # ---------- 분기/반복 ----------

    def _if(self, node: TSNode) -> ir.If:
        s = self.s
        kids = self._named(node)
        cond = self._fld(node, s.if_cond) if s.if_cond else (kids[0] if kids else None)
        then = self._fld(node, s.if_then) if s.if_then else None
        els = self._fld(node, s.if_else) if s.if_else else None
        if then is None or els is None:
            # 위치 기반(Kotlin/Swift): 조건 뒤 블록들이 then/else
            blocks = [c for c in kids[1:] if c.type in s.block or c.type in ("else_clause",)]
            if then is None and blocks:
                then = blocks[0]
            if els is None and len(blocks) > 1:
                els = blocks[-1]
        return ir.If(loc=loc_of(node, self.file),
                     test=self.expr(cond) if cond is not None else self._opaque(node),
                     then=self._body(then), orelse=self._body(els))

    def _loop(self, node: TSNode) -> ir.Loop:
        cond = child_by_field(node, "condition") or child_by_field(node, "right")
        body = child_by_field(node, "body")
        if body is None:
            body = next((c for c in reversed(self._named(node)) if c.type in self.s.block), None)
        return ir.Loop(loc=loc_of(node, self.file),
                       test=self.expr(cond) if cond is not None else None, body=self._body(body))

    # ---------- 선언/할당 ----------

    def _decl(self, node: TSNode) -> ir.Node:
        s = self.s
        kids = self._named(node)
        name = self._unwrap(self._fld(node, s.decl_name)) if s.decl_name else None
        if name is None:
            name = self._first_ident(node)
        val = self._fld(node, s.decl_value) if s.decl_value else None
        if val is None:
            # 값 필드가 없는 문법: 이름·타입·토큰을 뺀 마지막 자식을 값으로.
            # C# 은 초기값이 equals_value_clause 로 감싸이고 named child 가 아닐 수 있어
            # 전체 children 을 훑는다.
            skip = ("type_identifier", "user_type", "predefined_type", "implicit_type",
                    "variable_declaration", "pattern", "value_binding_pattern", "modifiers",
                    "type_annotation", "comment")
            rest = [c for c in node.children
                    if c is not name and c.is_named and c.type not in s.idents and c.type not in skip]
            if rest:
                val = rest[-1]
                if val.type == "equals_value_clause":       # C#: = expr 래퍼
                    inner = self._named(val)
                    val = inner[-1] if inner else None
        if name is None:
            return self._opaque(node)
        target = ir.Ident(loc=loc_of(name, self.file), name=text_of(name))
        if val is None:
            return target
        return ir.Assign(loc=loc_of(node, self.file), target=target,
                         value=self.expr(val), operator="declare")

    # ---------- 표현식 ----------

    def expr(self, node: TSNode) -> ir.Node:
        s = self.s
        t = node.type
        kids = self._named(node)

        if t in s.idents:
            return ir.Ident(loc=loc_of(node, self.file), name=text_of(node))

        if t in s.literals and not kids:
            return ir.Literal(loc=loc_of(node, self.file), value=None, raw=text_of(node))
        if t in s.literals:
            # 보간 문자열("id = #{q}", "$q", "\(q)", $"{q}") — 리터럴로 접으면 보간된 변수의
            # 오염이 사라진다. Opaque 로 두어 자식(interpolation → identifier) 오염을 전파한다.
            return self._opaque(node)

        if t == "parenthesized_expression":
            return self.expr(kids[0]) if kids else self._opaque(node)

        # Ruby: call 노드는 인자가 없으면 receiver.method 멤버 접근으로도 쓰인다
        if t == s.call:
            fn = self._fld(node, s.call_fn) if s.call_fn else None
            args_node = self._fld(node, s.call_args) if s.call_args else None
            if args_node is None:
                args_node = next((c for c in kids if c.type in s.args_types), None)
            if fn is None:
                name_f = self._fld(node, "name")
                obj_f = self._fld(node, "object")
                if s.member == s.call and (self._fld(node, "method") is not None):
                    # Ruby: receiver + method 필드로 callee 를 만든다
                    callee = self._member_from_ruby(node)
                elif name_f is not None:
                    # Java method_invocation{object,name}: 단일 callee 노드가 없고 필드가 분리됨
                    if obj_f is not None:
                        callee = ir.Member(loc=loc_of(node, self.file), obj=self.expr(obj_f),
                                           prop=text_of(name_f))
                    else:
                        callee = ir.Ident(loc=loc_of(name_f, self.file), name=text_of(name_f))
                else:
                    fn = next((c for c in kids if c is not args_node), None)
                    callee = self.expr(fn) if fn is not None else self._opaque(node)
            else:
                callee = self.expr(fn)
            args: list[ir.Node] = []
            if args_node is not None:
                # Kotlin/Swift: call_suffix → value_arguments → value_argument{value}
                container = args_node
                if container.type == "call_suffix":
                    container = next((c for c in self._named(container) if c.type in ("value_arguments",)), container)
                for a in self._named(container):
                    if a.type in ("value_argument", "argument", "named_argument"):
                        v = child_by_field(a, "value") or (self._named(a)[-1] if self._named(a) else None)
                        args.append(self.expr(v) if v is not None else self._opaque(a))
                    else:
                        args.append(self.expr(a))
            return ir.Call(loc=loc_of(node, self.file), callee=callee, args=args)

        if t == s.member:
            return self._member(node)

        if t in s.subscript:
            obj = self._fld(node, s.subscript_obj) if s.subscript_obj else (kids[0] if kids else None)
            return ir.Member(loc=loc_of(node, self.file),
                             obj=self.expr(obj) if obj is not None else self._opaque(node),
                             prop="", computed=True)

        if t in s.assign:
            left = self._fld(node, s.assign_left) if s.assign_left else (kids[0] if kids else None)
            right = self._fld(node, s.assign_right) if s.assign_right else (kids[-1] if len(kids) > 1 else None)
            # Go: expression_list 래퍼 → 첫 원소끼리 짝짓는다(다중 할당은 과대근사)
            if left is not None and left.type == "expression_list":
                lk = self._named(left)
                left = lk[0] if lk else left
            if right is not None and right.type == "expression_list":
                rk = self._named(right)
                right = rk[0] if rk else right
            return ir.Assign(loc=loc_of(node, self.file),
                             target=self.expr(left) if left is not None else self._opaque(node),
                             value=self.expr(right) if right is not None else ir.Literal(
                                 loc=loc_of(node, self.file), value=None, raw=""),
                             operator="=")

        if t in s.decl:
            return self._decl(node)

        if t in s.func:
            return self.function(node)

        if t in s.block or t in s.wrap:
            r = self.stmt(node)
            if isinstance(r, list):
                return ir.Opaque(loc=loc_of(node, self.file), kind=t, children=self._flat(r))
            return r if r is not None else self._opaque(node)

        # 문자열 보간·이항연산·캐스트·삼항 등은 Opaque(자식 오염 합집합)
        return self._opaque(node)

    def _member(self, node: TSNode) -> ir.Node:
        s = self.s
        kids = self._named(node)
        if s.member_obj:
            obj = self._fld(node, s.member_obj)
        else:
            obj = kids[0] if kids else None
        if s.member_prop:
            prop = self._fld(node, s.member_prop)
        else:
            prop = kids[-1] if len(kids) > 1 else None
        # Swift: navigation_suffix{suffix=simple_identifier} 래퍼
        if prop is not None and prop.type == "navigation_suffix":
            inner = child_by_field(prop, "suffix") or (self._named(prop)[0] if self._named(prop) else None)
            prop = inner
        return ir.Member(loc=loc_of(node, self.file),
                         obj=self.expr(obj) if obj is not None else self._opaque(node),
                         prop=text_of(prop) if prop is not None else "")

    def _member_from_ruby(self, node: TSNode) -> ir.Node:
        recv = child_by_field(node, "receiver")
        meth = child_by_field(node, "method")
        if recv is None:
            return ir.Ident(loc=loc_of(meth, self.file), name=text_of(meth)) if meth is not None else self._opaque(node)
        return ir.Member(loc=loc_of(node, self.file), obj=self.expr(recv),
                         prop=text_of(meth) if meth is not None else "")
