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
    new_expr: tuple[str, ...] = field(default_factory=tuple)     # 객체 생성식(new X(y))
    splice: tuple[str, ...] = field(default_factory=tuple)       # try/switch 등: 자식을 문으로 펼침
    # switch 처럼 "서로 배타적인 분기"를 담는 컨테이너 -> 그 안의 한 분기 노드 타입들.
    # 그냥 펼치면 분기가 순차 실행처럼 보여, 뒤 분기의 안전한 대입이 앞 분기에서 담긴
    # 오염을 지운다. if 사슬로 감싸 분기 합류(_merge)를 태운다.
    branches: dict = field(default_factory=dict)
    # 케이스 라벨 노드 타입(java: switch_label). 있으면 분기 조건을 `대상 == 라벨` 로
    # 만들어 상수 전파가 죽은 가지를 지울 수 있다. 없으면 분기 합집합으로만 다룬다.
    case_label: str = ""
    # 상수 전파가 분기 조건을 접으려면 연산자를 알아야 한다 → 이 세 가지는 Opaque 로 접지 않는다.
    #: 문자열 리터럴 안의 `$이름` 보간을 노출하지 않는 문법(Kotlin). 조각을 직접 읽는다.
    dollar_interp: str = ""
    #: 클래스 주 생성자에서 필드가 되는 파라미터 노드(Kotlin 의 class_parameter).
    ctor_property: tuple[str, ...] = field(default_factory=tuple)
    #: `if let x = e` / `guard let x = e` 처럼 조건 자리에서 이름을 묶는 문법(Swift).
    binds_in_cond: tuple[str, ...] = field(default_factory=tuple)
    #: 대입 좌변을 한 겹 감싸는 노드(Swift 의 directly_assignable_expression).
    unwrap_assign: tuple[str, ...] = field(default_factory=tuple)
    #: 인자 컨테이너 밖에 오는 후행 람다(Kotlin 의 annotated_lambda).
    trailing_lambda: tuple[str, ...] = field(default_factory=tuple)
    #: 파라미터를 안 적은 람다가 쓰는 암묵 이름(Kotlin 의 it). 없으면 빈 문자열.
    implicit_lambda_param: str = ""
    #: if_ 말고도 조건문으로 다룰 노드(루비의 unless). 없으면 Opaque 로 접혀
    #: 가드가 통째로 사라진다 — `unless 허용목록.include?(x) then 거부; return` 이
    #: 안 보이면 그 뒤의 값이 계속 오염으로 남는다.
    if_alt: tuple[str, ...] = ()
    binary: tuple[str, ...] = ("binary_expression",)
    unary: tuple[str, ...] = ("unary_expression",)
    ternary: tuple[str, ...] = ("ternary_expression", "conditional_expression")


#: 호출이 곰 객체 생성인 노드. 자바·C#은 생성자 이름이 이미 클래스명이라
#: 이름을 바꿀 필요는 없고, "이 호출의 결과가 그 객체"라는 표시만 달면 된다.
#: 수신자를 가리키는 단독 노드(자바·C#의 this, 스위프트의 self).
_RECEIVER_NODES = ("this", "self", "self_expression", "this_expression")

_CTOR_NODES = ("constructor_declaration", "constructor_invocation", "init_declaration")

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
        new_expr=("object_creation_expression",),
        splice=("try_statement", "try_with_resources_statement", "resource_specification",
                "resource", "catch_clause", "finally_clause", "synchronized_statement",
                "switch_expression", "switch_block", "switch_block_statement_group",
                "labeled_statement"),
        branches={"switch_expression": ("switch_block_statement_group", "switch_rule")},
        case_label="switch_label",
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
        new_expr=("object_creation_expression",),
        splice=("try_statement", "catch_clause", "finally_clause", "switch_statement",
                "switch_body", "switch_section", "lock_statement", "using_statement",
                "checked_statement", "labeled_statement"),
        branches={"switch_body": ("switch_section",)},
        unary=("prefix_unary_expression", "unary_expression"),
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
        splice=("select_statement", "type_switch_statement", "expression_switch_statement", "labeled_statement", "communication_case", "default_case", "expression_case", "type_case",),
        branches={"expression_switch_statement": ("expression_case", "default_case"),
                  "type_switch_statement": ("type_case", "default_case")},
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
        splice=("try_statement", "catch_clause", "switch_statement", "labeled_statement", "case_statement",),
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
        splice=("try_expression", "catch_block", "finally_block", "when_entry",),
        branches={"when_expression": ("when_entry",)},
        dollar_interp="string_literal",
        ctor_property=("class_parameter",),
        trailing_lambda=("annotated_lambda", "lambda_literal"),
        implicit_lambda_param="it",
    ),
    "swift": Spec(
        call="call_expression", call_fn=None, call_args=None, args_types=("call_suffix", "value_arguments"),
        member="navigation_expression", member_obj="target", member_prop="suffix",
        subscript=("subscript_expression",), subscript_obj=None,
        assign=("assignment",), assign_left="target", assign_right="result",
        decl=("property_declaration",), decl_name="name", decl_value="value",
        func=("function_declaration", "lambda_literal", "init_declaration"),
        func_name="name", func_params=None,
        params_types=("lambda_function_type_parameters",),
        param_name="name", func_body="body",
        ret=("control_transfer_statement",),
        if_="if_statement", if_cond=None, if_then=None, if_else=None,
        loops=("for_statement", "while_statement", "repeat_while_statement"),
        block=("function_body", "statements", "source_file", "class_body", "pattern"),
        idents=_ID + ("simple_identifier",), literals=_LIT_COMMON + ("line_string_literal", "multi_line_string_literal"),
        descend=("class_declaration", "protocol_declaration"),
        splice=("do_statement", "catch_block", "switch_entry",),
        branches={"switch_statement": ("switch_entry",)},
        binds_in_cond=("if_statement", "guard_statement"),
        unwrap_assign=("directly_assignable_expression",),
        binary=("additive_expression", "multiplicative_expression", "comparison_expression",
                "equality_expression", "conjunction_expression", "disjunction_expression"),
        unary=("prefix_expression",),
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
        if_alt=("unless",),
        loops=("while", "until", "for"),
        block=("program", "body_statement", "then", "else", "begin", "do"),
        idents=_ID + ("constant", "instance_variable", "global_variable", "class_variable"),
        literals=_LIT_COMMON + ("string", "symbol", "simple_symbol", "hash_key_symbol"),
        descend=("class", "module"),
        splice=("begin", "rescue", "ensure", "case", "when", "then",),
        branches={"case": ("when", "else")},
        # `post "/x" do ... end` — 루비의 블록도 인자 컨테이너 밖에 온다. 인자로 세지
        # 않으면 시나트라 라우트 본문이 통째로 분석에서 빠진다.
        trailing_lambda=("do_block", "block"),
        binary=("binary",),
        unary=("unary",),
        ternary=("conditional",),
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
        #: 지금 보고 있는 클래스의 필드 이름. 코틀린·스위프트는 this 없이 쓴다.
        self.fields: frozenset = frozenset()

    # ---------- 유틸 ----------

    def _named(self, node: TSNode) -> list[TSNode]:
        return [c for c in node.named_children if c.type not in ("comment", "line_comment", "block_comment")]

    def _fld(self, node: TSNode, name: str | None) -> TSNode | None:
        return child_by_field(node, name) if name else None

    def _annotations(self, node) -> list[str]:
        """파라미터에 붙은 어노테이션 이름. @RequestParam("q") -> RequestParam.

        Spring 계열은 요청 값을 파라미터로 주입하므로, 어노테이션을 못 보면 컨트롤러
        진입점이 통째로 사라진다(미탐). 이름만 모으고 인자는 보지 않는다.
        """
        out: list[str] = []
        stack = list(getattr(node, "children", []) or [])
        # Kotlin 은 어노테이션이 parameter 의 자식이 아니라 앞 형제(parameter_modifiers)다.
        prev = getattr(node, "prev_sibling", None)
        if prev is not None and prev.type.endswith("modifiers"):
            stack.append(prev)
        while stack:
            n = stack.pop()
            if n.type in ("annotation", "marker_annotation", "attribute"):
                name = self._fld(n, "name") or self._first_ident(n)
                if name is not None:
                    out.append(text_of(name).lstrip("@"))
                continue
            if n.type in ("modifiers", "parameter_modifiers", "attribute_list",
                          "annotation_argument_list"):
                stack.extend(getattr(n, "children", []) or [])
        return out

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
            return self._class(node)

        if t in s.func:
            return self.function(node)

        if t in s.ret:
            kids = self._named(node)
            # Swift control_transfer_statement 는 break/continue 도 포함 — 값 있으면 return 취급
            return ir.Return(loc=loc_of(node, self.file), value=self.expr(kids[0]) if kids else None)

        if t in s.binds_in_cond and (bind := self._bind_in_cond(node)) is not None:
            # 묶기만 하고 나머지는 평소대로 — if 는 분기로, guard 는 else 본문만.
            if t == self.s.if_:
                return [bind, self._if(node)]
            return [bind] + self.block(
                [c for c in self._named(node) if c.type in self.s.block])

        if t == s.if_ or t in s.if_alt:
            # unless 는 조건이 뒤집혀 있지만, "거부하고 돌아간다"를 알아보는 데는
            # 가지를 바꾸지 않는 쪽이 맞다 — 본문이 곧 거부 경로다.
            return self._if(node)

        if t in s.loops:
            return self._loop(node)

        if t in s.decl:
            return self._decl(node)

        # try/switch/synchronized 처럼 블록을 품지만 우리가 모델링하지 않는 문.
        # Opaque 로 접으면 블록 안 대입의 "순서"가 사라져 오염 추적이 그 지점에서 끊긴다
        # (Java 는 위험 코드가 대부분 try 안에 있어 치명적). 자식을 문 리스트로 펼친다.
        # switch 계열은 분기를 순차로 펼치면 안 된다 — 아래 splice 보다 먼저 본다.
        if t in s.branches:
            return self._branches(node, s.branches[t])

        if t in s.splice:
            return self.block(self._named(node))

        return self.expr(node)

    def _case_test(self, subj, values) -> ir.Node:
        """`대상 == 라벨1 || 대상 == 라벨2 ...`. 대상이나 라벨이 없으면 접을 수 없는 값."""
        if subj is None or not values:
            return ir.Literal(loc=loc_of(subj or values[0] if (subj or values) else None,
                                         self.file) if (subj or values) else
                              ir.Loc(self.file, 1, 0, 1, 0, 0, 0),
                              value=None, raw="switch")
        out = None
        for v in values:
            cmp_ = ir.Binary(loc=loc_of(v, self.file), op="==",
                             children=[self.expr(subj), self.expr(v)])
            out = cmp_ if out is None else ir.Binary(
                loc=loc_of(v, self.file), op="||", children=[out, cmp_])
        return out

    def _branches(self, node: TSNode, group_types: tuple[str, ...]):
        """switch 의 분기들을 if/else 사슬로 편다.

        분기는 서로 배타적인데 문 리스트로 그냥 이어 붙이면 마지막 분기가 앞 분기의
        대입을 덮어쓴다. 실측: OWASP 자바 코퍼스의 sqli 미탐 109건 중 17건이
        `case 'A': bar = param; ... default: bar = "safe";` 형태였다.

        라벨 노드 타입을 아는 언어(case_label)는 조건을 `대상 == 라벨` 로 만든다.
        그러면 선택자가 상수로 접힐 때 죽은 가지를 지울 수 있다. 모르는 언어는
        접을 수 없는 조건을 두어 예전처럼 분기 합집합으로만 다룬다(건전한 과대근사).
        """
        s = self.s
        kids = self._named(node)
        groups = [c for c in kids if c.type in group_types]
        holder = None
        if not groups:                       # 자바처럼 그룹이 블록 한 겹 안에 있는 경우
            for c in kids:
                inner = [g for g in self._named(c) if g.type in group_types]
                if inner:
                    groups, holder = inner, c
                    break
        if not groups:
            return self.block(kids)
        subj = next((c for c in kids
                     if c.type not in group_types
                     and (holder is None or c.start_byte != holder.start_byte)), None)

        default: list[ir.Node] = []
        cases: list[tuple[ir.Node, list[ir.Node]]] = []
        pending: list[TSNode] = []            # 라벨만 있고 본문이 없는 그룹(fall-through)
        saw_default = False
        for g in groups:
            gk = self._named(g)
            labels = [c for c in gk if s.case_label and c.type == s.case_label]
            body = self.block([c for c in gk
                               if not (s.case_label and c.type == s.case_label)])
            vals: list[TSNode] = []
            for lb in labels:
                lv = self._named(lb)
                if lv:
                    vals.extend(lv)
                else:
                    saw_default = True        # `default:` 는 라벨에 값이 없다
            if not body:
                pending.extend(vals)
                continue
            vals, pending = pending + vals, []
            if saw_default and not vals:
                default = body
            else:
                cases.append((self._case_test(subj, vals), body))
            saw_default = False
        chain: list[ir.Node] = default
        for test, body in reversed(cases):
            chain = [ir.If(loc=loc_of(node, self.file), test=test,
                           then=body, orelse=chain)]
        return chain

    def _dollar_string(self, node: TSNode) -> ir.Node:
        """`"ls $p"` — 이 문법은 보간을 named child 로 노출하지 않는다.

        조각이 string_content('$') + string_content('p') 로 쪼개져 와서 그냥 두면
        p 가 식별자로 살아나지 않아 문자열 템플릿이 통째로 미탐이다. `${p}` 형태는
        interpolation 노드로 오므로 평소대로 자식을 훑는다.
        """
        out: list[ir.Node] = []
        kids = self._named(node)
        dollar = False
        for c in kids:
            txt = text_of(c)
            if c.type == "string_content" and txt == "$":
                dollar = True
                continue
            if dollar:
                dollar = False
                if txt.isidentifier():
                    out.append(self.expr(c) if c.type in self.s.idents else
                               ir.Ident(loc=loc_of(c, self.file), name=txt))
                    continue
            if c.type != "string_content":
                out.append(self.expr(c))
        if not out:
            return ir.Literal(loc=loc_of(node, self.file), value=None, raw=text_of(node))
        return ir.Opaque(loc=loc_of(node, self.file), kind="string_template",
                         children=out)

    def _descendants(self, node: TSNode, types: tuple[str, ...], depth: int = 2):
        """가까운 후손 중 주어진 타입인 노드들. 컨테이너가 한 겹 더 감싸인 문법용."""
        if not types:
            return
        stack = [(c, 1) for c in self._named(node)]
        while stack:
            n, d = stack.pop()
            if n.type in types:
                yield n
            elif d < depth:
                stack.extend((c, d + 1) for c in self._named(n))

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
                    params.append(ir.Param(loc=loc_of(tgt, self.file), name=text_of(tgt),
                                           annotations=self._annotations(p)))
        # Swift 는 parameter 가 함수 노드의 직계 자식(컨테이너 없음)이고, 클로저는
        # 파라미터 컨테이너가 한 겹 더 안쪽(lambda_function_type)에 있다.
        if not params:
            for p in self._named(node):
                if p.type == "parameter":
                    tgt = self._fld(p, "name") or self._first_ident(p)
                    if tgt is not None:
                        params.append(ir.Param(loc=loc_of(tgt, self.file), name=text_of(tgt)))
        if not params:
            for cont in self._descendants(node, s.params_types, depth=3):
                for q in self._named(cont):
                    tgt = q if q.type in s.idents else self._first_ident(q)
                    if tgt is not None:
                        params.append(ir.Param(loc=loc_of(tgt, self.file), name=text_of(tgt)))
        if not params and s.implicit_lambda_param and node.type in s.trailing_lambda:
            # `list.forEach { exec(it) }` — 이름을 안 적으면 it 이 원소다.
            params.append(ir.Param(loc=loc_of(node, self.file),
                                   name=s.implicit_lambda_param))
        bnode = self._fld(node, s.func_body) if s.func_body else None
        if bnode is None:
            bnode = next((c for c in reversed(self._named(node)) if c.type in s.block), None)
        if bnode is not None:
            body = self._body(bnode)
        else:
            # 코틀린 람다는 본문 컨테이너 없이 문이 바로 자식으로 온다. 컨테이너만
            # 찾으면 몸통이 빈 함수가 되어 콜백 안의 위험 코드가 통째로 사라진다.
            skip = s.params_types + ("type_annotation", "user_type", "modifiers",
                                     "lambda_function_type", "comment")
            body = self.block([c for c in self._named(node)
                               if c.type not in skip
                               and (name_node is None or c.start_byte != name_node.start_byte)])
        return ir.Function(loc=loc_of(node, self.file),
                           name=text_of(name_node) if name_node is not None else None,
                           params=params, body=body,
                           is_ctor=node.type in _CTOR_NODES)

    # ---------- 분기/반복 ----------

    def _class(self, node: TSNode):
        """클래스 본문만 꺼내되, 필드 이름을 알고 들어간다.

        코틀린·스위프트는 필드를 `this.` 없이 쓴다. 필드 이름을 모르면 생성자가 채운
        값과 메서드가 읽는 이름이 이어지지 않아 서비스 클래스 형태가 통째로 미탐이다.
        코틀린의 주 생성자 프로퍼티(`class Svc(val cmd: String)`)는 선언과 대입이
        한 줄에 있으므로 생성자 함수를 만들어 준다.
        """
        s = self.s
        body = next((c for c in self._named(node) if c.type in s.block), None)
        ctor_params = list(self._descendants(node, s.ctor_property, depth=3))
        prev, self.fields = self.fields, self._field_names(body, ctor_params)
        try:
            stmts = self.block(self._named(body)) if body is not None else []
            if ctor_params:
                stmts.insert(0, self._primary_ctor(node, ctor_params))
        finally:
            self.fields = prev
        return stmts

    def _field_names(self, body: TSNode | None, ctor_params: list) -> frozenset:
        names = set()
        for c in ctor_params:
            tgt = self._first_ident(c)
            if tgt is not None:
                names.add(text_of(tgt))
        for c in (self._named(body) if body is not None else []):
            if c.type in self.s.decl:
                tgt = self._unwrap(self._fld(c, self.s.decl_name)) if self.s.decl_name else None
                tgt = tgt or self._first_ident(c)
                if tgt is not None:
                    names.add(text_of(tgt))
        return frozenset(names)

    def _primary_ctor(self, node: TSNode, ctor_params: list) -> ir.Function:
        """`class Svc(val cmd: String)` → 클래스 이름의 생성자 + this.cmd = cmd."""
        name = self._fld(node, "name") or self._first_ident(node)
        params: list[ir.Param] = []
        body: list[ir.Node] = []
        for c in ctor_params:
            tgt = self._first_ident(c)
            if tgt is None:
                continue
            who = text_of(tgt)
            params.append(ir.Param(loc=loc_of(tgt, self.file), name=who))
            body.append(ir.Assign(
                loc=loc_of(c, self.file), operator="=",
                target=ir.Member(loc=loc_of(c, self.file), prop=who,
                                 obj=ir.Ident(loc=loc_of(c, self.file), name="this")),
                value=ir.Ident(loc=loc_of(tgt, self.file), name=who)))
        return ir.Function(loc=loc_of(node, self.file),
                           name=text_of(name) if name is not None else None,
                           params=params, body=body, is_ctor=True)

    def _bind_in_cond(self, node: TSNode) -> ir.Node | None:
        """`if let q = req.query` / `guard let g = ...` 의 q·g 를 값에 묶는다.

        조건 자리에서 이름이 생기는 문법이라 그냥 두면 본문의 q 가 어디에도 묶이지
        않아 통째로 미탐이다. 옵셔널 해제는 값을 바꾸지 않으므로 그대로 잇는다.
        """
        name = child_by_field(node, "bound_identifier")
        if name is None:
            return None
        skip = self.s.block + ("value_binding_pattern", "else", "comment", "pattern")
        val = next((c for c in self._named(node)
                    if c.type not in skip and c.start_byte != name.start_byte), None)
        if val is None:
            return None
        return ir.Assign(loc=loc_of(node, self.file), operator="declare",
                         target=ir.Ident(loc=loc_of(name, self.file), name=text_of(name)),
                         value=self.expr(val))

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
        cond = child_by_field(node, "condition")
        # Swift/Kotlin 의 for-in: 반복 변수와 대상이 필드 이름이 다르거나(item/collection)
        # 아예 없다(코틀린은 순서로만 구분). 여기서 표준 필드 이름으로 맞춰 준다.
        if node.type == "for_statement" and child_by_field(node, "value") is None:
            item = child_by_field(node, "item") or child_by_field(node, "bound_identifier")
            coll = child_by_field(node, "collection")
            if item is None or coll is None:
                # 본문 컨테이너만 빼고 앞의 둘이 반복 변수와 대상이다. block 집합으로
                # 거르면 안 된다 — 코틀린은 변수 선언 노드도 그 집합에 들어 있다.
                body_node = child_by_field(node, "body")
                kids = [c for c in self._named(node)
                        if (body_node is None or c.start_byte != body_node.start_byte)
                        and c.type not in ("block", "statements", "control_structure_body",
                                           "function_body", "comment")]
                if len(kids) >= 2:
                    item, coll = kids[0], kids[1]
            if item is not None and coll is not None:
                tgt = self._first_ident(item) if item.type not in self.s.idents else item
                if tgt is not None:
                    body_node = child_by_field(node, "body") or next(
                        (c for c in reversed(self._named(node)) if c.type in self.s.block), None)
                    stmts = self._body(body_node)
                    stmts = [ir.Assign(
                        loc=loc_of(node, self.file), operator="declare",
                        target=ir.Ident(loc=loc_of(tgt, self.file), name=text_of(tgt)),
                        value=self.expr(coll))] + stmts
                    return ir.Loop(loc=loc_of(node, self.file), test=None, body=stmts)
        body = child_by_field(node, "body")
        if body is None:
            body = next((c for c in reversed(self._named(node)) if c.type in self.s.block), None)
        stmts = self._body(body)

        # for-each (for (T v : coll) / foreach (var v in coll)): 반복 변수는 순회 대상의 원소다.
        # 대상이 오염됐으면 변수도 오염된 것으로 보고(과대근사) 본문 앞에 바인딩을 넣는다.
        # 이게 없으면 컬렉션으로 들어온 사용자 입력이 루프 안에서 통째로 사라진다.
        # Go 의 range 는 반복 변수와 대상이 for_statement 가 아니라 range_clause 에
        # 달려 있다. 게다가 left 는 `_, p` / `k, v` 처럼 둘이고 **값은 뒤쪽**이다
        # (앞은 인덱스나 키). 하나뿐인 `for i := range xs` 는 인덱스만 받는 형태라
        # 묶지 않는다 — 인덱스에 컬렉션의 오염을 주면 과대근사가 지나치다.
        rng = next((c for c in self._named(node) if c.type == "range_clause"), None)
        if rng is not None:
            left = child_by_field(rng, "left")
            kids = self._named(left) if left is not None else []
            it = child_by_field(rng, "right")
            var = kids[-1] if len(kids) >= 2 else None
            if it is not None and var is not None:
                stmts = [ir.Assign(loc=loc_of(node, self.file),
                                   target=ir.Ident(loc=loc_of(var, self.file), name=text_of(var)),
                                   value=self.expr(it), operator="declare")] + stmts
            return ir.Loop(loc=loc_of(node, self.file), test=None, body=stmts)

        it = child_by_field(node, "value") or child_by_field(node, "right")
        var = child_by_field(node, "name") or child_by_field(node, "left")
        if it is not None and var is not None:
            tgt = self._unwrap(var)
            if tgt is not None and tgt.type not in self.s.idents:
                tgt = self._first_ident(tgt)
            if tgt is not None:
                stmts = [ir.Assign(loc=loc_of(node, self.file),
                                   target=ir.Ident(loc=loc_of(tgt, self.file), name=text_of(tgt)),
                                   value=self.expr(it), operator="declare")] + stmts
        elif cond is None:
            cond = it

        return ir.Loop(loc=loc_of(node, self.file),
                       test=self.expr(cond) if cond is not None else None, body=stmts)

    # ---------- 선언/할당 ----------

    def _decl(self, node: TSNode) -> ir.Node:
        s = self.s
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

        if t in _RECEIVER_NODES:
            # this / self — Opaque 로 접으면 this.cmd 의 경로가 아예 만들어지지 않아
            # 필드에 담긴 오염을 추적할 수 없다(생성자→필드→메서드 흐름이 통째로 미탐).
            return ir.Ident(loc=loc_of(node, self.file), name=text_of(node))

        if t == s.dollar_interp:
            return self._dollar_string(node)

        if t in s.idents:
            if text_of(node) in ("true", "false", "null", "nil", "None"):
                # 코틀린은 true/false 를 identifier 로 준다. 리터럴로 두지 않으면
                # 상수 전파가 `if (false)` 의 죽은 가지를 지우지 못한다.
                return ir.Literal(loc=loc_of(node, self.file), value=None,
                                  raw=text_of(node))
            name = text_of(node)
            if name in self.fields:
                # 코틀린·스위프트는 필드를 this 없이 그냥 이름으로 쓴다. 그대로 두면
                # 생성자가 채운 필드와 메서드가 읽는 이름이 이어지지 않는다.
                return ir.Member(loc=loc_of(node, self.file), prop=name,
                                 obj=ir.Ident(loc=loc_of(node, self.file), name="this"))
            return ir.Ident(loc=loc_of(node, self.file), name=name)

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
            # a.forEach { v -> ... } — 코틀린의 후행 람다는 인자 컨테이너 밖에 있다.
            # 인자로 세지 않으면 콜백 본문이 호출과 이어지지 않아 통째로 미탐이다.
            for c in kids:
                if c.type not in s.trailing_lambda:
                    continue
                # annotated_lambda 는 lambda_literal 을 한 겹 감싼 껍데기다. 껍데기를
                # 그대로 함수로 만들면 본문 컨테이너를 못 찾아 몸통이 빈 함수가 된다.
                inner = next((q for q in self._named(c) if q.type in s.func), c)
                args.append(self.expr(inner))
            return ir.Call(loc=loc_of(node, self.file), callee=callee, args=args)

        if t in s.new_expr:
            # new java.io.FileInputStream(path) — 생성자도 위험 지점이 될 수 있으므로
            # 타입 이름을 callee 로 하는 Call 로 모델링한다(Opaque 로 접으면 sink 매칭 불가).
            ty = self._fld(node, "type")
            args_node = self._fld(node, "arguments") or next(
                (c for c in kids if c.type in s.args_types), None)
            args = [self.expr(a) for a in self._named(args_node)] if args_node is not None else []
            callee = (ir.Ident(loc=loc_of(ty, self.file), name=text_of(ty))
                      if ty is not None else self._opaque(node))
            return ir.Call(loc=loc_of(node, self.file), callee=callee, args=args)

        if t == s.member:
            return self._member(node)

        if t in s.subscript:
            obj = self._fld(node, s.subscript_obj) if s.subscript_obj else (kids[0] if kids else None)
            idx = next((c for c in kids
                        if obj is None or c.start_byte != obj.start_byte), None)
            return ir.Member(loc=loc_of(node, self.file),
                             obj=self.expr(obj) if obj is not None else self._opaque(node),
                             prop="", computed=True,
                             index=self.expr(idx) if idx is not None else None)

        if t in s.assign:
            left = self._fld(node, s.assign_left) if s.assign_left else (kids[0] if kids else None)
            right = self._fld(node, s.assign_right) if s.assign_right else (kids[-1] if len(kids) > 1 else None)
            # Go: expression_list 래퍼 → 첫 원소끼리 짝짓는다(다중 할당은 과대근사)
            if left is not None and left.type in s.unwrap_assign:
                # Swift 의 directly_assignable_expression — 벗기지 않으면 좌변 경로가
                # 만들어지지 않아 대입 자체가 사라진다.
                kids_l = self._named(left)
                left = kids_l[0] if kids_l else left
            if left is not None and left.type == "expression_list":
                lk = self._named(left)
                left = lk[0] if lk else left
            if right is not None and right.type == "expression_list":
                rk = self._named(right)
                right = rk[0] if rk else right
            # s += p 는 덮어쓰기가 아니라 덧붙이기다. 연산자를 "=" 로 뭉개면 엔진이
            # 대상 슬롯을 비워버려, 뒤에 안전한 값을 += 하는 순간 앞서 담긴 오염이
            # 사라진다(자바 미탐의 한 갈래). Go 의 := 는 새 선언이라 "=" 와 같다.
            op_node = self._fld(node, "operator")
            op = text_of(op_node) if op_node is not None else "="
            if op in ("=", ":="):
                op = "="
            return ir.Assign(loc=loc_of(node, self.file),
                             target=self.expr(left) if left is not None else self._opaque(node),
                             value=self.expr(right) if right is not None else ir.Literal(
                                 loc=loc_of(node, self.file), value=None, raw=""),
                             operator=op)

        if t in s.decl:
            return self._decl(node)

        if t in s.func:
            return self.function(node)

        if t in s.block or t in s.wrap:
            r = self.stmt(node)
            if isinstance(r, list):
                return ir.Opaque(loc=loc_of(node, self.file), kind=t, children=self._flat(r))
            return r if r is not None else self._opaque(node)

        if t in s.binary:
            left = self._fld(node, "left") or self._fld(node, "lhs")
            right = self._fld(node, "right") or self._fld(node, "rhs")
            op = self._fld(node, "operator") or self._fld(node, "op")
            if left is not None and right is not None:
                return ir.Binary(loc=loc_of(node, self.file),
                                 op=text_of(op) if op is not None else "",
                                 children=[self.expr(left), self.expr(right)])

        if t in s.unary:
            operand = (self._fld(node, "operand") or self._fld(node, "argument")
                       or self._fld(node, "target"))
            op = self._fld(node, "operator") or self._fld(node, "operation")
            if operand is None and kids:      # C#: 필드 없이 위치로만
                operand = kids[-1]
            if operand is not None:
                op_txt = text_of(op) if op is not None else (
                    node.children[0].text.decode("utf-8", "replace") if node.children else "")
                return ir.Unary(loc=loc_of(node, self.file), op=op_txt,
                                children=[self.expr(operand)])

        if t in s.ternary:
            cond = self._fld(node, "condition")
            yes = self._fld(node, "consequence") or self._fld(node, "if_true")
            no = self._fld(node, "alternative") or self._fld(node, "if_false")
            if cond is not None and yes is not None and no is not None:
                return ir.Ternary(loc=loc_of(node, self.file),
                                  children=[self.expr(cond), self.expr(yes), self.expr(no)])

        # 문자열 보간·캐스트 등 나머지는 Opaque(자식 오염 합집합)
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
