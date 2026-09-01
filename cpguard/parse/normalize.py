"""CST -> IR 정규화.  ←←← 여기가 네가 구현할 M1 과제다.

목표: tree-sitter가 만든 언어별 CST를 ir.py의 언어중립 IR로 변환.
성공 기준: `pytest tests/test_normalize.py` 초록불.

--------------------------------------------------------------------------
동작 방식 개요
--------------------------------------------------------------------------
loader.parse_source(src)  →  Tree  →  tree.root_node (type='program')
그 root의 자식들을 재귀적으로 걸으며 IR 노드를 만든다.

아래 loc_of / text_of / child_by_field 는 완성돼 있으니 그대로 써라.
normalize()와 그 하위 헬퍼(_stmt, _expr 등)를 채우면 된다.

--------------------------------------------------------------------------
tree-sitter JavaScript 노드 타입 → IR 매핑 (핵심만)
--------------------------------------------------------------------------
  program                         → ir.Module(body=[...])
  function_declaration            → ir.Function
      field 'name'   = identifier
      field 'parameters' = formal_parameters (자식 identifier들 → ir.Param)
      field 'body'   = statement_block
  arrow_function / function_expression → ir.Function(name=None)
  statement_block                 → 문 리스트로 풀어서 body에 채움
  expression_statement            → 자식 표현식 하나를 문으로
  lexical_declaration (const/let) / variable_declaration (var)
      → 안의 variable_declarator 각각을 ir.Assign(operator='declare')
      variable_declarator: field 'name'=identifier, field 'value'=초기화식
  assignment_expression           → ir.Assign(operator = field 'operator' 텍스트)
      field 'left', field 'right'
  member_expression               → ir.Member
      field 'object', field 'property'(property_identifier)
      subscript_expression a[b]   → ir.Member(computed=True, prop="")
  call_expression                 → ir.Call
      field 'function' = callee,  field 'arguments' = arguments(자식들 → args)
  identifier / property_identifier → ir.Ident (property는 Member.prop 문자열로 흡수)
  string/number/true/false/null 등 → ir.Literal
  return_statement                → ir.Return (자식 있으면 그 표현식)
  if_statement                    → ir.If (M1 테스트엔 없음, 나중에)
  while/for*                      → ir.Loop (나중에)
  그 외 / 모르는 노드              → ir.Opaque(kind=node.type, children=[자식 표현식들])

팁:
  - node.child_by_field_name("name") 으로 field 접근(위 헬퍼 child_by_field 사용).
  - named children만 순회(node.named_children) 하면 쉼표/괄호 같은 토큰 무시됨.
  - 모르는 노드를 만나면 예외 대신 Opaque로 접어라 — 부분 동작이 목표.
"""
from __future__ import annotations

from tree_sitter import Node as TSNode, Tree

from .. import ir


# ---------- 완성된 헬퍼 (그대로 사용) ----------

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


# ---------- 네가 구현할 부분 ----------

def normalize(tree: Tree, file: str = "<memory>", language: str = "javascript") -> ir.Module:
    """CST -> ir.Module. 이걸 구현해라.

    반환: 파일 최상위 문/함수들을 담은 ir.Module.
    """
    raise NotImplementedError("normalize()를 구현하세요 — tests/test_normalize.py 참고")
