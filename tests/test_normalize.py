"""normalize() 계약 정의 = 네 M1 목표.

지금은 전부 실패(RED)한다. normalize.py를 구현해 전부 초록(GREEN)으로 만들면 M1 완료.
각 테스트가 기대하는 IR 구조가 곧 명세다.
"""
from cpguard import ir
from cpguard.parse import loader
from cpguard.parse.normalize import normalize

SAMPLE = """
function handler(req, res) {
  const id = req.query.id;
  const out = child_process.exec(id);
  return out;
}
"""


def _module(src=SAMPLE):
    return normalize(loader.parse_source(src, language="javascript"), file="sample.js")


# ---------- 최상위 구조 ----------

def test_module_has_one_function():
    mod = _module()
    assert isinstance(mod, ir.Module)
    assert len(mod.body) == 1
    assert isinstance(mod.body[0], ir.Function)


def test_function_signature():
    fn = _module().body[0]
    assert fn.name == "handler"
    assert [p.name for p in fn.params] == ["req", "res"]
    assert len(fn.body) == 3


# ---------- 문 종류 ----------

def test_declaration_becomes_assign():
    stmt = _module().body[0].body[0]
    assert isinstance(stmt, ir.Assign)
    assert stmt.operator == "declare"
    assert isinstance(stmt.target, ir.Ident) and stmt.target.name == "id"


def test_member_chain():
    # req.query.id  →  Member(prop=id, obj=Member(prop=query, obj=Ident(req)))
    value = _module().body[0].body[0].value
    assert isinstance(value, ir.Member) and value.prop == "id"
    inner = value.obj
    assert isinstance(inner, ir.Member) and inner.prop == "query"
    assert isinstance(inner.obj, ir.Ident) and inner.obj.name == "req"


def test_call_normalization():
    # child_process.exec(id)
    value = _module().body[0].body[1].value
    assert isinstance(value, ir.Call)
    assert isinstance(value.callee, ir.Member) and value.callee.prop == "exec"
    assert isinstance(value.callee.obj, ir.Ident) and value.callee.obj.name == "child_process"
    assert len(value.args) == 1
    assert isinstance(value.args[0], ir.Ident) and value.args[0].name == "id"


def test_return_statement():
    stmt = _module().body[0].body[2]
    assert isinstance(stmt, ir.Return)
    assert isinstance(stmt.value, ir.Ident) and stmt.value.name == "out"


# ---------- 최상위 표현식문 ----------

def test_toplevel_call_statement():
    mod = _module("eval(x);")
    assert len(mod.body) == 1
    call = mod.body[0]
    assert isinstance(call, ir.Call)
    assert isinstance(call.callee, ir.Ident) and call.callee.name == "eval"
    assert len(call.args) == 1 and call.args[0].name == "x"


# ---------- 위치 정보 보존 ----------

def test_loc_preserved():
    fn = _module().body[0]
    assert fn.loc.file == "sample.js"
    assert fn.loc.start_line >= 1
