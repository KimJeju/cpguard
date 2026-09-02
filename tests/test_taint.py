"""Taint 엔진 회귀 corpus — 취약(양성) / 정제(음성) 쌍으로 검증."""
import pytest

from cpguard.parse import loader, normalize
from cpguard.taint import engine
from cpguard.taint.spec import load_rules

RULES = load_rules(language="javascript")


def scan(src: str):
    tree = loader.parse_source(src, language="javascript")
    mod = normalize.normalize(tree, file="t.js")
    return engine.analyze(mod, src.encode(), RULES)


def ids(src: str) -> set[str]:
    return {f.rule_id for f in scan(src)}


# ---------- 양성: 취약 코드는 탐지돼야 한다 ----------

@pytest.mark.parametrize("rule_id,src", [
    ("js.command-injection", "function f(req){ const h=req.query.h; child_process.exec(h); }"),
    ("js.code-injection",    "function f(req){ const e=req.body.e; eval(e); }"),
    ("js.path-traversal",    "function f(req){ const n=req.query.n; fs.readFile(n); }"),
    ("js.sqli",              "function f(req){ const i=req.params.id; db.query('SELECT '+i); }"),
    ("js.ssrf",              "function f(req){ const u=req.query.url; http.get(u); }"),
    ("js.xss",               "function f(req,res){ const m=req.query.m; res.send(m); }"),
])
def test_vulnerable_detected(rule_id, src):
    assert rule_id in ids(src)


# ---------- 음성: 정제된 코드는 탐지되면 안 된다(오탐) ----------

@pytest.mark.parametrize("rule_id,src", [
    ("js.command-injection", "function f(req){ const h=shellQuote(req.query.h); child_process.exec(h); }"),
    ("js.path-traversal",    "function f(req){ const n=path.basename(req.query.n); fs.readFile(n); }"),
    ("js.xss",               "function f(req,res){ const m=escapeHtml(req.query.m); res.send(m); }"),
    ("js.sqli",              "function f(req){ const i=escapeSql(req.params.id); db.query('SELECT '+i); }"),
])
def test_sanitized_not_detected(rule_id, src):
    assert rule_id not in ids(src)


def test_constant_not_tainted():
    assert ids("function f(){ child_process.exec('ls -la'); }") == set()


# ---------- 흐름 특성 ----------

def test_trace_has_source_and_sink():
    f = scan("function f(req){ const h=req.query.h; child_process.exec(h); }")[0]
    assert f.steps[0].kind == "source"
    assert f.steps[-1].kind == "sink"
    assert "req.query.h" in f.steps[0].code
    assert "exec" in f.steps[-1].code


def test_callback_handler_is_analyzed():
    """Express 스타일 콜백 안의 취약점도 잡아야 한다 (실전 코드 대부분이 이 형태)."""
    src = "app.get('/p', function (req, res) { const h = req.query.h; child_process.exec(h); });"
    assert "js.command-injection" in ids(src)


def test_multi_hop_propagation():
    src = """
    function f(req){
      const a = req.query.x;
      const b = a;
      const c = "prefix" + b;
      child_process.exec(c);
    }"""
    f = scan(src)[0]
    assert len(f.steps) >= 4  # source -> 여러 전파 -> sink


# ---------- 프로시저 간 분석 (Phase 2) ----------

def test_interprocedural_source_and_sink_helpers():
    """오염 생성과 위험 지점이 서로 다른 함수에 있어도 이어서 추적해야 한다."""
    src = """
    function readInput(req){ return req.query.cmd; }
    function runIt(v){ child_process.exec(v); }
    function handler(req,res){ const c = readInput(req); runIt(c); }
    """
    assert "js.command-injection" in ids(src)


def test_interprocedural_trace_is_stitched():
    """호출자 경로 + 피호출 함수 내부 경로가 하나로 이어져야 한다."""
    src = """
    function readInput(req){ return req.query.cmd; }
    function runIt(v){ child_process.exec(v); }
    function handler(req,res){ const c = readInput(req); runIt(c); }
    """
    f = [x for x in scan(src) if x.rule_id == "js.command-injection"][0]
    kinds = [s.kind for s in f.steps]
    assert kinds[0] == "source" and kinds[-1] == "sink"
    assert "call" in kinds and "param" in kinds


def test_param_taint_flows_to_return():
    """param -> return 전파: wrap 이 오염을 통과시킨다."""
    src = """
    function wrap(x){ return "p" + x; }
    function handler(req){ const a = wrap(req.query.q); child_process.exec(a); }
    """
    assert "js.command-injection" in ids(src)


def test_function_not_passing_taint_is_not_flagged():
    """인자가 오염돼도 리턴으로 흐르지 않으면 오염되지 않아야 한다(정밀도)."""
    src = """
    function ignore(x){ return "constant"; }
    function handler(req){ const a = ignore(req.query.q); child_process.exec(a); }
    """
    assert "js.command-injection" not in ids(src)


def test_sanitizer_inside_helper_blocks_flow():
    src = """
    function clean(x){ return shellQuote(x); }
    function handler(req){ const a = clean(req.query.q); child_process.exec(a); }
    """
    assert "js.command-injection" not in ids(src)


def test_recursive_function_terminates():
    """재귀 함수에서도 요약 계산이 종료돼야 한다(고정점 반복 상한)."""
    src = """
    function rec(x){ if (x) { return rec(x); } return x; }
    function handler(req){ const a = rec(req.query.q); child_process.exec(a); }
    """
    assert "js.command-injection" in ids(src)


# ---------- 흐름 민감도 (분기 병합 · 루프 고정점) ----------

def test_taint_in_one_branch_only():
    src = 'function f(req,flag){ let c="ls"; if(flag){c=req.query.c;} child_process.exec(c); }'
    assert "js.command-injection" in ids(src)


def test_branch_merge_keeps_taint():
    """else 분기의 안전한 대입이 then 분기의 오염을 지우면 안 된다."""
    src = 'function f(req,flag){ let c; if(flag){c=req.query.c;} else {c="safe";} child_process.exec(c); }'
    assert "js.command-injection" in ids(src)


def test_loop_fixpoint_propagation():
    """회전을 거쳐 도달하는 오염도 잡아야 한다."""
    src = 'function f(req){ let cur="x",nxt="y"; for(var i=0;i<3;i++){cur=nxt; nxt=req.query.c;} child_process.exec(cur); }'
    assert "js.command-injection" in ids(src)


def test_loop_reports_once():
    """루프 고정점 반복이 같은 취약점을 여러 번 보고하면 안 된다."""
    src = 'function f(req){ for(var i=0;i<3;i++){ child_process.exec(req.query.c); } }'
    hits = [f for f in scan(src) if f.rule_id == "js.command-injection"]
    assert len(hits) == 1


def test_branch_sanitized_still_clean():
    src = 'function f(req,flag){ let c="ls"; if(flag){c=shellQuote(req.query.c);} child_process.exec(c); }'
    assert "js.command-injection" not in ids(src)
