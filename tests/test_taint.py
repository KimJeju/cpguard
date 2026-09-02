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
