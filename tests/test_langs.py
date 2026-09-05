"""다국어 확장 — Java·Kotlin·Go·Ruby·C/C++·Swift·C# 에서 source→sink taint 탐지.

언어마다 취약 스니펫 하나를 파일로 쓰고 scan_file 이 해당 규칙을 잡는지 본다.
정규화기(normalize_cfam)·문법 등록(loader)·스펙(specs/*.yml) 세 층을 한 번에 검증한다.
"""
import tempfile
from pathlib import Path

import pytest

from cpguard.scanner import scan_file

CASES = [
    ("java", "A.java", "java.sqli",
     'class A { void f(HttpServletRequest request, Statement stmt) throws Exception {'
     ' String q = request.getParameter("id"); stmt.executeQuery("SELECT * FROM t WHERE id=" + q); } }'),
    ("java", "B.java", "java.command-injection",
     'class B { void f(HttpServletRequest request) throws Exception {'
     ' String c = request.getParameter("cmd"); Runtime.getRuntime().exec(c); } }'),
    ("kotlin", "A.kt", "kotlin.command-injection",
     'fun f(request: HttpServletRequest) { val c = request.getParameter("cmd"); Runtime.getRuntime().exec(c) }'),
    ("kotlin", "W.kt", "kotlin.webview-xss",
     'fun f(intent: Intent, web: WebView) { val u = intent.getStringExtra("u"); web.loadUrl(u) }'),
    ("go", "a.go", "go.command-injection",
     'package m\nimport ("net/http"; "os/exec")\nfunc h(w http.ResponseWriter, r *http.Request) {'
     ' c := r.FormValue("cmd"); exec.Command(c) }'),
    ("go", "b.go", "go.sqli",
     'package m\nfunc h(r *http.Request, db *sql.DB) { q := r.FormValue("id"); db.Query("SELECT * FROM t WHERE id=" + q) }'),
    ("ruby", "a.rb", "ruby.command-injection",
     'def run\n  c = params[:cmd]\n  system(c)\nend'),
    ("ruby", "b.rb", "ruby.sqli",
     'def show\n  q = params[:id]\n  User.where("id = #{q}")\nend'),
    ("cpp", "a.cpp", "cpp.command-injection",
     'int main(int argc, char** argv) { char* c = getenv("CMD"); system(c); return 0; }'),
    ("cpp", "b.cpp", "cpp.buffer-overflow",
     'int main(int argc, char** argv) { char buf[16]; strcpy(buf, argv[1]); return 0; }'),
    ("c", "c.c", "cpp.format-string",
     'int main(int argc, char** argv) { char* s = getenv("S"); printf(s); return 0; }'),
    ("swift", "a.swift", "swift.webview-xss",
     'func f(req: Request, web: WKWebView) { let h = req.query["h"]; web.loadHTMLString(h, baseURL: nil) }'),
    ("csharp", "A.cs", "csharp.sqli",
     'class A { void F(HttpRequest request, SqlCommand cmd) {'
     ' var q = request.Query["id"]; cmd.CommandText = "x" + q; cmd.ExecuteReader(q); } }'),
    ("csharp", "B.cs", "csharp.command-injection",
     'class B { void F(HttpRequest request) { var c = request.Query["c"]; Process.Start(c); } }'),
]


@pytest.mark.parametrize("lang,fname,rule,src", CASES, ids=[f"{c[0]}:{c[2]}" for c in CASES])
def test_new_language_detects_taint(lang, fname, rule, src):
    d = Path(tempfile.mkdtemp(prefix="cpguard_lang_"))
    p = d / fname
    p.write_text(src, encoding="utf-8")
    ids = {f.rule_id for f in scan_file(p)}
    assert rule in ids, f"{lang}: expected {rule}, got {sorted(ids)}"


def test_new_extensions_registered():
    from cpguard.parse import loader
    for ext in (".java", ".kt", ".go", ".rb", ".cpp", ".c", ".h", ".swift", ".cs"):
        assert ext in loader.SUPPORTED_EXTENSIONS
    assert loader.rule_language("c") == "cpp"          # C 파일은 cpp 규칙 공유
    assert loader.rule_language("java") == "java"


# ---- 정규화기 회귀: try 블록 · for-each · 객체 생성 ----
# 셋 다 "IR 이 문장 순서를 잃거나 노드를 Opaque 로 접어" taint 가 조용히 끊기던 자리다.
# 조용한 미탐이라 벤치마크 없이는 드러나지 않으므로 최소 케이스를 남긴다.

def _scan(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    return {f.rule_id for f in scan_file(p)}


def test_java_taint_survives_try_block(tmp_path):
    """try 블록을 Opaque 로 접으면 블록 안 대입 순서가 사라져 오염이 끊겼다."""
    src = ('class A { void f(HttpServletRequest request) {'
           ' String p = request.getParameter("q");'
           ' try { String sql = "select " + p;'
           '       java.sql.Statement st = null; st.executeQuery(sql); }'
           ' catch (Exception e) {} } }')
    assert "java.sqli" in _scan(tmp_path, "T.java", src)


def test_java_taint_flows_through_foreach(tmp_path):
    """for (T v : coll) 의 반복 변수는 순회 대상의 원소 — 대상이 오염되면 변수도 오염."""
    src = ('class A { void f(HttpServletRequest request) {'
           ' javax.servlet.http.Cookie[] cs = request.getCookies();'
           ' String p = "";'
           ' for (javax.servlet.http.Cookie c : cs) { p = c.getValue(); }'
           ' Runtime.getRuntime().exec(p); } }')
    assert "java.command-injection" in _scan(tmp_path, "F.java", src)


def test_java_object_creation_is_a_sink(tmp_path):
    """new FileInputStream(path) 처럼 생성자 자체가 위험 지점인 경우."""
    src = ('class A { void f(HttpServletRequest request) {'
           ' String p = request.getParameter("f");'
           ' java.io.FileInputStream in = new java.io.FileInputStream(new java.io.File(p)); } }')
    assert "java.path-traversal" in _scan(tmp_path, "N.java", src)


def test_parse_cache_version_tracks_normalizer(tmp_path):
    """정규화기 소스가 바뀌면 파싱 캐시 키가 바뀌어야 한다.

    상수를 손으로 올리는 방식은 잊기 쉽고, 잊으면 옛 IR 이 재사용돼
    '고쳤는데 결과가 안 바뀐다'는 조용한 오류가 난다."""
    from cpguard import scanner
    assert scanner._PARSE_CACHE_VER == scanner._normalizer_version()
    assert len(scanner._PARSE_CACHE_VER) >= 8


# ---- 상수 전파 ----
# 경로 민감도가 없어 죽은 가지의 오염까지 보고하던 오탐을 줄이는 축.
# OWASP Benchmark 안전 케이스의 46%가 이 형태라 회귀하면 오탐률이 바로 튄다.

def test_constfold_kills_dead_branch(tmp_path):
    """컴파일 시점에 거짓인 else 가지는 오염 경로로 세지 않는다."""
    src = ('class A { void f(HttpServletRequest request) {'
           ' String p = request.getParameter("q");'
           ' int num = 86;'
           ' String bar;'
           ' if ((7 * 42) - num > 200) bar = "safe"; else bar = p;'
           ' Runtime.getRuntime().exec(bar); } }')
    assert "java.command-injection" not in _scan(tmp_path, "C1.java", src)


def test_constfold_keeps_live_branch(tmp_path):
    """반대로 상수 조건이 참이면 그 가지의 오염은 그대로 살아 있어야 한다(미탐 금지)."""
    src = ('class A { void f(HttpServletRequest request) {'
           ' String p = request.getParameter("q");'
           ' int num = 86;'
           ' String bar;'
           ' if ((7 * 42) - num > 200) bar = p; else bar = "safe";'
           ' Runtime.getRuntime().exec(bar); } }')
    assert "java.command-injection" in _scan(tmp_path, "C2.java", src)


def test_constfold_ternary(tmp_path):
    """삼항도 같은 함정 형태로 쓰인다."""
    src = ('class A { void f(HttpServletRequest request) {'
           ' String p = request.getParameter("q");'
           ' int num = 106;'
           ' String bar = (7 * 18) + num > 200 ? "safe" : p;'
           ' Runtime.getRuntime().exec(bar); } }')
    assert "java.command-injection" not in _scan(tmp_path, "C3.java", src)


def test_constfold_gives_up_on_reassigned_name(tmp_path):
    """두 번 이상 대입된 이름은 값을 특정할 수 없으므로 접지 않는다(건전성)."""
    src = ('class A { void f(HttpServletRequest request, boolean flag) {'
           ' String p = request.getParameter("q");'
           ' int num = 86;'
           ' if (flag) num = 1000;'
           ' String bar;'
           ' if ((7 * 42) - num > 200) bar = "safe"; else bar = p;'
           ' Runtime.getRuntime().exec(bar); } }')
    assert "java.command-injection" in _scan(tmp_path, "C4.java", src)


def test_constfold_never_folds_a_parameter(tmp_path):
    """파라미터 값은 호출자가 정한다 — 상수로 접으면 안 된다."""
    from cpguard.parse.constfold import _eval, _UNK
    from cpguard import ir
    loc = ir.Loc("<t>", 1, 0, 1, 1, 0, 1)
    assert _eval(ir.Ident(loc=loc, name="x"), {}) is _UNK
    assert _eval(ir.Binary(loc=loc, op="*",
                           children=[ir.Literal(loc=loc, value=None, raw="7"),
                                     ir.Literal(loc=loc, value=None, raw="42")]), {}) == 294
    assert _eval(ir.Binary(loc=loc, op="/",
                           children=[ir.Literal(loc=loc, value=None, raw="1"),
                                     ir.Literal(loc=loc, value=None, raw="0")]), {}) is _UNK


# ---- 컨테이너 오염 전파 ----

def test_container_mutation_taints_receiver(tmp_path):
    """list.add(오염) 은 리스트를 오염시킨다 — 수신자 변경을 모델링하지 않으면 미탐."""
    src = ('class A { void f(HttpServletRequest request) {'
           ' String p = request.getParameter("q");'
           ' java.util.List<String> a = new java.util.ArrayList<String>();'
           ' a.add("sh"); a.add(p);'
           ' ProcessBuilder pb = new ProcessBuilder(); pb.command(a); } }')
    assert "java.command-injection" in _scan(tmp_path, "M1.java", src)


def test_map_taint_is_key_sensitive(tmp_path):
    """리터럴 키로 넣고 다른 키로 꺼내면 오염이 아니다(맵 통째 오염은 오탐)."""
    safe = ('class A { void f(HttpServletRequest request) {'
            ' String p = request.getParameter("q");'
            ' java.util.HashMap<String,Object> m = new java.util.HashMap<String,Object>();'
            ' m.put("bad", p); m.put("ok", "safe");'
            ' String bar = (String) m.get("ok");'
            ' Runtime.getRuntime().exec(bar); } }')
    assert "java.command-injection" not in _scan(tmp_path, "M2.java", safe)

    tainted = safe.replace('m.get("ok")', 'm.get("bad")')
    assert "java.command-injection" in _scan(tmp_path, "M3.java", tainted)
