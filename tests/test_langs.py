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
