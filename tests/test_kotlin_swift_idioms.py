"""Kotlin·Swift 관용구 탐지 회귀 방지.

둘 다 라벨링된 정답지가 없다. 모바일 앱 코드에서 흔한 형태를 최소 재현으로 직접
물어본다. 각 항목은 '취약'(탐지되어야 함)이거나 '안전'(탐지되면 안 됨)이다.

여기 등장하는 exec·system 은 탐지 대상 문자열이다. 임시 파일에 텍스트로 쓴 뒤
스캐너에 넣어 "이 흐름을 잡는가"를 묻는 용도이며, 실행하지 않는다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules(user_dir=False)

KT_TPL = """import java.lang.Runtime
class Handler {
    fun handle(request: javax.servlet.http.HttpServletRequest) {
%s
    }
}
"""
SW_TPL = """import Foundation
func handle(req: Request) {
%s
}
"""
WHOLE = "WHOLE"

KT = [
    ("기본 흐름", "취약", '        val p = request.getParameter("x")\n        Runtime.getRuntime().exec(p)'),
    ("문자열 템플릿", "취약",
     '        val p = request.getParameter("x")\n        Runtime.getRuntime().exec("ls $p")'),
    ("템플릿 중괄호", "취약",
     '        val p = request.getParameter("x")\n        Runtime.getRuntime().exec("ls ${p}")'),
    ("+= 축적", "취약",
     '        val p = request.getParameter("x")\n        var s = "ls "\n'
     '        s += p\n        s += " safe"\n        Runtime.getRuntime().exec(s)'),
    ("val 체인", "취약",
     '        val p = request.getParameter("x")\n        val q = p.trim()\n'
     '        Runtime.getRuntime().exec(q)'),
    ("엘비스 기본값", "취약",
     '        val p = request.getParameter("x") ?: ""\n        Runtime.getRuntime().exec(p)'),
    ("널 단언", "취약",
     '        val p = request.getParameter("x")!!\n        Runtime.getRuntime().exec(p)'),
    ("let 스코프 함수", "취약",
     '        request.getParameter("x")?.let { Runtime.getRuntime().exec(it) }'),
    ("when 분기", "취약",
     '        val p = request.getParameter("x")\n        var s = "safe"\n'
     '        when (request.getParameter("k")) {\n            "a" -> s = p\n'
     '            else -> s = "safe2"\n        }\n        Runtime.getRuntime().exec(s)'),
    ("for 반복 변수", "취약",
     '        val a = request.getParameterValues("x")\n'
     '        for (v in a) { Runtime.getRuntime().exec(v) }'),
    ("함수 경유", "취약", WHOLE + """
import java.lang.Runtime
fun run(v: String) { Runtime.getRuntime().exec(v) }
class H { fun handle(request: javax.servlet.http.HttpServletRequest) {
    run(request.getParameter("x"))
} }
"""),
    ("클래스 필드 경유", "취약", WHOLE + """
import java.lang.Runtime
class Svc(private val cmd: String) {
    fun run() { Runtime.getRuntime().exec(cmd) }
}
class H { fun handle(request: javax.servlet.http.HttpServletRequest) {
    Svc(request.getParameter("x")).run()
} }
"""),
    ("this 필드 경유", "취약", WHOLE + """
import java.lang.Runtime
class Svc2 {
    var cmd: String = ""
    fun run() { Runtime.getRuntime().exec(this.cmd) }
}
class H { fun handle(request: javax.servlet.http.HttpServletRequest) {
    val s = Svc2()
    s.cmd = request.getParameter("x")
    s.run()
} }
"""),
    ("숫자 변환", "안전",
     '        val p = request.getParameter("x").toInt()\n'
     '        Runtime.getRuntime().exec("ls $p")'),
    ("상수 분기(죽은 가지)", "안전",
     '        val p = request.getParameter("x")\n        var s = "safe"\n'
     '        if (false) { s = p }\n        Runtime.getRuntime().exec(s)'),
    ("람다 인자", "취약",
     '        val a = request.getParameterValues("x")\n'
     '        a.forEach { v -> Runtime.getRuntime().exec(v) }'),
]

SW = [
    ("기본 흐름", "취약", '    let p = req.query\n    system(p)'),
    ("문자열 보간", "취약", '    let p = req.query\n    system("ls \\(p)")'),
    ("+= 축적", "취약",
     '    let p = req.query\n    var s = "ls "\n    s += p\n    s += " safe"\n    system(s)'),
    ("옵셔널 체이닝", "취약", '    let p = req.query?.first\n    system(p!)'),
    ("널 병합", "취약", '    let p = req.query ?? ""\n    system(p)'),
    ("guard let", "취약",
     '    guard let p = req.query else { return }\n    system(p)'),
    ("if let", "취약", '    if let p = req.query { system(p) }'),
    ("for-in 반복 변수", "취약",
     '    let a = req.queryItems\n    for v in a { system(v) }'),
    ("switch 분기", "취약",
     '    let p = req.query\n    var s = "safe"\n    switch req.headers {\n'
     '    case "a": s = p\n    default: s = "safe2"\n    }\n    system(s)'),
    ("함수 경유", "취약", WHOLE + """
import Foundation
func runIt(_ v: String) { system(v) }
func handle(req: Request) { runIt(req.query) }
"""),
    ("클래스 필드 경유", "취약", WHOLE + """
import Foundation
class Svc {
    let cmd: String
    init(cmd: String) { self.cmd = cmd }
    func run() { system(self.cmd) }
}
func handle(req: Request) { Svc(cmd: req.query).run() }
"""),
    ("숫자 변환", "안전", '    let p = Int(req.query)\n    system("ls \\(p)")'),
    ("상수 분기(죽은 가지)", "안전",
     '    let p = req.query\n    var s = "safe"\n    if false { s = p }\n    system(s)'),
    ("클로저 인자", "취약",
     '    let a = req.queryItems\n    a.forEach { v in system(v) }'),
]


CHECKS = ([("kotlin", KT_TPL, ".kt", "kotlin.") + c for c in KT]
          + [("swift", SW_TPL, ".swift", "swift.") + c for c in SW])


@pytest.mark.parametrize("lang,tpl,ext,prefix,name,want,body", CHECKS,
                         ids=[f"{c[0]}-{c[4]}" for c in CHECKS])
def test_idiom(tmp_path, lang, tpl, ext, prefix, name, want, body):
    f = tmp_path / ("probe" + ext)
    f.write_text(body[len(WHOLE):] if body.startswith(WHOLE) else tpl % body,
                 encoding="utf-8")
    hit = any(x.rule_id.startswith(prefix) for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {lang} / {name}"
    else:
        assert not hit, f"오탐: {lang} / {name}"
