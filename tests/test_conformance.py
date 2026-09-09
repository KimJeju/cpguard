"""언어 간 정규화기·엔진 기능 대조.

정답지(벤치마크)가 있는 언어는 자바·파이썬뿐이다. 나머지 언어는 규칙만 있고 흐름
분석 기능이 실제로 같은 수준인지 확인된 적이 없었다 — 실제로 JS·PHP 는 파이썬에서
이미 고친 결함(반복 변수 미바인딩, switch 분기 소실, 상수 전파 미작동, += 오염 소실,
리터럴 키 첨자 미구분)을 그대로 갖고 있었다.

점수가 아니라 **기능 유무 대조**다. 각 항목은 '취약'(탐지되어야 함)이거나
'안전'(탐지되면 안 됨)이다. 언어별 본문이 None 이면 그 언어에 없는 문법이라 건너뛴다.

여기 등장하는 os.system·exec·system 등은 탐지 대상 문자열이다. 임시 파일에 텍스트로
쓴 뒤 스캐너에 넣어 "이 흐름을 잡는가"를 묻는 용도이며, 실행하지 않는다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules(user_dir=False)

#: 언어 -> (확장자, 파일 템플릿, 소스식, 싱크식(값 자리 %s), 규칙 접두)
LANGS = {
    "js": (".js",
           "const cp = require('child_process');\n"
           "app.post('/x', function (req, res) {\n%s\n});\n",
           "req.query.x", "cp.exec(%s)", "js."),
    "php": (".php",
            "<?php\nfunction v() {\n%s\n}\n",
            "$_GET['x']", "system(%s)", "php."),
    "py": (".py",
           "import os\nfrom flask import request\ndef v():\n%s\n",
           "request.args.get('x')", "os.system(%s)", "py."),
    "java": (".java",
             "import javax.servlet.http.*;\npublic class {CLS} extends HttpServlet {{\n"
             "  public void doPost(HttpServletRequest request, HttpServletResponse response)\n"
             "      throws Exception {{\n%s\n  }}\n}}\n",
             'request.getParameter("x")', "Runtime.getRuntime().exec(%s)", "java."),
}

#: (이름, 기대, 언어별 본문). 본문은 소스를 SRC, 싱크를 SINK(...) 로 쓴다.
CASES = [
    ("기본 흐름", "취약", {
        "js": "  const p = SRC;\n  SINK(p);",
        "php": "  $p = SRC;\n  SINK($p);",
        "py": "    p = SRC\n    SINK(p)",
        "java": "    String p = SRC;\n    SINK(p);",
    }),
    ("문자열 연결", "취약", {
        "js": "  const p = SRC;\n  SINK('ls ' + p);",
        "php": "  $p = SRC;\n  SINK('ls ' . $p);",
        "py": "    p = SRC\n    SINK('ls ' + p)",
        "java": '    String p = SRC;\n    SINK("ls " + p);',
    }),
    ("문자열 보간", "취약", {
        "js": "  const p = SRC;\n  SINK(`ls ${p}`);",
        "php": '  $p = SRC;\n  SINK("ls $p");',
        "py": "    p = SRC\n    SINK(f'ls {p}')",
        "java": None,
    }),
    ("+= 오염 유지", "취약", {
        "js": "  const p = SRC;\n  let s = 'ls ';\n  s += p;\n  s += ' safe';\n  SINK(s);",
        "php": "  $p = SRC;\n  $s = 'ls ';\n  $s .= $p;\n  $s .= ' safe';\n  SINK($s);",
        "py": "    p = SRC\n    s = 'ls '\n    s += p\n    s += ' safe'\n    SINK(s)",
        "java": '    String p = SRC;\n    String s = "ls ";\n    s += p;\n    s += " safe";\n    SINK(s);',
    }),
    ("첨자 대입 보존", "취약", {
        "js": "  const p = SRC;\n  const m = {};\n  m['b'] = p;\n  m['c'] = 'safe';\n  SINK(m['b']);",
        "php": "  $p = SRC;\n  $m = array();\n  $m['b'] = $p;\n  $m['c'] = 'safe';\n  SINK($m['b']);",
        "py": "    p = SRC\n    m = {}\n    m['b'] = p\n    m['c'] = 'safe'\n    SINK(m['b'])",
        "java": None,
    }),
    ("다른 키 읽기", "안전", {
        "js": "  const p = SRC;\n  const m = {};\n  m['b'] = p;\n  SINK(m['c']);",
        "php": "  $p = SRC;\n  $m = array();\n  $m['b'] = $p;\n  SINK($m['c']);",
        "py": "    p = SRC\n    m = {}\n    m['b'] = p\n    SINK(m['c'])",
        "java": None,
    }),
    ("반복 변수 바인딩", "취약", {
        "js": "  const items = SRC;\n  for (const it of items) { SINK(it); }",
        "php": "  $items = SRC;\n  foreach ($items as $it) { SINK($it); }",
        "py": "    items = SRC\n    for it in items:\n        SINK(it)",
        "java": ("    String[] items = request.getParameterValues(\"x\");\n"
                 "    for (String it : items) { SINK(it); }"),
    }),
    ("분기 합류", "취약", {
        "js": "  const p = SRC;\n  let s = 'safe';\n  if (p.length > 2) { s = p; }\n  SINK(s);",
        "php": "  $p = SRC;\n  $s = 'safe';\n  if (strlen($p) > 2) { $s = $p; }\n  SINK($s);",
        "py": "    p = SRC\n    s = 'safe'\n    if len(p) > 2:\n        s = p\n    SINK(s)",
        "java": ('    String p = SRC;\n    String s = "safe";\n'
                 "    if (p.length() > 2) { s = p; }\n    SINK(s);"),
    }),
    ("switch 분기", "취약", {
        "js": ("  const p = SRC;\n  let s = 'safe';\n  switch (req.query.k) {\n"
               "    case 'a': s = p; break;\n    default: s = 'safe2';\n  }\n  SINK(s);"),
        "php": ("  $p = SRC;\n  $s = 'safe';\n  switch ($_GET['k']) {\n"
                "    case 'a': $s = $p; break;\n    default: $s = 'safe2';\n  }\n  SINK($s);"),
        "py": None,
        "java": ('    String p = SRC;\n    String s = "safe";\n'
                 '    switch (request.getParameter("k")) {\n'
                 '      case "a": s = p; break;\n      default: s = "safe2";\n    }\n    SINK(s);'),
    }),
    ("상수 삼항(죽은 가지)", "안전", {
        "js": "  const p = SRC;\n  const s = false ? p : 'safe';\n  SINK(s);",
        "php": "  $p = SRC;\n  $s = false ? $p : 'safe';\n  SINK($s);",
        "py": "    p = SRC\n    s = p if False else 'safe'\n    SINK(s)",
        "java": '    String p = SRC;\n    String s = false ? p : "safe";\n    SINK(s);',
    }),
    ("상수 if(죽은 가지)", "안전", {
        "js": "  const p = SRC;\n  let s = 'safe';\n  if (false) { s = p; }\n  SINK(s);",
        "php": "  $p = SRC;\n  $s = 'safe';\n  if (false) { $s = $p; }\n  SINK($s);",
        "py": "    p = SRC\n    s = 'safe'\n    if False:\n        s = p\n    SINK(s)",
        "java": ('    String p = SRC;\n    String s = "safe";\n'
                 "    if (false) { s = p; }\n    SINK(s);"),
    }),
]


def _sink_expand(body: str, sink: str) -> str:
    """SINK(...) 를 언어별 싱크 식으로 바꾼다(중첩 괄호까지 맞춰 자른다)."""
    while "SINK(" in body:
        i = body.index("SINK(")
        depth, j = 0, i + 4
        while j < len(body):
            if body[j] == "(":
                depth += 1
            elif body[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = body[:i] + sink % body[i + 5:j] + body[j + 1:]
    return body


CHECKS = [(lang, name, want, bodies[lang])
          for lang in LANGS
          for name, want, bodies in CASES
          if bodies.get(lang) is not None]


@pytest.mark.parametrize("lang,name,want,body",
                         CHECKS, ids=[f"{l}-{n}" for l, n, _, _ in CHECKS])
def test_conformance(tmp_path, lang, name, want, body):
    ext, tpl, src, sink, prefix = LANGS[lang]
    cls = "T" + str(abs(hash((lang, name))) % 99999)
    text = (tpl % _sink_expand(body.replace("SRC", src), sink))
    if lang == "java":
        text = text.replace("{CLS}", cls).replace("{{", "{").replace("}}", "}")
    f = tmp_path / ((cls if lang == "java" else "t") + ext)
    f.write_text(text, encoding="utf-8")

    hit = any(x.rule_id.startswith(prefix) for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {lang} / {name}\n{text}"
    else:
        assert not hit, f"오탐: {lang} / {name}\n{text}"
