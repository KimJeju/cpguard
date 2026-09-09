"""JS/Node 관용구 탐지 회귀 방지.

JS 는 라벨링된 정답지가 없는 언어라(OWASP Benchmark 는 자바·파이썬만 있다) 실제 노드
코드에서 흔한 형태를 최소 재현으로 직접 물어본다. 각 항목은 '취약'(탐지되어야 함)
이거나 '안전'(탐지되면 안 됨)이다.

여기 등장하는 cp.exec 는 탐지 대상 문자열이다. 임시 파일에 텍스트로 쓴 뒤 스캐너에
넣어 "이 흐름을 잡는가"를 묻는 용도이며, 실행하지 않는다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules(user_dir=False)

TPL = ("const cp = require('child_process');\n"
       "const app = require('express')();\n"
       "app.post('/x', async function (req, res) {\n%s\n});\n")

CASES = [
    ("구조분해 파라미터", "취약", "  const { x } = req.query;\n  cp.exec(x);"),
    ("구조분해 기본값", "취약", "  const { x = '' } = req.body;\n  cp.exec(x);"),
    ("배열 구조분해", "취약", "  const [a] = [req.query.x];\n  cp.exec(a);"),
    ("옵셔널 체이닝", "취약", "  const x = req.query?.x;\n  cp.exec(x);"),
    ("널 병합", "취약", "  const x = req.query.x ?? 'd';\n  cp.exec(x);"),
    ("논리합 기본값", "취약", "  const x = req.query.x || 'd';\n  cp.exec(x);"),
    ("전개 연산자", "취약", "  const a = [...[req.query.x]];\n  cp.exec(a[0]);"),
    ("await", "취약", "  const x = await Promise.resolve(req.query.x);\n  cp.exec(x);"),
    ("then 콜백", "취약",
     "  Promise.resolve(req.query.x).then(function (v) { cp.exec(v); });"),
    ("map 콜백", "취약", "  [req.query.x].map(function (v) { cp.exec(v); });"),
    ("forEach 콜백", "취약", "  req.body.list.forEach(function (v) { cp.exec(v); });"),
    ("화살표 콜백", "취약", "  [req.query.x].forEach((v) => cp.exec(v));"),
    ("객체 리터럴 왕복", "취약", "  const o = { cmd: req.query.x };\n  cp.exec(o.cmd);"),
    ("객체 다른 키", "안전",
     "  const o = { cmd: req.query.x, safe: 'ls' };\n  cp.exec(o.safe);"),
    ("배열 push 후 읽기", "취약",
     "  const a = [];\n  a.push(req.query.x);\n  cp.exec(a[0]);"),
    ("JSON 왕복", "취약",
     "  const o = JSON.parse(JSON.stringify(req.query.x));\n  cp.exec(o);"),
    ("try/catch", "취약", "  try { cp.exec(req.query.x); } catch (e) {}"),
    ("클래스 메서드 경유", "취약",
     "  class R { run(v) { cp.exec(v); } }\n  new R().run(req.query.x);"),
    ("모듈 함수 경유", "취약", "  function run(v) { cp.exec(v); }\n  run(req.query.x);"),
    ("정규식 검사 가드", "안전",
     "  const x = req.query.x;\n  if (/^[0-9]+$/.test(x)) { cp.exec(x); }"),
    ("숫자 변환", "안전", "  const x = Number(req.query.x);\n  cp.exec(String(x));"),
    ("parseInt", "안전", "  const x = parseInt(req.query.x, 10);\n  cp.exec('ls ' + x);"),
    ("템플릿 중첩", "취약", "  const x = req.query.x;\n  cp.exec(`ls ${`${x}`}`);"),
    ("문자열 메서드 통과", "취약",
     "  const x = req.query.x;\n  cp.exec(x.trim().toLowerCase());"),
    ("length 는 안전", "안전", "  const x = req.query.x;\n  cp.exec('ls ' + x.length);"),
    ("화살표 축약 함수 경유", "취약",
     "  const run = (v) => cp.exec(v);\n  run(req.query.x);"),
    ("헤더 소스", "취약", "  cp.exec(req.headers['x-cmd']);"),
    ("params 소스", "취약", "  cp.exec(req.params.id);"),
    ("반복 인덱스 접근", "취약",
     "  const a = req.body.list;\n  for (let i = 0; i < a.length; i++) { cp.exec(a[i]); }"),
    ("while 축적", "취약",
     "  let s = '';\n  while (true) { s += req.query.x; break; }\n  cp.exec(s);"),
]


@pytest.mark.parametrize("name,want,body", CASES, ids=[c[0] for c in CASES])
def test_js_idiom(tmp_path, name, want, body):
    f = tmp_path / "probe.js"
    f.write_text(TPL % body, encoding="utf-8")
    hit = any(x.rule_id.startswith("js.") for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"
