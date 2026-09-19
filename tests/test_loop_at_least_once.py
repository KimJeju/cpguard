"""최소 1회 도는 루프(do-while · while(true)) 는 루프 전 상태를 합류시키지 않는다.

    v = x;                                  // 오염
    do { if (!m.Success) v = ""; else v = x; break; } while (…);
    sink(v);                                // v 는 "" 이거나 검증된 x

`_run_loop` 은 0회 실행 경로로 루프 전 env 를 항상 합류시켜 검증 전 v 가 되살아났다.
SARD C# 의 "only numbers" 안전 변형 가운데 루프로 감싼 것들이 전부 오탐이었다.
조건이 미지수인 `while (cond)` 는 0회가 가능하므로 그대로 오염이어야 한다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules()
_HEAD = ("using System; using System.Text.RegularExpressions; using MySql.Data.MySqlClient;\n"
         "class C { static void Main(string[] args){\n"
         "string x = args[1]; string v = x; int n = args.Length;\n"
         "Regex r = new Regex(@\"^[0-9]*$\"); Match m = r.Match(x);\n")
_BODY = 'if (!m.Success) { v = ""; } else { v = x; } break;'
_TAIL = ('\nstring q = "SELECT * FROM t WHERE id=\'" + v + "\'";'
         ' var cmd = new MySqlCommand(); cmd.CommandText = q; cmd.ExecuteReader();\n} }\n')

CASES = [
    ("do-while", "안전", "do { " + _BODY + " } while (n > 42);"),
    ("while-true", "안전", "while (true) { " + _BODY + " }"),
    ("while-const-eq", "안전", "while ((1 == 1)) { " + _BODY + " }"),
    ("while-unknown-cond", "취약", "while (n > 42) { " + _BODY + " }"),   # 0회 가능 → 루프 전 v 유지
]


@pytest.mark.parametrize("name,want,body", CASES, ids=[c[0] for c in CASES])
def test_loop_at_least_once(tmp_path, name, want, body):
    f = tmp_path / "t.cs"
    f.write_text(_HEAD + body + _TAIL, encoding="utf-8")
    hit = any(x.rule_id == "csharp.sqli" for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"
