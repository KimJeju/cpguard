"""검사 실패면 기본값, 아니면 원본 — if/else 대입 형태의 검증.

    Match m = r.Match(x);
    if (!m.Success) { v = ""; } else { v = x; }
    query = "... '" + v + "'";                   // v 는 "" 이거나 검증된 x

`_defaulted_path` 는 else 없는 형태(`if (검사 실패) v = 기본값;`)만 알았다. SARD C# 의
"only numbers" 필터(CWE-89 안전 변형 4,224건의 대부분)가 이 if/else 형태라 전부 오탐이었다.
검사는 규칙의 validators 토큰(`Success`)이 부정된 멤버 접근으로 나타나고, 검사 대상 `m` 은
`r.Match(x)` 의 파생값이라 `_derived_origins` 로 x 에 닿는다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules()
_HEAD = ("using System; using System.Text.RegularExpressions; using MySql.Data.MySqlClient;\n"
         "class C { static void Main(string[] args){\n"
         "string x = args[1]; string v = null; string other = args[2];\n"
         "Regex r = new Regex(@\"^[0-9]*$\"); Match m = r.Match(x);\n")
_TAIL = ('\nstring q = "SELECT * FROM t WHERE id=\'" + v + "\'";'
         ' var cmd = new MySqlCommand(); cmd.CommandText = q; cmd.ExecuteReader();\n} }\n')

CASES = [
    ("validated-else-original", "안전",   # 코퍼스 형태 — v 는 "" 아니면 검증된 x
     'if (!m.Success) { v = ""; } else { v = x; }'),
    ("else-assigns-other-taint", "취약",  # else 가 검사와 무관한 오염값을 넣는다
     'if (!m.Success) { v = ""; } else { v = other; }'),
    ("not-negated-else-is-failure", "취약",  # 부정이 없으면 else 가 실패 쪽 — x 는 미검증
     'if (m.Success) { v = ""; } else { v = x; }'),
    ("then-assigns-taint", "취약",        # then 이 상수가 아니면 합류값이 고정되지 않는다
     'if (!m.Success) { v = other; } else { v = x; }'),
]


@pytest.mark.parametrize("name,want,body", CASES, ids=[c[0] for c in CASES])
def test_validated_else(tmp_path, name, want, body):
    f = tmp_path / "t.cs"
    f.write_text(_HEAD + body + _TAIL, encoding="utf-8")
    hit = any(x.rule_id == "csharp.sqli" for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"
