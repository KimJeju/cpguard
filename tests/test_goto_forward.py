"""전방 goto 는 건너뛴 구간의 효과를 무효화할 수 있다 — goto 시점 상태를 라벨에 합류한다.

    v = x;
    goto Skip;                       // 검증 블록을 건너뛴다
    if (!m.Success) v = ""; else v = x;
    Skip: {}
    sink(v);                         // v 는 검증 전 x 일 수 있다

엔진은 goto 를 모르고(Opaque) 선형으로 읽어, if/else 검증 인식(74e4445) 이후 이 형태를
씻어 버렸다(SARD C# preg_match 변형 1-15, bad 24건이 미탐으로). 전방 goto 시점의 env 를
라벨 문에서 합류시키면 "건너뛸 수 있다"가 모델에 들어온다. 뒤로 가는 goto(라벨이 먼저)는
합류할 것이 없어 그대로다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules()
_HEAD = ("using System; using System.Text.RegularExpressions; using MySql.Data.MySqlClient;\n"
         "class C { static void Main(string[] args){\n"
         "string x = args[1]; string v = x;\n"
         "Regex r = new Regex(@\"^[0-9]*$\"); Match m = r.Match(x);\n")
_VALID = 'if (!m.Success) { v = ""; } else { v = x; }'
_TAIL = ('\nstring q = "SELECT * FROM t WHERE id=\'" + v + "\'";'
         ' var cmd = new MySqlCommand(); cmd.CommandText = q; cmd.ExecuteReader();\n} }\n')

CASES = [
    ("goto-skips-validation", "취약", "goto Skip;\n" + _VALID + "\nSkip: {}"),
    ("no-goto-validated", "안전", _VALID),
    ("goto-skips-taint-assign", "취약",       # v="" 뒤 goto 로 v=x 를 건너뛸 수도, 안 뛸 수도
     'v = ""; goto Skip;\nv = x;\nSkip: {}'),  # → 과대근사로 오염 유지
]


@pytest.mark.parametrize("name,want,body", CASES, ids=[c[0] for c in CASES])
def test_goto_forward(tmp_path, name, want, body):
    f = tmp_path / "t.cs"
    f.write_text(_HEAD + body + _TAIL, encoding="utf-8")
    hit = any(x.rule_id == "csharp.sqli" for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"
