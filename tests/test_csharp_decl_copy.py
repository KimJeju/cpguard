"""C# 선언+초기화 복사 `string v = x;` 가 오염을 넘기는가.

cfam `_decl` 의 C# 폴백(`decl_value=None`)이 초기값 후보에서 identifier 를 전부 빼서
(이름 노드를 빼려던 필터) `string v = x;` 는 Assign 조차 만들어지지 않았다 — 선언 복사가
통째로 미탐. `args[1]` 같은 비식별자 초기값만 살아남아 SARD(`= null` 선언 뒤 대입)에선
드러나지 않았다. 상수 초기화는 여전히 오염이 아니어야 한다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules()
_HEAD = "using System; using MySql.Data.MySqlClient;\nclass C { static void Main(string[] args){\n"
_TAIL = ('\nstring q = "SELECT * FROM t WHERE id=\'" + v + "\'";'
         ' var cmd = new MySqlCommand(); cmd.CommandText = q; cmd.ExecuteReader();\n} }\n')

CASES = [
    ("decl-copy-string", "취약", 'string x = args[1]; string v = x;'),
    ("decl-copy-var", "취약", 'string x = Console.ReadLine(); var v = x;'),
    ("decl-copy-chain", "취약", 'string x = args[1]; string w = x; string v = w;'),
    ("decl-const", "안전", 'string x = args[1]; string v = "const";'),
    ("decl-no-init-then-const", "안전", 'string x = args[1]; string v; v = "c";'),
]


@pytest.mark.parametrize("name,want,body", CASES, ids=[c[0] for c in CASES])
def test_csharp_decl_copy(tmp_path, name, want, body):
    f = tmp_path / "t.cs"
    f.write_text(_HEAD + body + _TAIL, encoding="utf-8")
    hit = any(x.rule_id == "csharp.sqli" for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"
