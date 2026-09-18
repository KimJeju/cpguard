"""C# SQLi — `cmd.CommandText = <오염>` 프로퍼티 대입 싱크.

SARD C# 스위트(CWE-89)는 예외 없이 `CreateCommand() → cmd.CommandText = query →
cmd.ExecuteReader()` 체인을 쓴다. 규칙이 CommandText 를 호출(call) 싱크로만 두고 있어
대입 형태를 통째로 놓쳤다(재현율 12.7%의 주 원인). 대입 싱크를 인식하는지 지킨다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules()

_HEAD = "using MySql.Data.MySqlClient;\nclass C { static void M(){\n"
_TAIL = "\n} }\n"

# (name, want, body) — body 는 M() 본문
CASES = [
    ("commandtext-assign-execute", "취약",
     'string t=Console.ReadLine(); string q="SELECT \'"+t+"\'";'
     ' var cmd=new MySqlCommand(); cmd.CommandText=q; cmd.ExecuteReader();'),
    ("commandtext-assign-only", "취약",
     'string t=Console.ReadLine(); var cmd=new MySqlCommand(); cmd.CommandText=t;'),
    ("concat-direct-ctor", "취약",   # 이미 통과하던 형태 — 회귀 방지
     'string t=Console.ReadLine(); var cmd=new MySqlCommand("SELECT \'"+t+"\'");'),
    ("parameterized-safe", "안전",   # CommandText 는 상수, 오염은 파라미터로 — 오탐 금지
     'string t=Console.ReadLine(); var cmd=new MySqlCommand();'
     ' cmd.CommandText="SELECT * FROM u WHERE n=@n";'
     ' cmd.Parameters.AddWithValue("@n", t); cmd.ExecuteReader();'),
]

# 진입점 명령행 인자(Main(string[] args)) — args[i] 가 오염 소스인지. 코퍼스 CWE-89 의
# 1/4 이 이 소스다.
ARGS_CASES = [
    ("args-index-concat-commandtext", "취약",
     'string q="SELECT \'"+args[1]+"\'"; var cmd=new MySqlCommand();'
     ' cmd.CommandText=q; cmd.ExecuteReader();'),
    ("args-index-direct-ctor", "취약",
     'var cmd=new MySqlCommand(args[1]);'),
]


@pytest.mark.parametrize("name,want,body", ARGS_CASES, ids=[c[0] for c in ARGS_CASES])
def test_csharp_sqli_args_source(tmp_path, name, want, body):
    head = "using MySql.Data.MySqlClient;\nclass C { static void Main(string[] args){\n"
    f = tmp_path / "t.cs"
    f.write_text(head + body + _TAIL, encoding="utf-8")
    hit = any(x.rule_id == "csharp.sqli" for x in scan_file(f, RULES))
    assert hit if want == "취약" else not hit, name


@pytest.mark.parametrize("name,want,body", CASES, ids=[c[0] for c in CASES])
def test_csharp_sqli_assign_sink(tmp_path, name, want, body):
    f = tmp_path / "t.cs"
    f.write_text(_HEAD + body + _TAIL, encoding="utf-8")
    hit = any(x.rule_id == "csharp.sqli" for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"
