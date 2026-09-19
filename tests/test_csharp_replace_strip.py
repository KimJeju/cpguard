"""`Regex.Replace(x, "")` — 문자 삭제형 정제, 명령 주입 규칙에서만.

SARD C# 은 `new Regex("[;invalid chars]").Replace(x, "")` 를 명령 주입엔 전부 good 으로
라벨한다(bad 변형 없음). 경로 조작은 같은 형태가 필터 내용(문자집합 범위·정규식 앵커)에
따라 good/bad 로 갈려 이름으로 못 가르므로 정제로 보지 않는다(넣으면 정탐을 잃는다).
SQL·LDAP·XPath 엔 삭제가 부족해 bad. 빈 문자열이 아닌 치환은 삭제가 아니다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules()
_HEAD = ("using System; using System.IO; using System.Text.RegularExpressions; using MySql.Data.MySqlClient;\n"
         "class C { static void Main(string[] args){\nstring x = args[1]; Regex r = new Regex(\"[a]\");\n")
_TAIL = "\n} }\n"
_LS = 'System.Diagnostics.Process.Start("/bin/bash", "-c \'ls " + v + "\'");'

CASES = [
    ("csharp.command-injection", "안전", 'string v = r.Replace(x, ""); ' + _LS),
    ("csharp.command-injection", "취약", 'string v = r.Replace(x, "_"); ' + _LS),   # 삭제가 아니면 정제 아님
    ("csharp.path-traversal", "취약", 'string v = r.Replace(x, ""); File.Exists(v);'),   # 경로 조작엔 정제 아님
    ("csharp.sqli", "취약",
     'string v = r.Replace(x, ""); var cmd = new MySqlCommand(); cmd.CommandText = "SELECT \'" + v + "\'"; cmd.ExecuteReader();'),
]


@pytest.mark.parametrize("rule_id,want,body", CASES,
                         ids=[f"{r.split('.')[1]}-{w}-{i}" for i, (r, w, _) in enumerate(CASES)])
def test_csharp_replace_strip(tmp_path, rule_id, want, body):
    f = tmp_path / "t.cs"
    f.write_text(_HEAD + body + _TAIL, encoding="utf-8")
    hit = any(x.rule_id == rule_id for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {rule_id}"
    else:
        assert not hit, f"오탐: {rule_id}"
