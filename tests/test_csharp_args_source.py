"""C# 명령행 인자 소스 `Main(string[] args)` — sqli 외 규칙 4종.

SARD C# 스위트는 CWE 마다 소스 1/4 이 `args[i]` 인데 csharp.sqli 에만 소스가 있어
path/cmd/ldap/xpath 는 args 버킷이 0% 였다(readline·shell 은 96~100%). 규칙마다
name 소스 `args` 한 줄. 상수 소스는 오염이 아니므로 잡히면 안 된다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules()
_HEAD = ("using System; using System.IO; using System.Xml; using System.DirectoryServices;\n"
         "class C { static void Main(string[] args){\n")
_TAIL = "\n} }\n"

CASES = [
    ("csharp.path-traversal", "취약", 'File.Exists(args[1]);'),
    ("csharp.command-injection", "취약",
     'System.Diagnostics.Process.Start("/bin/bash", "-c \'ls " + args[1] + "\'");'),
    ("csharp.ldap-injection", "취약",
     'string q = "(&(objectClass=person)(sn=" + args[1] + "))";'
     ' var s = new DirectorySearcher(null, q);'),
    ("csharp.xpath-injection", "취약",
     'var doc = new XmlDocument(); XmlNode n = doc.SelectSingleNode(args[1]);'),
    ("csharp.path-traversal", "안전", 'string t = "hardcoded"; File.Exists(t);'),
    ("csharp.command-injection", "안전",
     'string t = "hardcoded"; System.Diagnostics.Process.Start("/bin/bash", "-c \'ls " + t + "\'");'),
]


@pytest.mark.parametrize("rule_id,want,body", CASES,
                         ids=[f"{r.split('.')[1]}-{w}" for r, w, _ in CASES])
def test_csharp_args_source(tmp_path, rule_id, want, body):
    f = tmp_path / "t.cs"
    f.write_text(_HEAD + body + _TAIL, encoding="utf-8")
    hit = any(x.rule_id == rule_id for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {rule_id}"
    else:
        assert not hit, f"오탐: {rule_id}"
