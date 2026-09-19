"""수신자를 씻는 정제 — `sb.Replace("'", "&apos;")` 처럼 반환값을 안 쓰는 이스케이프 호출.

    StringBuilder text = new StringBuilder(x);   // text 오염
    text.Replace("&", "&amp;"); text.Replace("'", "&apos;"); …
    string v = text.ToString();                  // v 는 인코딩된 값

정제 판정은 값 흐름(`_taint`) 안의 호출에만 있어서, 수신자를 제자리에서 바꾸는 호출은
아무것도 씻지 못했다(SARD C# xml_encode 안전 변형이 XPath 규칙에서 오탐). 규칙이
sanitizer_args 로 인정한 호출(토큰 `&apos;`·`&quot;`)이 오염된 수신자에 문 단위로 걸리면
수신자를 env 에서 뺀다. 토큰이 없는 Replace 는 정제가 아니고, 다른 규칙(명령 주입)엔
XML 인코딩이 정제가 아니다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules()
_HEAD = ("using System; using System.Text; using System.Xml;\n"
         "class C { static void Main(string[] args){\nstring x = args[1];\n"
         "StringBuilder text = new StringBuilder(x);\n")
_XPATH = ('\nstring v = text.ToString(); string q = string.Format("//user[@name=\'{0}\']", v);'
          ' var doc = new XmlDocument(); XmlNode n = doc.SelectSingleNode(q);\n} }\n')
_CMD = ('\nstring v = text.ToString();'
        ' System.Diagnostics.Process.Start("/bin/bash", "-c \'ls " + v + "\'");\n} }\n')

CASES = [
    ("csharp.xpath-injection", "안전", 'text.Replace("&", "&amp;"); text.Replace("\'", "&apos;"); text.Replace("<", "&lt;");', _XPATH),
    ("csharp.xpath-injection", "취약", 'text.Replace("a", "b");', _XPATH),          # 토큰 없음 → 정제 아님
    ("csharp.xpath-injection", "취약", '', _XPATH),                                  # 아무것도 안 함
    ("csharp.command-injection", "취약", 'text.Replace("\'", "&apos;");', _CMD),   # XML 인코딩은 명령 주입 정제가 아님
]


@pytest.mark.parametrize("rule_id,want,body,tail", CASES,
                         ids=[f"{r.split('.')[1]}-{w}-{i}" for i, (r, w, _, _) in enumerate(CASES)])
def test_receiver_sanitizer(tmp_path, rule_id, want, body, tail):
    f = tmp_path / "t.cs"
    f.write_text(_HEAD + body + tail, encoding="utf-8")
    hit = any(x.rule_id == rule_id for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {rule_id}"
    else:
        assert not hit, f"오탐: {rule_id}"
