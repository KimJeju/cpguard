"""PHP 어댑터 검증 — 언어중립 IR 위에서 코어가 그대로 동작하는지 확인.

주의: 취약 PHP 스니펫을 소스에 그대로 적으면 백신이 웹셸 시그니처로 오인해
파일을 잠글 수 있다(실제로 겪음). 위험한 형태는 조각을 이어붙여 만든다.
"""
import pytest

from cpguard.parse import loader, normalize
from cpguard.taint import engine
from cpguard.taint.spec import load_rules

RULES = load_rules(language="php")

OPEN = "<?php "
GET = '$_GET["x"]'
POST = '$_POST["x"]'
REQ = '$_REQUEST["x"]'


def php(*parts: str) -> str:
    return OPEN + " ".join(parts)


def scan(src: str):
    tree = loader.parse_source(src, language="php")
    mod = normalize.normalize(tree, file="t.php", language="php")
    return engine.analyze(mod, src.encode(), RULES)


def ids(src: str) -> set[str]:
    return {f.rule_id for f in scan(src)}


# ---------- 양성 ----------

@pytest.mark.parametrize("rule_id,src", [
    ("php.sqli", php(f'$i={GET};', 'mysqli_query($c, "SELECT ".$i);')),
    ("php.command-injection", php(f'system("ping ".{REQ});')),
    ("php.xss", php(f'echo {GET};')),
    ("php.file-inclusion", php(f'include({GET});')),
    ("php.code-injection", php(f'$c={POST};', 'ev' + 'al($c);')),
    ("php.ssrf", php(f'file_get_contents({GET});')),
])
def test_vulnerable_detected(rule_id, src):
    assert rule_id in ids(src)


# ---------- 음성 ----------

@pytest.mark.parametrize("rule_id,src", [
    ("php.sqli", php(f'$i=mysqli_real_escape_string($c,{GET});',
                     'mysqli_query($c,"SELECT ".$i);')),
    ("php.command-injection", php(f'system("ping ".escapeshellarg({REQ}));')),
    ("php.xss", php(f'echo htmlspecialchars({GET});')),
    ("php.file-inclusion", php(f'include(basename({GET}));')),
])
def test_sanitized_not_detected(rule_id, src):
    assert rule_id not in ids(src)


def test_constant_not_tainted():
    assert ids(php('system("ls -la");', 'echo "hello";')) == set()


# ---------- PHP 특유 문법 ----------

def test_string_interpolation_propagates():
    """보간 문자열("...$id...")로도 오염이 흘러야 한다."""
    src = php(f'$id={GET};', '$q="SELECT * FROM u WHERE id=$id";', 'mysqli_query($c,$q);')
    assert "php.sqli" in ids(src)


def test_switch_statement_body_is_analyzed():
    """switch 안의 문도 분석돼야 한다 (DVWA sqli 가 이 형태)."""
    src = php(
        f'$id = {GET};',
        'switch ($db) { case "mysql": $q = "SELECT ".$id; mysqli_query($c, $q); break; }',
    )
    assert "php.sqli" in ids(src)


def test_interprocedural_php():
    src = php(
        f'function getInput(){{ return {GET}; }}',
        'function runCmd($x){ system($x); }',
        'runCmd(getInput());',
    )
    assert "php.command-injection" in ids(src)


def test_branch_merge_php():
    src = php(f'if ($f) {{ $c = {GET}; }} else {{ $c = "safe"; }}', 'system($c);')
    assert "php.command-injection" in ids(src)


def test_loop_body_php():
    src = php(f'foreach ($a as $v) {{ $c = {GET}; }}', 'system($c);')
    assert "php.command-injection" in ids(src)


# ---------- 언어 분리 ----------

def test_language_detection():
    assert loader.language_name_for("a/b/x.php") == "php"
    assert loader.language_name_for("x.phtml") == "php"


def test_rules_are_language_scoped():
    """언어 필드가 다르면 규칙이 섞이지 않아야 한다."""
    js_rules = load_rules(language="javascript")
    assert all(r.id.startswith("js.") for r in js_rules)
    assert all(r.id.startswith("php.") for r in RULES)
