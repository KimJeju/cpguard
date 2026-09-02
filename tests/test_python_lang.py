"""Python 어댑터 검증 — 세 번째 언어에서도 코어가 그대로 동작하는지."""
import pytest

from cpguard.parse import loader, normalize
from cpguard.taint import engine
from cpguard.taint.spec import load_rules

RULES = load_rules(language="python")


def scan(src: str):
    tree = loader.parse_source(src, language="python")
    mod = normalize.normalize(tree, file="t.py", language="python")
    return engine.analyze(mod, src.encode(), RULES)


def ids(src: str) -> set[str]:
    return {f.rule_id for f in scan(src)}


@pytest.mark.parametrize("rule_id,src", [
    ("py.command-injection", 'import os\ndef h(request):\n    os.system("ping " + request.GET["c"])\n'),
    ("py.sqli", 'def h(request):\n    cursor.execute("SELECT " + request.GET["id"])\n'),
    ("py.code-injection", 'def h(request):\n    return eval(request.POST["e"])\n'),
    ("py.path-traversal", 'def h(request):\n    return open(request.GET["f"]).read()\n'),
    ("py.ssrf", 'import requests\ndef h(request):\n    return requests.get(request.GET["u"])\n'),
])
def test_vulnerable_detected(rule_id, src):
    assert rule_id in ids(src)


@pytest.mark.parametrize("rule_id,src", [
    ("py.command-injection", 'import os, shlex\ndef h(request):\n    os.system("ping " + shlex.quote(request.GET["c"]))\n'),
    ("py.path-traversal", 'import os\ndef h(request):\n    return open(os.path.basename(request.GET["f"])).read()\n'),
])
def test_sanitized_not_detected(rule_id, src):
    assert rule_id not in ids(src)


def test_constant_not_tainted():
    assert ids('import os\ndef h():\n    os.system("ls -la")\n') == set()


def test_interprocedural_python():
    src = ('import os\n'
           'def get(request):\n    return request.GET["c"]\n'
           'def run(x):\n    os.system(x)\n'
           'def h(request):\n    run(get(request))\n')
    assert "py.command-injection" in ids(src)


def test_branch_merge_python():
    src = ('import os\n'
           'def h(request, flag):\n'
           '    if flag:\n        c = request.GET["c"]\n'
           '    else:\n        c = "safe"\n'
           '    os.system(c)\n')
    assert "py.command-injection" in ids(src)


def test_class_method_is_analyzed():
    src = ('import os\n'
           'class V:\n'
           '    def handle(self, request):\n'
           '        os.system(request.GET["c"])\n')
    assert "py.command-injection" in ids(src)


def test_decorated_function_is_analyzed():
    src = ('import os\n'
           '@app.route("/x")\n'
           'def h(request):\n    os.system(request.GET["c"])\n')
    assert "py.command-injection" in ids(src)


def test_language_detection():
    assert loader.language_name_for("a/b/x.py") == "python"
    assert loader.rule_language("python") == "python"


def test_tsx_uses_jsx_grammar():
    """.tsx 는 JSX 를 아는 문법으로 파싱돼야 한다(안 그러면 전부 구문오류)."""
    assert loader.language_name_for("C.tsx") == "tsx"
    assert loader.rule_language("tsx") == "typescript"
    src = "const A = () => <div id='x'>hi</div>;"
    tree = loader.parse_source(src, language="tsx")
    assert not tree.root_node.has_error
