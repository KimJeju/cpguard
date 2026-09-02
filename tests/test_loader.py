"""loader 스모크 테스트 — 완성본, 이미 초록불이어야 한다."""
from cpguard.parse import loader


def test_parse_js_source():
    tree = loader.parse_source("const x = 1;", language="javascript")
    assert tree.root_node.type == "program"
    assert tree.root_node.named_child_count == 1


def test_parse_ts_source():
    tree = loader.parse_source("const x: number = 1;", language="typescript")
    assert tree.root_node.type == "program"


def test_language_name_for():
    assert loader.language_name_for("a/b/foo.js") == "javascript"
    assert loader.language_name_for("foo.tsx") == "tsx"        # JSX 문법 필요
    assert loader.rule_language("tsx") == "typescript"       # 규칙상으로는 TS
    assert loader.language_name_for("x.py") == "python"


def test_unsupported_ext():
    import pytest
    with pytest.raises(loader.UnsupportedLanguage):
        loader.language_name_for("foo.rb")
