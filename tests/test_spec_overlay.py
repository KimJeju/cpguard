"""사용자 규칙 오버레이 — 동봉 규칙을 소스 수정 없이 조정할 수 있어야 한다.

오탐이 나도 사용자가 손댈 방법이 없으면 제품이 아니다. 조정 수단은 규칙 YAML 자체다.
"""
import textwrap

from cpguard.report.finding import RULE_ALIASES, canonical_rule_id
from cpguard.taint import spec


def _yml(d, name, body):
    p = d / name
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return p


def test_user_overlay_extends_lists_and_overrides_scalars(tmp_path):
    ship, user = tmp_path / "ship", tmp_path / "user"
    ship.mkdir(); user.mkdir()
    _yml(ship, "sqli.yml", """
        id: demo.sqli
        message: 원본
        severity: critical
        languages: [java]
        sinks:
          - callee: [stmt.execute]
        sanitizers:
          - callee: [escapeSql]
    """)
    _yml(user, "sqli.yml", """
        id: demo.sqli
        severity: medium
        sinks:
          - callee: [ourDb.raw]
        sanitizers:
          - callee: [com.acme.SafeSql.check]
    """)
    r = {x.id: x for x in spec.load_rules(ship, user_dir=user)}["demo.sqli"]
    assert r.severity == "medium", "스칼라는 사용자 값이 이긴다"
    assert r.message == "원본", "건드리지 않은 키는 그대로"
    assert [s.callee for s in r.sinks] == [["stmt.execute"], ["ourDb.raw"]]
    assert r.sanitizers == ["escapeSql", "com.acme.SafeSql.check"]


def test_replace_drops_shipped_lists(tmp_path):
    ship, user = tmp_path / "ship", tmp_path / "user"
    ship.mkdir(); user.mkdir()
    _yml(ship, "a.yml", "id: demo.a\nsinks:\n  - callee: [x]\n")
    _yml(user, "a.yml", "id: demo.a\nreplace: true\nsinks:\n  - callee: [y]\n")
    r = spec.load_rules(ship, user_dir=user)[0]
    assert [s.callee for s in r.sinks] == [["y"]]


def test_user_can_add_a_new_rule(tmp_path):
    ship, user = tmp_path / "ship", tmp_path / "user"
    ship.mkdir(); user.mkdir()
    _yml(ship, "a.yml", "id: demo.a\n")
    _yml(user, "b.yml", "id: acme.internal-api\nseverity: high\n")
    assert {r.id for r in spec.load_rules(ship, user_dir=user)} == {"demo.a", "acme.internal-api"}


def test_overlay_can_be_disabled(tmp_path):
    ship = tmp_path / "ship"; ship.mkdir()
    _yml(ship, "a.yml", "id: demo.a\nseverity: critical\n")
    assert spec.load_rules(ship, user_dir=False)[0].severity == "critical"


def test_legacy_ids_feed_the_rename_table(tmp_path):
    ship = tmp_path / "ship"; ship.mkdir()
    _yml(ship, "a.yml", "id: java.sql-injection\nlegacy_ids: [java.sqli]\n")
    try:
        spec.load_rules(ship, user_dir=False)
        assert canonical_rule_id("java.sqli") == "java.sql-injection"
    finally:
        RULE_ALIASES.pop("java.sqli", None)


def test_shipped_rules_still_load():
    rules = spec.load_rules(user_dir=False)
    assert len(rules) > 50 and all(r.id for r in rules)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
