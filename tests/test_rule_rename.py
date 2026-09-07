"""규칙 개명이 판정 승계·신규/해결 비교를 끊지 않는지 본다.

지문이 rule_id 로 만들어지므로, 개명 이력(RULE_ALIASES)을 따라가지 않으면 이름만 바꿔도
과거 진단의 오탐 판정이 전부 날아가고 모든 탐지가 '신규'로 보인다.
"""
from cpguard.report import finding as models


def _finding(idx: int, rule_id: str) -> dict:
    return {"id": idx, "rule_id": rule_id, "file": "app/Dao.java", "line": 42,
            "fp": models.fingerprint(rule_id, "app/Dao.java", "stmt.execute( q )"),
            "steps": [{"kind": "sink", "file": "app/Dao.java", "line": 42,
                       "code": "stmt.execute(q)"}]}


def test_rename_keeps_fingerprint():
    old = _finding(0, "java.sqli")                      # 개명 전에 저장된 스캔
    models.RULE_ALIASES["java.sqli"] = "java.sql-injection"
    try:
        new_fp = models.fingerprint("java.sql-injection", "app/Dao.java", "stmt.execute(q)")
        assert old["fp"] != new_fp, "개명하면 저장된 지문은 당연히 달라진다"
        assert models.stored_fp(old) == new_fp, "옛 스캔 지문이 현재 이름으로 승계돼야 한다"
    finally:
        models.RULE_ALIASES.pop("java.sqli")


def test_no_alias_uses_stored_fp_verbatim():
    f = _finding(0, "java.sqli")
    assert models.stored_fp(f) == f["fp"]


def test_alias_chain_and_cycle():
    models.RULE_ALIASES.update({"a": "b", "b": "c", "x": "y", "y": "x"})
    try:
        assert models.canonical_rule_id("a") == "c"
        models.canonical_rule_id("x")          # 순환이어도 멈춘다
    finally:
        for k in ("a", "b", "x", "y"):
            models.RULE_ALIASES.pop(k)


if __name__ == "__main__":
    test_rename_keeps_fingerprint()
    test_no_alias_uses_stored_fp_verbatim()
    test_alias_chain_and_cycle()
    print("ok")
