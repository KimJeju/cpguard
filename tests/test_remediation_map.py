"""모든 규칙이 유형별 조치 권고에 연결되는지 본다.

연결이 없으면 보고서의 '조치 방안'이 규칙과 무관한 일반 문구로 떨어진다. 조용히
품질만 떨어지고 아무도 모르므로, 새 규칙을 넣을 때 여기서 실패하게 둔다.
"""
import pathlib

import yaml

from cpguard.i18n import REMEDIATION_EN
from cpguard.report.pdf import REMEDIATION, VULN_EXAMPLE, _rule_key

ROOT = pathlib.Path(__file__).resolve().parent.parent / "cpguard"


def _rule_ids() -> list[str]:
    ids = [yaml.safe_load(p.read_text(encoding="utf-8"))["id"]
           for p in (ROOT / "specs").glob("*.yml")]
    for p in (ROOT / "patterns").glob("*.yml"):
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        ids += [r["id"] for r in (d.get("rules") or d.get("patterns") or [])
                if isinstance(r, dict) and r.get("id")]
    return sorted(set(ids))


def test_every_rule_maps_to_remediation():
    unmapped = [r for r in _rule_ids() if not _rule_key(r)]
    assert not unmapped, ("조치 권고에 연결되지 않은 규칙 — pdf.REMEDIATION 에 유형을 넣거나 "
                          f"_EXPLICIT_KEY 에 매핑을 추가할 것: {unmapped}")


def test_mapped_keys_exist_in_both_languages():
    keys = {_rule_key(r) for r in _rule_ids()}
    assert not (keys - REMEDIATION.keys()), "한글 조치 맵에 없는 키"
    assert not (keys - REMEDIATION_EN.keys()), "영문 조치 맵에 없는 키"
    assert not (keys - VULN_EXAMPLE.keys()), "취약 코드 예시가 없는 유형"


def test_remediation_tables_are_parallel():
    assert REMEDIATION.keys() == REMEDIATION_EN.keys()
    assert all(len(v) == 4 for v in REMEDIATION.values())
    assert all(len(v) == 4 for v in REMEDIATION_EN.values())


if __name__ == "__main__":
    test_every_rule_maps_to_remediation()
    test_mapped_keys_exist_in_both_languages()
    test_remediation_tables_are_parallel()
    print("ok")
