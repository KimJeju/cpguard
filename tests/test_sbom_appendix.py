"""부록 E — 오픈소스 컴포넌트 목록이 실제 보고서에 실리는지 본다.

"어떤 오픈소스를 쓰는가" 는 취약점과 별개로 요구되는 산출물이다. 취약점 0건이어도
목록 자체가 점검했다는 근거이므로 실려야 한다.
"""
from cpguard.report.pdf import SBOM_MAX_ROWS, sbom_table


class FakeScan:
    """보고서가 읽는 최소 인터페이스만 흉내낸다(Scan 은 Django 모델이라 무겁다)."""

    def __init__(self, sbom, findings=()):
        self.scan_config = {"sbom": sbom}
        self.findings = list(findings)
        self.language_stats = []


def _dep(mv):
    return {"id": 0, "category": "dependency", "matched_value": mv,
            "rule_id": "sca.vulnerable-dependency", "severity": "high",
            "file": "package-lock.json", "line": 1, "message": "", "cwe": "CWE-1395"}


def test_counts_vulnerabilities_per_component_and_sorts_them_first():
    scan = FakeScan(
        sbom=[["npm", "axios", "0.21.0", "MIT"],
              ["npm", "lodash", "4.17.15", "MIT"],
              ["PyPI", "django", "4.2.1", "-"]],
        findings=[_dep("lodash@4.17.15 · CVE-2020-8203"),
                  _dep("lodash@4.17.15 · CVE-2021-23337"),
                  _dep("axios@0.21.0 · CVE-2020-28168")])
    rows, total, vulnerable = sbom_table(scan)
    assert total == 3 and vulnerable == 2
    assert [r[1] for r in rows] == ["lodash", "axios", "django"], "취약한 것부터 싣는다"
    assert [r[4] for r in rows] == [2, 1, 0]


def test_no_sbom_means_no_appendix():
    assert sbom_table(FakeScan(sbom=[])) == ([], 0, 0)


def test_large_inventory_is_capped_but_total_is_kept():
    sbom = [["npm", f"pkg{i:04d}", "1.0.0", "MIT"] for i in range(SBOM_MAX_ROWS + 50)]
    rows, total, _ = sbom_table(FakeScan(sbom=sbom))
    assert len(rows) == SBOM_MAX_ROWS and total == SBOM_MAX_ROWS + 50
