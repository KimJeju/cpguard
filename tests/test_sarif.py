"""SARIF 직렬화 — 업로드가 거부되지 않을 형식으로 나가야 한다.

GitHub Code Scanning 은 SARIF 를 스키마 검증한 뒤 받는다. 규격 위반이 한 건이라도
있으면 파일 전체를 거부하므로, 탐지 하나 때문에 그 스캔 결과가 통째로 사라진다.
"""
from cpguard.report.sarif import to_sarif
from cpguard.scanner import scan_path


def _regions(sarif):
    for r in sarif["runs"][0]["results"]:
        for loc in r["locations"]:
            yield loc["physicalLocation"]["region"]
        for cf in r.get("codeFlows", []):
            for tf in cf["threadFlows"]:
                for l in tf["locations"]:
                    yield l["location"]["physicalLocation"]["region"]


def test_findings_without_a_line_are_still_valid_sarif(tmp_path):
    """파일명 규칙(.env·id_rsa)은 줄이 없어 Loc 이 0 이다 — SARIF 는 1-based 만 받는다."""
    (tmp_path / "id_rsa").write_text("x", encoding="utf-8")
    (tmp_path / "a.js").write_text(
        "function f(req){ child_process.exec(req.query.c); }\n", encoding="utf-8")

    findings, _ = scan_path(tmp_path)
    assert any(f.rule_id == "secret.risky-filename" for f in findings)

    regions = list(_regions(to_sarif(findings, base=tmp_path)))
    assert regions
    for reg in regions:
        assert reg["startLine"] >= 1 and reg["endLine"] >= reg["startLine"]
        assert reg["startColumn"] >= 1 and reg["endColumn"] >= 1
