"""스캔 무결성 보고 검증.

"탐지 0건"이 안전을 뜻하는지, 파일을 제대로 못 읽어서인지 구분되어야 한다.
tree-sitter 는 깨진 소스에도 예외를 던지지 않으므로 구문오류를 별도로 감지해야 한다.
"""
from cpguard.scanner import ScanReport, scan_path

GOOD = "function f(req){ child_process.exec(req.query.c); }\n"
BROKEN = "function f(req){ const x = ;;; @@@ unterminated\n"


def test_clean_project_reports_complete(tmp_path):
    (tmp_path / "a.js").write_text(GOOD, encoding="utf-8")
    (tmp_path / "b.js").write_text("const x = 1;\n", encoding="utf-8")

    findings, report = scan_path(tmp_path)
    assert report.scanned == 2
    assert report.complete
    assert "전부 분석 완료" in report.summary()
    assert findings  # a.js 의 취약점


def test_syntax_error_is_reported_as_partial(tmp_path):
    (tmp_path / "ok.js").write_text(GOOD, encoding="utf-8")
    (tmp_path / "bad.js").write_text(BROKEN, encoding="utf-8")

    _, report = scan_path(tmp_path)
    assert not report.complete
    assert len(report.partial) == 1
    assert "bad.js" in report.partial[0]
    assert "부분분석" in report.summary()


def test_oversized_file_is_reported(tmp_path, monkeypatch):
    import cpguard.scanner as sc
    monkeypatch.setattr(sc, "MAX_FILE_BYTES", 10)
    (tmp_path / "big.js").write_text(GOOD * 50, encoding="utf-8")

    _, report = scan_path(tmp_path)
    assert len(report.skipped_too_large) == 1
    assert not report.complete


def test_total_counts_every_candidate(tmp_path, monkeypatch):
    import cpguard.scanner as sc
    monkeypatch.setattr(sc, "MAX_FILE_BYTES", 60)
    (tmp_path / "ok.js").write_text("const x = 1;\n", encoding="utf-8")
    (tmp_path / "big.js").write_text(GOOD * 50, encoding="utf-8")

    _, report = scan_path(tmp_path)
    assert report.total == 2


def test_empty_project_is_complete(tmp_path):
    findings, report = scan_path(tmp_path)
    assert findings == [] and report.scanned == 0 and report.complete


def test_report_defaults():
    r = ScanReport()
    assert r.complete and r.total == 0
