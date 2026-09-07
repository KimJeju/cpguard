"""검수에서 나온 결함들의 회귀 테스트.

전부 "산출물·호스트가 스캔 대상 때문에 다치는" 부류라, 조용히 되돌아가면 알아채기 어렵다.
"""
import io
import zipfile

import pytest

from cpguard.extract import UnsafeArchive, safe_extract_zip
from cpguard.patterns import load_pattern_rules, scan_text
from cpguard.report.excel import csv_safe


def test_lying_header_cannot_write_past_the_size_cap(tmp_path, monkeypatch):
    """헤더가 신고한 크기가 아니라 실제로 쓴 바이트로 상한을 건다."""
    import cpguard.extract as ex
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", "A" * 200_000)      # 잘 압축되는 큰 파일
    monkeypatch.setattr(ex, "MAX_TOTAL_BYTES", 1000)   # 헤더 검사도 걸리지만
    monkeypatch.setattr(ex, "MAX_COMPRESSION_RATIO", 10 ** 9)
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(z, tmp_path / "out")


def test_extract_still_works_within_limits(tmp_path):
    z = tmp_path / "ok.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a/b.js", "const x = 1;\n")
    assert safe_extract_zip(z, tmp_path / "out") == 1
    assert (tmp_path / "out" / "a" / "b.js").read_text(encoding="utf-8") == "const x = 1;\n"


def test_a_rule_without_masking_does_not_leak_another_rules_pii():
    """같은 줄의 주민번호는 어느 규칙이 보고하든 마스킹된 채로 나가야 한다."""
    rules = load_pattern_rules()
    line = "INSERT INTO users VALUES ('880101-1234568', '192.168.0.5');"
    findings = scan_text(line + "\n", "dump.sql", rules)
    assert findings, "이 줄은 최소 한 건은 탐지돼야 한다"
    ids = {f.rule_id for f in findings}
    assert "pii.kr-resident-number" in ids and "infra.private-ip" in ids, ids
    for f in findings:
        for s in f.steps:
            assert "880101-1234568" not in s.code, f"{f.rule_id} 가 주민번호를 그대로 실었다"


@pytest.mark.parametrize("cell", ["=cmd|'/c calc'!A1", "+1+1", "-2+3", "@SUM(A1)"])
def test_formula_cells_are_neutralised(cell):
    assert csv_safe(cell).startswith("'")


def test_ordinary_cells_are_untouched():
    for v in ("app/server.js", "CWE-89", 42, "", None):
        assert csv_safe(v) == v


def _second_arg_rule():
    from cpguard.taint.spec import Rule, SinkPattern, SourcePattern
    return Rule(
        id="test.second-arg-only", message="두 번째 인자만 위험", severity="high",
        cwe="CWE-000", owasp="", languages=["javascript"],
        sources=[SourcePattern(kind="member", object="req", property=["query"])],
        sinks=[SinkPattern(callee=["danger"], arg=1)], sanitizers=[],
    )


def _findings_for(tmp_path, code):
    from cpguard.scanner import parse_file
    from cpguard.taint import engine
    p = tmp_path / "a.js"
    p.write_text(code, encoding="utf-8")
    module, src, _lang, _err = parse_file(p, use_cache=False)
    return engine.analyze(module, src, [_second_arg_rule()])


def test_sink_arg_out_of_range_is_not_a_sink(tmp_path):
    """규칙이 2번째 인자만 위험하다고 했으면 인자 1개짜리 호출은 대상이 아니다."""
    hits = _findings_for(tmp_path, "function h(req){ danger(req.query.x); }\n")
    assert hits == [], "규칙이 제외한 자리를 잡았다"


def test_declared_sink_arg_still_reports(tmp_path):
    hits = _findings_for(tmp_path, "function h(req){ danger('safe', req.query.x); }\n")
    assert len(hits) == 1 and hits[0].rule_id == "test.second-arg-only"


def test_a_size_limit_says_how_to_raise_it(tmp_path, monkeypatch):
    """대형 제품 아카이브는 실제로 기본 상한을 넘는다.

    상한만 알려주고 끝내면 사용자는 도구가 고장난 줄 안다 — 올리는 방법이 같은
    문장에 있어야 한다.
    """
    import cpguard.extract as ex

    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.txt", "x" * 100_000)
    monkeypatch.setattr(ex, "MAX_TOTAL_BYTES", 1000)

    with pytest.raises(UnsafeArchive) as e:
        safe_extract_zip(z, tmp_path / "out")

    msg = str(e.value)
    assert "CPGUARD_MAX_BYTES" in msg, "올리는 방법을 말해야 한다"
    assert "0.0GB" not in msg, "작은 상한이 0.0GB 로 뭉개지면 안 된다"
