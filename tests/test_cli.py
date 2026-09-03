"""CLI 진입점 스모크 — 특히 한글/유니코드 출력이 콘솔에서 죽지 않는지."""
from __future__ import annotations

import io

from cpguard import cli


def test_force_utf8_is_safe_on_streams_without_reconfigure():
    # 캡처/리다이렉트된 스트림(reconfigure 없음)에서도 예외 없이 넘어가야 한다.
    cli._force_utf8_output()  # 실제 stdout/stderr — 예외 안 나면 통과


def test_scan_prints_unicode_without_crash(tmp_path, capsys):
    # em-dash·화살표가 든 규칙 메시지를 출력해도 UnicodeEncodeError 로 죽지 않아야 한다.
    # (한글 Windows cp949 콘솔 회귀 방지)
    src = tmp_path / "app.js"
    src.write_text(
        "function h(req){ const x = req.query.id; db.query('SELECT '+x); }",
        encoding="utf-8",
    )
    rc = cli.main(["scan", str(tmp_path), "--quiet"])
    out = capsys.readouterr().out
    assert rc in (0, 1)          # 1 = 탐지 있음, 0 = 없음 — 둘 다 정상 종료
    assert "탐지" in out          # 요약 라인이 정상 출력됨


def test_scan_missing_path_returns_2(tmp_path):
    assert cli.main(["scan", str(tmp_path / "nope")]) == 2
