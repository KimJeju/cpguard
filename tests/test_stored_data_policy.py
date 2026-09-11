"""저장소(DB·파일)에서 읽은 값을 사용자 입력으로 볼 것인가 — 기본 켜짐.

2차 주입·저장형 XSS 는 여기서 나온다. 신뢰 경계를 어디로 볼지는 조직마다 다르므로
`--trust-stored-data` (또는 `CPGUARD_TRUST_STORED_DATA=1`)로 끌 수 있다.

켜는 쪽으로 정한 근거는 15개 스위트 A/B 측정이다 — 손해 보는 스위트가 없었고 Go 는
취약 50건을 더 잡으면서 오탐이 9건 늘어(교환비 5.6:1) 정밀도가 오히려 올랐다.
전후 표는 bench/README.md 에 있다.

여기 등장하는 exec·system 은 탐지 대상 문자열이다. 임시 파일에 텍스트로 쓴 뒤
스캐너에 넣어 "이 흐름을 잡는가"를 묻는 용도이며, 실행하지 않는다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

GO = """package testcode

import (
\t"database/sql"
\t"os/exec"
)

var DB *sql.DB

func Handle() {
\tvar bio string
\tDB.QueryRow("SELECT bio FROM profiles LIMIT 1").Scan(&bio)
\texec.Command("sh", "-c", "echo "+bio)
}
"""

JS = """const cp = require('child_process');
async function handle(db) {
  const row = (await db.query("SELECT text FROM comments")).rows[0].text;
  cp.exec("echo " + row);
}
"""

CASES = [("go", ".go", GO, "go.command-injection"),
         ("js", ".js", JS, "js.command-injection")]


@pytest.mark.parametrize("lang,ext,src,rule", CASES, ids=[c[0] for c in CASES])
def test_stored_data_is_a_source_by_default(tmp_path, monkeypatch, lang, ext, src, rule):
    monkeypatch.delenv("CPGUARD_TRUST_STORED_DATA", raising=False)
    f = tmp_path / ("probe" + ext)
    f.write_text(src, encoding="utf-8")
    assert any(x.rule_id == rule for x in scan_file(f, load_rules(user_dir=False))), \
        f"미탐: {lang} — 저장소 읽기가 기본에서 소스여야 한다"


@pytest.mark.parametrize("lang,ext,src,rule", CASES, ids=[c[0] for c in CASES])
def test_opt_out_restores_trust(tmp_path, monkeypatch, lang, ext, src, rule):
    monkeypatch.setenv("CPGUARD_TRUST_STORED_DATA", "1")
    f = tmp_path / ("probe" + ext)
    f.write_text(src, encoding="utf-8")
    assert not any(x.rule_id == rule for x in scan_file(f, load_rules(user_dir=False))), \
        f"오탐: {lang} — 끄면 저장소를 신뢰해야 한다"
