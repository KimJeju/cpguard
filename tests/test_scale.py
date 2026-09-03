"""대규모 최적화: 싱크 필터·파싱 캐시·멀티프로세스가 결과를 바꾸지 않는지."""
from __future__ import annotations

import os
import tempfile

os.environ.setdefault("CPGUARD_HOME", tempfile.mkdtemp(prefix="cpg_scale_"))

from cpguard.scanner import parse_file, scan_path  # noqa: E402


def _project() -> str:
    d = tempfile.mkdtemp(prefix="cpg_proj_")
    files = {
        "lib/input.js": "function readInput(req){ return req.query.cmd; }\nmodule.exports=readInput;",
        "lib/run.js": "function runIt(v){ child_process.exec(v); }\nmodule.exports=runIt;",
        "app.js": "function handler(req,res){ const c = readInput(req); runIt(c); }",
        "safe/util.js": "function add(a,b){ return a + b; }",   # sink 없음 → 프루닝 대상
    }
    for name, data in files.items():
        p = os.path.join(d, *name.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(data)
    return d


def _sig(findings):
    return sorted((f.rule_id, f.file, f.sink.loc.start_line) for f in findings)


def test_parallel_matches_sequential_and_keeps_crossfile():
    d = _project()
    f1, _ = scan_path(d, jobs=1)
    f2, _ = scan_path(d, jobs=2)
    assert _sig(f1) == _sig(f2)                                   # 병렬=순차
    assert any(f.rule_id == "js.command-injection" for f in f1)   # 크로스파일 탐지 유지(싱크필터 후에도)


def test_parse_cache_roundtrip(tmp_path):
    from cpguard.scanner import _parse_cache_dir
    p = tmp_path / "a.js"
    p.write_text("function h(req){ db.query('SELECT '+req.query.id); }", encoding="utf-8")
    m1, _, _, _ = parse_file(str(p))
    assert list(_parse_cache_dir().glob("*.pkl")), "캐시 파일이 생성돼야 한다"
    m2, _, _, _ = parse_file(str(p))          # 두 번째는 캐시에서
    assert m2.loc.file == str(p)              # 경로 보존(다른 파일과 안 섞임)
